@file:OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)

package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlin.io.encoding.Base64

/**
 * X.509 certificates and identities (a certificate chain plus its private key), stored with the
 * platform's native protection. PKCS#12 identities keep their private key in native key storage;
 * certificate chains and the alias index are kept in the platform's secure secret storage.
 *
 * Stores are isolated by service/account namespace like the other stores, and imports replace
 * any existing entry with the same alias.
 *
 * ```kotlin
 * val certificates = CertificateStore.forCurrentPlatform(serviceName = "my-app", accountName = "user-123")
 * val identity = certificates.importPkcs12("client", pkcs12Bytes, passphrase)
 * certificates.importCertificate("pinned-ca", caDer)
 * val chain: List<ByteArray>? = certificates.info("client")?.certificateChainDer
 * ```
 */
public interface CertificateStore {
    /**
     * Imports the single identity in [pkcs12] under [alias], replacing any existing entry.
     *
     * [passphrase] is read but not cleared; callers own and should clear it.
     *
     * @return the imported entry, with [CertificateInfo.hasPrivateKey] set.
     * @throws KeychainUnavailableException if the backend is unavailable or the import fails;
     *   reason `Unsupported` if the bundle exceeds what the platform can store.
     * @throws IllegalArgumentException if [alias] is invalid, [pkcs12] is empty, larger than
     *   1 MiB, malformed, protected by a different passphrase, or does not contain exactly one
     *   private key with its certificate chain.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun importPkcs12(
        alias: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): CertificateInfo

    /**
     * Imports a single DER-encoded X.509 certificate under [alias], replacing any existing entry.
     *
     * @return the imported entry, without a private key.
     * @throws KeychainUnavailableException if the backend is unavailable or the import fails.
     * @throws IllegalArgumentException if [alias] is invalid or [certificateDer] is empty, larger
     *   than 1 MiB, or not a DER-encoded X.509 certificate.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun importCertificate(
        alias: String,
        certificateDer: ByteArray,
    ): CertificateInfo

    /**
     * Returns the entry stored under [alias].
     *
     * @return the entry, or `null` if none exists.
     * @throws KeychainUnavailableException if the backend is unavailable or the lookup fails.
     * @throws IllegalArgumentException if [alias] is blank or contains NUL, CR, or LF.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun info(alias: String): CertificateInfo?

    /**
     * Returns every alias in this store, sorted.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the lookup fails.
     */
    @Throws(KeychainUnavailableException::class)
    public fun aliases(): List<String>

    /**
     * Deletes the entry under [alias], including any private key. Deleting a missing entry
     * succeeds silently as long as the backend itself is available.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     * @throws IllegalArgumentException if [alias] is blank or contains NUL, CR, or LF.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun delete(alias: String): Unit

    /**
     * Deletes every entry in this store's service/account namespace, including private keys.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     */
    @Throws(KeychainUnavailableException::class)
    public fun clear(): Unit

    /** Platform-specific factories for creating an application-scoped certificate store. */
    public companion object {
        /**
         * Creates a certificate store isolated by [serviceName] and [accountName] using default
         * [KeychainOptions]. See the three-argument overload for details.
         *
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String = serviceName,
        ): CertificateStore = forCurrentPlatform(serviceName, accountName, KeychainOptions())

        /**
         * Creates a certificate store isolated by both [serviceName] and [accountName]. Desktop
         * JVM keeps identities in the macOS login keychain, the Windows current-user certificate
         * store, or Linux Secret Service. Android callers must use the `Context`-taking overload
         * instead; this overload returns a store that throws [KeychainUnavailableException] on
         * Android. Apple platforms store identities in the data-protection keychain, which needs an
         * app with keychain entitlements (unsigned macOS processes get reason `Unsupported`) and
         * macOS 15 or later on macOS. One identity can be stored under only one alias per keychain.
         *
         * @param serviceName identifies the calling application or integration; must be
         *   nonblank and free of NUL/CR/LF.
         * @param accountName identifies the certificate owner. Same validity rules as [serviceName].
         * @param options platform-specific behavior; options that don't apply are ignored.
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String,
            options: KeychainOptions,
        ): CertificateStore {
            validateIdentifier(serviceName, "serviceName")
            validateIdentifier(accountName, "accountName")
            return ValidatingCertificateStore(platformCertificateStore(serviceName, accountName, options))
        }
    }
}

/**
 * A certificate chain stored in a [CertificateStore], leaf certificate first.
 *
 * @property alias the entry's alias within its store.
 * @property hasPrivateKey whether the entry is an identity whose private key is stored natively.
 * @param certificateChainDer the DER-encoded X.509 certificates, leaf first.
 */
public class CertificateInfo(
    public val alias: String,
    certificateChainDer: List<ByteArray>,
    public val hasPrivateKey: Boolean,
) {
    private val chain = certificateChainDer.map { it.copyOf() }

    /** The DER-encoded X.509 certificates, leaf first; each call returns copies. */
    public val certificateChainDer: List<ByteArray> get() = chain.map { it.copyOf() }

    /** Entries are equal when the alias, private-key flag, and every certificate are equal. */
    override fun equals(other: Any?): Boolean =
        other is CertificateInfo &&
            alias == other.alias &&
            hasPrivateKey == other.hasPrivateKey &&
            chain.size == other.chain.size &&
            chain.indices.all { chain[it].contentEquals(other.chain[it]) }

    /** Combines the alias, private-key flag, and certificates. */
    override fun hashCode(): Int =
        chain.fold(alias.hashCode() * 31 + hasPrivateKey.hashCode()) { hash, der ->
            hash * 31 +
                der.contentHashCode()
        }

    /** Describes the alias, private-key flag, and chain length. */
    override fun toString(): String = "CertificateInfo(alias=$alias, hasPrivateKey=$hasPrivateKey, certificates=${chain.size})"
}

internal expect fun platformCertificateStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CertificateStore

internal const val MAX_CERTIFICATE_INPUT_BYTES: Int = 1024 * 1024

/** Service suffix that keeps certificate metadata apart from the caller's own secrets. */
internal const val CERTIFICATE_METADATA_SERVICE: String = "certificates"

/** Parses and natively stores identities; everything else is shared in [KeychainCertificateStore]. */
internal interface CertificateBackend {
    /** Returns the DER chain, leaf first; throws [IllegalArgumentException] for bad data or passphrase. */
    fun parsePkcs12(
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): List<ByteArray>

    /** Returns the canonical DER encoding; throws [IllegalArgumentException] for invalid input. */
    fun parseCertificate(der: ByteArray): ByteArray

    fun storeIdentity(
        label: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    )

    /** Deletes the identity and its private key; a missing identity is not an error. */
    fun deleteIdentity(label: String)
}

/**
 * Keeps each entry's chain in [metadata] under `certificate:<alias>` and the alias index under
 * `index`, and delegates private keys to [backend] under a namespaced label. The index is not
 * transactional across processes; concurrent imports from several processes may drop aliases
 * from [aliases] without affecting the entries themselves.
 */
internal class KeychainCertificateStore(
    private val namespace: String,
    private val metadata: CredentialKeychain,
    private val backend: CertificateBackend,
) : CertificateStore {
    override fun importPkcs12(
        alias: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): CertificateInfo {
        val chain = backend.parsePkcs12(pkcs12, passphrase)
        delete(alias)
        backend.storeIdentity(label(alias), pkcs12, passphrase)
        return record(alias, chain, hasPrivateKey = true)
    }

    override fun importCertificate(
        alias: String,
        certificateDer: ByteArray,
    ): CertificateInfo {
        val certificate = backend.parseCertificate(certificateDer)
        delete(alias)
        return record(alias, listOf(certificate), hasPrivateKey = false)
    }

    override fun info(alias: String): CertificateInfo? = metadata.read(entryKey(alias))?.let { decodeEntry(alias, it) }

    override fun aliases(): List<String> = readIndex().sorted()

    override fun delete(alias: String) {
        backend.deleteIdentity(label(alias))
        metadata.delete(entryKey(alias))
        val index = readIndex()
        if (alias in index) writeIndex(index - alias)
    }

    override fun clear() {
        readIndex().forEach { backend.deleteIdentity(label(it)) }
        metadata.clear()
    }

    private fun record(
        alias: String,
        chain: List<ByteArray>,
        hasPrivateKey: Boolean,
    ): CertificateInfo {
        try {
            metadata.write(entryKey(alias), encodeEntry(chain, hasPrivateKey))
            writeIndex(readIndex() + alias)
        } catch (error: IllegalArgumentException) {
            // A backend value limit (for example secret-tool's 8 KiB) rejected the metadata.
            if (hasPrivateKey) backend.deleteIdentity(label(alias))
            metadata.delete(entryKey(alias))
            throw KeychainUnavailableException(Reason.Unsupported, "certificate data is too large for this platform's secret storage")
        }
        return CertificateInfo(alias, chain, hasPrivateKey)
    }

    private fun readIndex(): Set<String> =
        metadata.read(INDEX_KEY)?.let { parseCredentialNamespace(it)?.toSet() ?: throw corrupted() } ?: emptySet()

    private fun writeIndex(aliases: Set<String>) {
        if (aliases.isEmpty()) {
            metadata.delete(
                INDEX_KEY,
            )
        } else {
            metadata.write(INDEX_KEY, credentialNamespace(*aliases.sorted().toTypedArray()))
        }
    }

    internal fun label(alias: String): String = "credential-keychain-kotlin:${credentialNamespace(namespace, alias)}"

    private fun entryKey(alias: String) = "certificate:$alias"

    private fun encodeEntry(
        chain: List<ByteArray>,
        hasPrivateKey: Boolean,
    ): String =
        credentialNamespace(
            FORMAT_VERSION,
            if (hasPrivateKey) IDENTITY else CERTIFICATE,
            *chain.map { Base64.encode(it) }.toTypedArray(),
        )

    private fun decodeEntry(
        alias: String,
        value: String,
    ): CertificateInfo {
        val parts = parseCredentialNamespace(value)
        if (parts == null || parts.size < 3 || parts[0] != FORMAT_VERSION || parts[1] !in setOf(IDENTITY, CERTIFICATE)) throw corrupted()
        val chain =
            try {
                parts.drop(2).map { Base64.decode(it) }
            } catch (_: IllegalArgumentException) {
                throw corrupted()
            }
        return CertificateInfo(alias, chain, hasPrivateKey = parts[1] == IDENTITY)
    }

    private fun corrupted() = KeychainUnavailableException(Reason.Corrupted, "certificate metadata is malformed")

    private companion object {
        const val INDEX_KEY = "index"
        const val FORMAT_VERSION = "1"
        const val IDENTITY = "identity"
        const val CERTIFICATE = "certificate"
    }
}

internal class ValidatingCertificateStore(
    private val delegate: CertificateStore,
) : CertificateStore {
    override fun importPkcs12(
        alias: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): CertificateInfo {
        validateIdentifier(alias, "alias")
        validateCertificateInput(pkcs12, "pkcs12")
        return delegate.importPkcs12(alias, pkcs12, passphrase)
    }

    override fun importCertificate(
        alias: String,
        certificateDer: ByteArray,
    ): CertificateInfo {
        validateIdentifier(alias, "alias")
        validateCertificateInput(certificateDer, "certificateDer")
        return delegate.importCertificate(alias, certificateDer)
    }

    override fun info(alias: String): CertificateInfo? {
        validateIdentifier(alias, "alias")
        return delegate.info(alias)
    }

    override fun aliases(): List<String> = delegate.aliases()

    override fun delete(alias: String) {
        validateIdentifier(alias, "alias")
        delegate.delete(alias)
    }

    override fun clear() {
        delegate.clear()
    }

    private fun validateCertificateInput(
        bytes: ByteArray,
        field: String,
    ) {
        require(bytes.isNotEmpty()) { "$field must not be empty." }
        require(bytes.size <= MAX_CERTIFICATE_INPUT_BYTES) { "$field must be at most $MAX_CERTIFICATE_INPUT_BYTES bytes." }
    }
}

internal class UnsupportedCertificateStore(
    private val platform: String,
) : CertificateStore {
    override fun importPkcs12(
        alias: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): CertificateInfo = throw unsupported()

    override fun importCertificate(
        alias: String,
        certificateDer: ByteArray,
    ): CertificateInfo = throw unsupported()

    override fun info(alias: String): CertificateInfo? = throw unsupported()

    override fun aliases(): List<String> = throw unsupported()

    override fun delete(alias: String): Unit = throw unsupported()

    override fun clear(): Unit = throw unsupported()

    private fun unsupported() = KeychainUnavailableException(Reason.Unsupported, platform)
}
