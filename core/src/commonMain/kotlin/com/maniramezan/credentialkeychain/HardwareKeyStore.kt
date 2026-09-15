package com.maniramezan.credentialkeychain

/**
 * Non-exportable ECDSA P-256 signing keys generated inside the platform's secure hardware:
 * StrongBox or the trusted execution environment on Android, and the Secure Enclave on Apple
 * platforms. Private keys never leave the hardware; callers receive the public key and
 * signatures only.
 *
 * By default [generate] fails with [KeychainUnavailableException.Reason.Unsupported] when no
 * secure hardware is available (emulators, simulators, unsigned macOS tools, desktop JVM). Opt in
 * to software-backed keys with [HardwareKeySpec.allowSoftwareKeys]; [HardwareKeyInfo.securityLevel]
 * always reports the level actually obtained.
 *
 * Signatures use ECDSA with SHA-256 over the supplied data and are DER-encoded (X9.62), so they
 * verify with `SHA256withECDSA` on the JVM and `ecdsaSignatureMessageX962SHA256` on Apple
 * platforms. Keys are isolated by the store's service/account namespace, like the other stores.
 *
 * ```kotlin
 * val keys = HardwareKeyStore.forCurrentPlatform(serviceName = "my-app", accountName = "user-123")
 * val key = keys.generate("device-binding")
 * upload(key.publicKeyDer)
 * val signature: ByteArray? = keys.sign("device-binding", challenge)
 * ```
 */
public interface HardwareKeyStore {
    /**
     * Generates a new key under [alias], replacing any existing key with that alias.
     *
     * @return the new key's public information.
     * @throws KeychainUnavailableException with reason `Unsupported` if secure hardware is not
     *   available and [HardwareKeySpec.allowSoftwareKeys] is `false`, or if the platform has no
     *   key backend; with another reason if generation fails.
     * @throws IllegalArgumentException if [alias] is blank or contains NUL, CR, or LF.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun generate(
        alias: String,
        spec: HardwareKeySpec = HardwareKeySpec(),
    ): HardwareKeyInfo

    /**
     * Returns the public information of the key under [alias].
     *
     * @return the key information, or `null` if no key exists for [alias].
     * @throws KeychainUnavailableException if the backend is unavailable or the lookup fails.
     * @throws IllegalArgumentException if [alias] is blank or contains NUL, CR, or LF.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun info(alias: String): HardwareKeyInfo?

    /**
     * Signs [data] with the private key under [alias] using ECDSA with SHA-256.
     *
     * @return the DER-encoded signature, or `null` if no key exists for [alias].
     * @throws KeychainUnavailableException if the backend is unavailable or signing fails, for
     *   example with reason `Locked` while the device is locked.
     * @throws IllegalArgumentException if [alias] is blank or contains NUL, CR, or LF.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun sign(
        alias: String,
        data: ByteArray,
    ): ByteArray?

    /**
     * Deletes the key under [alias]. Deleting a missing key succeeds silently as long as the
     * backend itself is available.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     * @throws IllegalArgumentException if [alias] is blank or contains NUL, CR, or LF.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun delete(alias: String): Unit

    /**
     * Deletes every key in this store's service/account namespace.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     */
    @Throws(KeychainUnavailableException::class)
    public fun clear(): Unit

    /** Platform-specific factories for creating an application-scoped key store. */
    public companion object {
        /**
         * Creates a key store isolated by [serviceName] and [accountName] using default
         * [KeychainOptions]. See the three-argument overload for details.
         *
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String = serviceName,
        ): HardwareKeyStore = forCurrentPlatform(serviceName, accountName, KeychainOptions())

        /**
         * Creates a key store isolated by both [serviceName] and [accountName]. Unlike the other
         * stores, Android needs no `Context`: keys live only in Android Keystore. Desktop JVM
         * returns a store whose operations throw [KeychainUnavailableException] with reason
         * `Unsupported`.
         *
         * @param serviceName identifies the calling application or integration; must be
         *   nonblank and free of NUL/CR/LF.
         * @param accountName identifies the key owner. Same validity rules as [serviceName].
         * @param options platform-specific behavior; [KeychainOptions.appleAccessibility]
         *   controls when Apple keys can sign.
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String,
            options: KeychainOptions,
        ): HardwareKeyStore {
            validateIdentifier(serviceName, "serviceName")
            validateIdentifier(accountName, "accountName")
            return ValidatingHardwareKeyStore(platformHardwareKeyStore(serviceName, accountName, options))
        }
    }
}

/**
 * Options for [HardwareKeyStore.generate].
 *
 * @property allowSoftwareKeys when `true`, generation falls back to a software-backed key if no
 *   secure hardware is available; when `false` (the default), it fails with reason `Unsupported`.
 */
public class HardwareKeySpec(
    public val allowSoftwareKeys: Boolean = false,
) {
    /** Specs are equal when their options are equal. */
    override fun equals(other: Any?): Boolean = other is HardwareKeySpec && allowSoftwareKeys == other.allowSoftwareKeys

    /** Derived from [allowSoftwareKeys]. */
    override fun hashCode(): Int = allowSoftwareKeys.hashCode()

    /** Describes the options. */
    override fun toString(): String = "HardwareKeySpec(allowSoftwareKeys=$allowSoftwareKeys)"
}

/**
 * Public information about a key in a [HardwareKeyStore].
 *
 * @property alias the key's alias within its store.
 * @property securityLevel where the private key actually lives.
 * @param publicKeyDer the DER-encoded X.509 SubjectPublicKeyInfo of the public key.
 */
public class HardwareKeyInfo(
    public val alias: String,
    publicKeyDer: ByteArray,
    public val securityLevel: SecurityLevel,
) {
    private val encodedPublicKey = publicKeyDer.copyOf()

    /** The DER-encoded X.509 SubjectPublicKeyInfo of the public key; each call returns a copy. */
    public val publicKeyDer: ByteArray get() = encodedPublicKey.copyOf()

    /** Key information is equal when the alias, public key, and security level are equal. */
    override fun equals(other: Any?): Boolean =
        other is HardwareKeyInfo &&
            alias == other.alias &&
            securityLevel == other.securityLevel &&
            encodedPublicKey.contentEquals(other.encodedPublicKey)

    /** Combines the alias, public key, and security level. */
    override fun hashCode(): Int = (alias.hashCode() * 31 + encodedPublicKey.contentHashCode()) * 31 + securityLevel.hashCode()

    /** Describes the alias, security level, and public key size. */
    override fun toString(): String =
        "HardwareKeyInfo(alias=$alias, securityLevel=$securityLevel, publicKeyDer=${encodedPublicKey.size} bytes)"
}

/** Where a [HardwareKeyStore] private key lives. */
public enum class SecurityLevel {
    /** Software-backed; only created when [HardwareKeySpec.allowSoftwareKeys] is `true`. */
    Software,

    /** An Android trusted execution environment, or secure hardware of unknown kind. */
    TrustedEnvironment,

    /** An Android StrongBox secure element. */
    StrongBox,

    /** The Apple Secure Enclave. */
    SecureEnclave,
}

internal expect fun platformHardwareKeyStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): HardwareKeyStore

internal class ValidatingHardwareKeyStore(
    private val delegate: HardwareKeyStore,
) : HardwareKeyStore {
    override fun generate(
        alias: String,
        spec: HardwareKeySpec,
    ): HardwareKeyInfo {
        validateIdentifier(alias, "alias")
        return delegate.generate(alias, spec)
    }

    override fun info(alias: String): HardwareKeyInfo? {
        validateIdentifier(alias, "alias")
        return delegate.info(alias)
    }

    override fun sign(
        alias: String,
        data: ByteArray,
    ): ByteArray? {
        validateIdentifier(alias, "alias")
        return delegate.sign(alias, data)
    }

    override fun delete(alias: String) {
        validateIdentifier(alias, "alias")
        delegate.delete(alias)
    }

    override fun clear() {
        delegate.clear()
    }
}

internal class UnsupportedHardwareKeyStore(
    private val platform: String,
) : HardwareKeyStore {
    override fun generate(
        alias: String,
        spec: HardwareKeySpec,
    ): HardwareKeyInfo = throw unsupported()

    override fun info(alias: String): HardwareKeyInfo? = throw unsupported()

    override fun sign(
        alias: String,
        data: ByteArray,
    ): ByteArray? = throw unsupported()

    override fun delete(alias: String): Unit = throw unsupported()

    override fun clear(): Unit = throw unsupported()

    private fun unsupported() = KeychainUnavailableException(KeychainUnavailableException.Reason.Unsupported, platform)
}

/** DER SubjectPublicKeyInfo header for an uncompressed P-256 point (id-ecPublicKey, prime256v1). */
internal val P256_PUBLIC_KEY_PREFIX: ByteArray =
    byteArrayOf(
        0x30,
        0x59,
        0x30,
        0x13,
        0x06,
        0x07,
        0x2A,
        0x86.toByte(),
        0x48,
        0xCE.toByte(),
        0x3D,
        0x02,
        0x01,
        0x06,
        0x08,
        0x2A,
        0x86.toByte(),
        0x48,
        0xCE.toByte(),
        0x3D,
        0x03,
        0x01,
        0x07,
        0x03,
        0x42,
        0x00,
    )

/** Wraps a 65-byte uncompressed P-256 point in a SubjectPublicKeyInfo; returns `null` for any other input. */
internal fun p256SubjectPublicKeyInfo(uncompressedPoint: ByteArray): ByteArray? =
    if (uncompressedPoint.size == 65 && uncompressedPoint[0] == 0x04.toByte()) P256_PUBLIC_KEY_PREFIX + uncompressedPoint else null
