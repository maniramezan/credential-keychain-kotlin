package com.maniramezan.credentialkeychain

import android.content.Context
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Creates a certificate store isolated by [serviceName] and [accountName]. Private keys of
 * imported identities are moved into Android Keystore, where they cannot be exported; certificate
 * chains and the alias index are kept in the same encrypted, non-backed-up files as
 * `CredentialKeychain`, under a separate namespace.
 *
 * `context` is retained only as [Context.getApplicationContext].
 *
 * ```kotlin
 * val certificates = CertificateStore.forCurrentPlatform(
 *     context = applicationContext,
 *     serviceName = "my-app",
 *     accountName = "user-123",
 * )
 * ```
 *
 * @param context any Android `Context`; only its application context is retained.
 * @param serviceName identifies the calling application or integration; must be nonblank
 *   and free of NUL/CR/LF.
 * @param accountName identifies the certificate owner; defaults to [serviceName]. Same
 *   validity rules as [serviceName].
 * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or contains
 *   NUL, CR, or LF.
 */
@Throws(IllegalArgumentException::class)
public fun CertificateStore.Companion.forCurrentPlatform(
    context: Context,
    serviceName: String,
    accountName: String = serviceName,
): CertificateStore {
    validateIdentifier(serviceName, "serviceName")
    validateIdentifier(accountName, "accountName")
    val metadata = AndroidKeychain(context.applicationContext, credentialNamespace(serviceName, CERTIFICATE_METADATA_SERVICE), accountName)
    return ValidatingCertificateStore(
        KeychainCertificateStore(credentialNamespace(serviceName, accountName), metadata, AndroidCertificateBackend()),
    )
}

/**
 * Returns the Android Keystore entry of the identity stored under [alias], for use with `Signature`,
 * `KeyManagerFactory`, or an `SSLContext`. The private key stays inside Android Keystore.
 *
 * @return the entry, or `null` if [alias] has no entry or holds only a certificate.
 * @throws KeychainUnavailableException if the read fails.
 * @throws IllegalArgumentException if [alias] is blank or contains NUL, CR, or LF, or this store was
 *   not created by `CertificateStore.forCurrentPlatform`.
 */
@Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
public fun CertificateStore.privateKeyEntry(alias: String): KeyStore.PrivateKeyEntry? {
    val (backend, label) = identityTarget(alias) ?: return null
    return (backend as AndroidCertificateBackend).privateKeyEntry(label)
}

internal actual fun platformCertificateStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CertificateStore = UnsupportedCertificateStore("Android requires the Context-taking forCurrentPlatform overload")

/**
 * Imports identities into Android Keystore under `com.maniramezan.credentialkeychain.certificate.<sha256(label)>`.
 * EC keys may sign; RSA keys may sign and decrypt with the paddings TLS and CMS use. Other key
 * algorithms are rejected.
 */
internal class AndroidCertificateBackend : CertificateBackend {
    override fun parsePkcs12(
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): List<ByteArray> = loadIdentity(pkcs12, passphrase).chain.map { it.encoded }

    override fun parseCertificate(der: ByteArray): ByteArray =
        try {
            (CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate).encoded
        } catch (_: CertificateException) {
            throw IllegalArgumentException("certificateDer is not a DER-encoded X.509 certificate.")
        } catch (_: ClassCastException) {
            throw IllegalArgumentException("certificateDer is not a DER-encoded X.509 certificate.")
        }

    override fun storeIdentity(
        label: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ) {
        val identity = loadIdentity(pkcs12, passphrase)
        val protection = protectionFor(identity.privateKey)
        guarded {
            val store = keyStore()
            val alias = keyStoreAlias(label)
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            store.setEntry(alias, KeyStore.PrivateKeyEntry(identity.privateKey, identity.chain.toTypedArray()), protection)
        }
    }

    fun privateKeyEntry(label: String): KeyStore.PrivateKeyEntry? =
        guarded { keyStore().getEntry(keyStoreAlias(label), null) as? KeyStore.PrivateKeyEntry }

    override fun deleteIdentity(label: String) =
        guarded {
            val store = keyStore()
            if (store.containsAlias(keyStoreAlias(label))) store.deleteEntry(keyStoreAlias(label))
        }

    private fun protectionFor(key: PrivateKey): KeyProtection =
        when (key.algorithm) {
            KeyProperties.KEY_ALGORITHM_EC -> {
                KeyProtection
                    .Builder(KeyProperties.PURPOSE_SIGN)
                    .setDigests(*DIGESTS)
                    .build()
            }

            KeyProperties.KEY_ALGORITHM_RSA -> {
                KeyProtection
                    .Builder(KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(*DIGESTS)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1, KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .build()
            }

            else -> {
                throw IllegalArgumentException("pkcs12 private key must be EC or RSA.")
            }
        }

    private fun <T> guarded(block: () -> T): T =
        try {
            block()
        } catch (error: KeychainUnavailableException) {
            throw error
        } catch (error: Exception) {
            // Keystore exceptions carry no key material; keep them as the cause for diagnosis.
            throw KeychainUnavailableException(Reason.Failed, "Android Keystore certificate operation failed", error)
        }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun keyStoreAlias(label: String) = "com.maniramezan.credentialkeychain.certificate.${sha256Hex(label)}"

    private class Identity(
        val privateKey: PrivateKey,
        val chain: List<X509Certificate>,
    )

    /** Loads the single private key and its chain; every input problem is an [IllegalArgumentException]. */
    private fun loadIdentity(
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): Identity {
        val invalid = "pkcs12 is malformed or the passphrase is incorrect."
        val store = KeyStore.getInstance("PKCS12")
        try {
            store.load(pkcs12.inputStream(), passphrase)
        } catch (_: IOException) {
            throw IllegalArgumentException(invalid)
        } catch (_: GeneralSecurityException) {
            throw IllegalArgumentException(invalid)
        }
        val keyAliases = store.aliases().toList().filter { store.isKeyEntry(it) }
        require(keyAliases.size == 1) { "pkcs12 must contain exactly one private key." }
        val key =
            try {
                store.getKey(keyAliases.single(), passphrase) as? PrivateKey
            } catch (_: GeneralSecurityException) {
                null
            } ?: throw IllegalArgumentException(invalid)
        val chain =
            store
                .getCertificateChain(
                    keyAliases.single(),
                )?.map { it as? X509Certificate ?: throw IllegalArgumentException(invalid) }
        require(!chain.isNullOrEmpty()) { "pkcs12 must contain the private key's certificate chain." }
        return Identity(key, chain)
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        val DIGESTS =
            arrayOf(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
    }
}
