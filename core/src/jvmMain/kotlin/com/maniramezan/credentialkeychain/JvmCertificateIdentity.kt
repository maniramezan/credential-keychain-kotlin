package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.security.KeyStore
import java.security.PrivateKey

/**
 * Returns the private key and certificate chain of the identity stored under [alias], for use with
 * `Signature`, `KeyManagerFactory`, or an `SSLContext`.
 *
 * On macOS the key comes from the login keychain through the JDK `KeychainStore` provider, on
 * Windows from the current-user certificate store through the JDK `Windows-MY` provider (the key
 * stays non-exportable and signs through Windows), and on Linux from the PKCS#12 bundle in Secret
 * Service.
 *
 * @return the entry, or `null` if [alias] has no entry or holds only a certificate.
 * @throws KeychainUnavailableException if the platform has no certificate backend or the read fails.
 * @throws IllegalArgumentException if [alias] is blank or contains NUL, CR, or LF, or this store was
 *   not created by `CertificateStore.forCurrentPlatform`.
 */
@Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
public fun CertificateStore.privateKeyEntry(alias: String): KeyStore.PrivateKeyEntry? {
    val (backend, label) = identityTarget(alias) ?: return null
    return when (backend) {
        is MacOSCertificateBackend -> {
            keyStoreEntry(backend.keyStore, label, MacOSCertificateBackend.TRANSFER_PASSWORD.toCharArray(), "macOS KeychainStore")
        }

        is LinuxCertificateBackend -> {
            backend.readIdentity(label)?.let { KeyStore.PrivateKeyEntry(it.privateKey, it.chain.toTypedArray()) }
        }

        is WindowsCertificateBackend -> {
            // Windows-MY names each certificate after its friendly name, which the import set to the label.
            keyStoreEntry({ KeyStore.getInstance("Windows-MY") }, label, null, "Windows certificate store")
        }

        else -> {
            null
        }
    }
}

/** Creates and loads the store inside the guard, so provider failures are always sanitized. */
private fun keyStoreEntry(
    keyStore: () -> KeyStore,
    label: String,
    password: CharArray?,
    name: String,
): KeyStore.PrivateKeyEntry? {
    try {
        val store = keyStore()
        store.load(null, null)
        if (!store.isKeyEntry(label)) return null
        val key = store.getKey(label, password) as? PrivateKey ?: return null
        val chain = store.getCertificateChain(label) ?: return null
        return KeyStore.PrivateKeyEntry(key, chain)
    } catch (_: Exception) {
        // Provider exceptions can describe certificates; never attach them.
        throw KeychainUnavailableException(Reason.Failed, "$name read failed")
    }
}
