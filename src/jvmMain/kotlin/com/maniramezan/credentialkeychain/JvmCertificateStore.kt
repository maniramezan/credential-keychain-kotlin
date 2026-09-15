package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

internal actual fun platformCertificateStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CertificateStore {
    val metadata = platformKeychain(credentialNamespace(serviceName, CERTIFICATE_METADATA_SERVICE), accountName, options)
    val backend =
        when (desktopOs()) {
            DesktopOs.MacOS -> {
                MacOSCertificateBackend()
            }

            DesktopOs.Linux -> {
                LinuxCertificateBackend(metadata)
            }

            DesktopOs.Windows -> {
                WindowsCertificateBackend(
                    PowerShell(findExecutable("powershell.exe"), commandRunner(options.desktopCommandTimeout)),
                )
            }

            DesktopOs.Other -> {
                return UnsupportedCertificateStore(
                    System.getProperty("os.name").orEmpty().ifEmpty { "unknown operating system" },
                )
            }
        }
    return KeychainCertificateStore(credentialNamespace(serviceName, accountName), metadata, backend)
}

internal class Pkcs12Identity(
    val privateKey: PrivateKey,
    val chain: List<X509Certificate>,
)

/** Loads the single private key and its chain from [pkcs12]; all input problems are [IllegalArgumentException]. */
internal fun loadPkcs12Identity(
    pkcs12: ByteArray,
    passphrase: CharArray,
): Pkcs12Identity {
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
    val chain = store.getCertificateChain(keyAliases.single())?.map { it as? X509Certificate ?: throw IllegalArgumentException(invalid) }
    require(!chain.isNullOrEmpty()) { "pkcs12 must contain the private key's certificate chain." }
    return Pkcs12Identity(key, chain)
}

/** JDK parsing shared by every desktop backend. */
internal abstract class JvmCertificateBackend : CertificateBackend {
    override fun parsePkcs12(
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): List<ByteArray> = loadPkcs12Identity(pkcs12, passphrase).chain.map { it.encoded }

    override fun parseCertificate(der: ByteArray): ByteArray =
        try {
            (CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate).encoded
        } catch (_: CertificateException) {
            throw IllegalArgumentException("certificateDer is not a DER-encoded X.509 certificate.")
        } catch (_: ClassCastException) {
            throw IllegalArgumentException("certificateDer is not a DER-encoded X.509 certificate.")
        }
}

/**
 * Stores identities in the macOS login keychain through the JDK `KeychainStore` provider, using
 * the namespaced label as the keychain alias. The password only protects the provider's transient
 * PKCS#12 exchange with the Security framework.
 */
internal class MacOSCertificateBackend(
    internal val keyStore: () -> KeyStore = { KeyStore.getInstance("KeychainStore") },
) : JvmCertificateBackend() {
    override fun storeIdentity(
        label: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ) {
        val identity = loadPkcs12Identity(pkcs12, passphrase)
        keychain { store ->
            if (store.containsAlias(label)) store.deleteEntry(label)
            store.setKeyEntry(label, identity.privateKey, TRANSFER_PASSWORD.toCharArray(), identity.chain.toTypedArray())
            store.store(null, TRANSFER_PASSWORD.toCharArray())
        }
    }

    override fun deleteIdentity(label: String) =
        keychain { store ->
            if (store.containsAlias(label)) {
                store.deleteEntry(label)
                store.store(null, TRANSFER_PASSWORD.toCharArray())
            }
        }

    private fun keychain(block: (KeyStore) -> Unit) {
        try {
            block(keyStore().apply { load(null, null) })
        } catch (_: Exception) {
            // Provider exceptions can describe certificates; never attach them.
            throw KeychainUnavailableException(Reason.Failed, "macOS KeychainStore operation failed")
        }
    }

    internal companion object {
        const val TRANSFER_PASSWORD = "credential-keychain-kotlin"
    }
}

/**
 * Linux has no standard secure identity store, so the identity is re-encoded as PKCS#12 and kept
 * in Secret Service beside the chain metadata. Bundles over the `secret-tool` limit are unsupported.
 */
internal class LinuxCertificateBackend(
    private val metadata: CredentialKeychain,
) : JvmCertificateBackend() {
    override fun storeIdentity(
        label: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ) {
        val identity = loadPkcs12Identity(pkcs12, passphrase)
        val bundle =
            KeyStore.getInstance("PKCS12").run {
                load(null, null)
                setKeyEntry(BUNDLE_ALIAS, identity.privateKey, BUNDLE_PASSWORD.toCharArray(), identity.chain.toTypedArray())
                ByteArrayOutputStream().also { store(it, BUNDLE_PASSWORD.toCharArray()) }.toByteArray()
            }
        try {
            metadata.write(identityKey(label), Base64.getEncoder().encodeToString(bundle))
        } catch (_: IllegalArgumentException) {
            throw KeychainUnavailableException(Reason.Unsupported, "PKCS#12 bundles over 8 KiB are not supported by Linux Secret Service")
        }
    }

    override fun deleteIdentity(label: String) = metadata.delete(identityKey(label))

    /** Returns the stored identity, or `null` if none exists. */
    internal fun readIdentity(label: String): Pkcs12Identity? =
        metadata.read(identityKey(label))?.let {
            try {
                loadPkcs12Identity(Base64.getDecoder().decode(it), BUNDLE_PASSWORD.toCharArray())
            } catch (_: IllegalArgumentException) {
                throw KeychainUnavailableException(Reason.Corrupted, "Linux identity bundle is malformed")
            }
        }

    private fun identityKey(label: String) = "identity:$label"

    private companion object {
        const val BUNDLE_ALIAS = "identity"

        // Secret Service provides the protection; this only satisfies the PKCS#12 format.
        const val BUNDLE_PASSWORD = "credential-keychain-kotlin"
    }
}

/**
 * Imports identities into the Windows current-user `My` certificate store with a non-exportable,
 * persisted private key, tagged by friendly name. Deleting removes the certificate and its key
 * container. Bundles and passphrases travel only through stdin.
 */
internal class WindowsCertificateBackend(
    private val shell: PowerShell,
) : JvmCertificateBackend() {
    override fun storeIdentity(
        label: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ) {
        shell.requireExecutable()
        val encodedBundle = Base64.getEncoder().encodeToString(pkcs12)
        val encodedPassphrase = Base64.getEncoder().encodeToString(String(passphrase).toByteArray(Charsets.UTF_8))
        run(
            """
            $REMOVE_FUNCTION
            ${'$'}bytes = [System.Convert]::FromBase64String(${PowerShell.literal(encodedBundle)})
            ${'$'}password = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${PowerShell.literal(
                encodedPassphrase,
            )}))
            ${'$'}flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'PersistKeySet,UserKeySet'
            ${'$'}certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(${'$'}bytes, ${'$'}password, ${'$'}flags)
            ${'$'}certificate.FriendlyName = ${PowerShell.literal(label)}
            Remove-CkkCertificates ${PowerShell.literal(label)}
            ${'$'}store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
            ${'$'}store.Open('ReadWrite')
            try { ${'$'}store.Add(${'$'}certificate) } finally { ${'$'}store.Close() }
            """.trimIndent(),
        )
    }

    override fun deleteIdentity(label: String) {
        shell.requireExecutable()
        run("$REMOVE_FUNCTION\nRemove-CkkCertificates ${PowerShell.literal(label)}")
    }

    private fun run(script: String) = shell.run(script, "Windows certificate store operation failed")

    private companion object {
        val REMOVE_FUNCTION =
            """
            function Remove-CkkCertificates([string]${'$'}label) {
                ${'$'}store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
                ${'$'}store.Open('ReadWrite')
                try {
                    foreach (${'$'}existing in @(${'$'}store.Certificates | Where-Object { ${'$'}_.FriendlyName -eq ${'$'}label })) {
                        if (${'$'}existing.HasPrivateKey) {
                            try {
                                ${'$'}rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(${'$'}existing)
                                if (${'$'}rsa -is [System.Security.Cryptography.RSACng]) { ${'$'}rsa.Key.Delete() }
                                elseif (${'$'}rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) { ${'$'}rsa.PersistKeyInCsp = ${'$'}false; ${'$'}rsa.Clear() }
                            } catch { }
                            try {
                                ${'$'}ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey(${'$'}existing)
                                if (${'$'}ecdsa -is [System.Security.Cryptography.ECDsaCng]) { ${'$'}ecdsa.Key.Delete() }
                            } catch { }
                        }
                        ${'$'}store.Remove(${'$'}existing)
                    }
                } finally {
                    ${'$'}store.Close()
                }
            }
            """.trimIndent()
    }
}
