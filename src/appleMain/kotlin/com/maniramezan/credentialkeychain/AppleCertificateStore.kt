@file:OptIn(
    kotlinx.cinterop.ExperimentalForeignApi::class,
    kotlinx.cinterop.UnsafeNumber::class,
    kotlin.experimental.ExperimentalNativeApi::class,
)

package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Security.*
import platform.posix.RTLD_NOW
import platform.posix.dlopen
import platform.posix.dlsym
import kotlin.native.OsFamily
import kotlin.native.Platform

internal actual fun platformCertificateStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CertificateStore =
    KeychainCertificateStore(
        credentialNamespace(serviceName, accountName),
        AppleKeychain(credentialNamespace(serviceName, CERTIFICATE_METADATA_SERVICE), accountName, options.appleAccessibility),
        AppleCertificateBackend(options.appleAccessibility),
    )

/**
 * Stores identities in the data-protection keychain. PKCS#12 data is decoded in memory with
 * `SecPKCS12Import`, then `SecItemAdd` stores the identity (certificate and private key) with the
 * namespaced label; deleting the identity by label removes both parts.
 *
 * Unsigned macOS processes cannot use the data-protection keychain and get `Unsupported`. On macOS,
 * `SecPKCS12Import` also adds identities to the default keychain unless `kSecImportToMemoryOnly`
 * is passed, which exists only from macOS 15, so identities require macOS 15 or later there.
 */
internal class AppleCertificateBackend(
    private val accessibility: AppleAccessibility,
) : CertificateBackend {
    override fun parsePkcs12(
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): List<ByteArray> = withImportedIdentity(pkcs12, passphrase) { identity, chain -> chainDer(identity, chain) }

    override fun parseCertificate(der: ByteArray): ByteArray =
        withAnyCFData(der) { data ->
            val certificate =
                SecCertificateCreateWithData(null, data)
                    ?: throw IllegalArgumentException("certificateDer is not a DER-encoded X.509 certificate.")
            try {
                certificateDer(certificate)
            } finally {
                CFRelease(certificate)
            }
        }

    override fun storeIdentity(
        label: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ) = withImportedIdentity(pkcs12, passphrase) { identity, _ ->
        withRetainingDictionary { query ->
            CFDictionarySetValue(query, kSecValueRef, identity)
            query.setString(kSecAttrLabel, label)
            CFDictionarySetValue(query, kSecAttrAccessible, accessibleAttribute(accessibility))
            CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue)
            val status = SecItemAdd(query, null)
            // Keychain identities are unique by certificate and key, so one identity can back only one alias.
            if (status == errSecDuplicateItem) {
                throw secFailure(Reason.Failed, "this identity is already stored in the keychain under another alias")
            }
            checkSecStatus(status)
        }
    }

    override fun deleteIdentity(label: String) =
        withRetainingDictionary { query ->
            CFDictionarySetValue(query, kSecClass, kSecClassIdentity)
            query.setString(kSecAttrLabel, label)
            CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue)
            val status = SecItemDelete(query)
            // A process without keychain entitlements can never have stored an identity.
            if (status != errSecItemNotFound && status != errSecMissingEntitlement) checkSecStatus(status)
        }

    private fun <T> withImportedIdentity(
        pkcs12: ByteArray,
        passphrase: CharArray,
        block: (SecIdentityRef, CFArrayRef?) -> T,
    ): T {
        val memoryOnly = importToMemoryOnlyOption()
        if (memoryOnly == null && Platform.osFamily == OsFamily.MACOSX) {
            throw secFailure(Reason.Unsupported, "certificate identities require macOS 15 or later")
        }
        return withRetainingDictionary { options ->
            options.setString(kSecImportExportPassphrase, passphrase.concatToString())
            if (memoryOnly != null) CFDictionarySetValue(options, memoryOnly, kCFBooleanTrue)
            withAnyCFData(pkcs12) { data ->
                memScoped {
                    val items = alloc<CFArrayRefVar>()
                    items.value = null
                    val status = SecPKCS12Import(data, options, items.ptr)
                    val array = items.value
                    try {
                        when (status) {
                            errSecSuccess -> {
                                Unit
                            }

                            errSecAuthFailed, errSecDecode, errSecPkcs12VerifyFailure -> {
                                throw IllegalArgumentException("pkcs12 is malformed or the passphrase is incorrect.")
                            }

                            else -> {
                                checkSecStatus(status)
                            }
                        }
                        val identities =
                            (0 until (array?.let { CFArrayGetCount(it).toInt() } ?: 0)).mapNotNull { index ->
                                val item: CFDictionaryRef =
                                    CFArrayGetValueAtIndex(array, index.convert())?.reinterpret() ?: return@mapNotNull null
                                val identity: SecIdentityRef =
                                    CFDictionaryGetValue(item, kSecImportItemIdentity)?.reinterpret() ?: return@mapNotNull null
                                val chain: CFArrayRef? = CFDictionaryGetValue(item, kSecImportItemCertChain)?.reinterpret()
                                identity to chain
                            }
                        require(identities.size == 1) { "pkcs12 must contain exactly one private key." }
                        block(identities.single().first, identities.single().second)
                    } finally {
                        array?.let { CFRelease(it) }
                    }
                }
            }
        }
    }

    /** Leaf certificate first, followed by the rest of the chain without repeating the leaf. */
    private fun chainDer(
        identity: SecIdentityRef,
        chain: CFArrayRef?,
    ): List<ByteArray> {
        val leaf =
            memScoped {
                val certificate = alloc<SecCertificateRefVar>()
                checkSecStatus(SecIdentityCopyCertificate(identity, certificate.ptr))
                val reference = certificate.value ?: throw secFailure(Reason.Corrupted, "identity has no certificate")
                try {
                    certificateDer(reference)
                } finally {
                    CFRelease(reference)
                }
            }
        val rest =
            (0 until (chain?.let { CFArrayGetCount(it).toInt() } ?: 0))
                .mapNotNull { index ->
                    val certificate: SecCertificateRef? = CFArrayGetValueAtIndex(chain, index.convert())?.reinterpret()
                    certificate?.let { certificateDer(it) }
                }.filterNot { it.contentEquals(leaf) }
        return listOf(leaf) + rest
    }

    private fun certificateDer(certificate: SecCertificateRef): ByteArray {
        val data = SecCertificateCopyData(certificate) ?: throw secFailure(Reason.Corrupted, "certificate has no data")
        try {
            return data.toByteArray()
        } finally {
            CFRelease(data)
        }
    }

    /**
     * `kSecImportToMemoryOnly` exists only from iOS/tvOS 18, watchOS 11, and macOS 15. It is looked
     * up at runtime so the framework still loads on older systems, where it returns `null`.
     */
    private fun importToMemoryOnlyOption(): CFStringRef? {
        val symbol = dlsym(dlopen(null, RTLD_NOW), "kSecImportToMemoryOnly") ?: return null
        return symbol.reinterpret<CFStringRefVar>().pointed.value
    }
}
