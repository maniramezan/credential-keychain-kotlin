@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.UnsafeNumber::class)

package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Security.*

internal actual fun platformHardwareKeyStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): HardwareKeyStore = AppleHardwareKeyStore(serviceName, accountName, options.appleAccessibility)

/**
 * P-256 private keys whose application tag is the service/account namespace and whose label is
 * the alias. Generation tries the Secure Enclave first. Secure Enclave keys live in the
 * data-protection keychain, which unsigned macOS processes cannot use, so every lookup searches
 * the data-protection keychain first and then, on macOS, the file-based keychain that holds
 * software fallback keys. On iOS, tvOS, and watchOS both searches reach the same keychain.
 */
internal class AppleHardwareKeyStore(
    service: String,
    account: String,
    private val accessibility: AppleAccessibility,
) : HardwareKeyStore {
    private val tag = credentialNamespace(service, account).encodeToByteArray()

    override fun generate(
        alias: String,
        spec: HardwareKeySpec,
    ): HardwareKeyInfo {
        delete(alias)
        val enclaveStatus = createKey(alias, secureEnclave = true)
        if (enclaveStatus != errSecSuccess) {
            if (enclaveStatus == errSecInteractionNotAllowed || enclaveStatus == errSecUserCanceled) checkSecStatus(enclaveStatus)
            if (!spec.allowSoftwareKeys) {
                throw secFailure(Reason.Unsupported, "Apple Secure Enclave is not available (status $enclaveStatus)")
            }
            checkSecStatus(createKey(alias, secureEnclave = false))
        }
        return info(alias) ?: throw secFailure(Reason.Failed, "Apple Keychain did not store the key")
    }

    override fun info(alias: String): HardwareKeyInfo? =
        withKey(alias) { key, attributes -> HardwareKeyInfo(alias, publicKeyDer(key), securityLevel(attributes)) }

    override fun sign(
        alias: String,
        data: ByteArray,
    ): ByteArray? =
        withKey(alias) { key, _ ->
            withAnyCFData(data) { input ->
                memScoped {
                    val error = alloc<CFErrorRefVar>()
                    val signature =
                        SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, input, error.ptr)
                            ?: throw errorFailure(error.value, "Apple Secure Enclave signing failed")
                    try {
                        signature.toByteArray()
                    } finally {
                        CFRelease(signature)
                    }
                }
            }
        }

    override fun delete(alias: String) = deleteMatching(alias)

    override fun clear() = deleteMatching(alias = null)

    /** Returns the security status of creating the key, so callers can decide whether to fall back. */
    private fun createKey(
        alias: String,
        secureEnclave: Boolean,
    ): Int {
        val accessControl =
            if (secureEnclave) {
                SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    accessibleAttribute(accessibility),
                    kSecAccessControlPrivateKeyUsage,
                    null,
                )
                    ?: return errSecParam
            } else {
                null
            }
        try {
            return withRetainingDictionary { privateAttributes ->
                CFDictionarySetValue(privateAttributes, kSecAttrIsPermanent, kCFBooleanTrue)
                privateAttributes.setData(kSecAttrApplicationTag, tag)
                privateAttributes.setString(kSecAttrLabel, alias)
                if (accessControl != null) {
                    CFDictionarySetValue(privateAttributes, kSecAttrAccessControl, accessControl)
                } else {
                    CFDictionarySetValue(privateAttributes, kSecAttrAccessible, accessibleAttribute(accessibility))
                }
                withRetainingDictionary { attributes ->
                    CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
                    attributes.setInt(kSecAttrKeySizeInBits, 256)
                    if (secureEnclave) {
                        CFDictionarySetValue(attributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
                        CFDictionarySetValue(attributes, kSecUseDataProtectionKeychain, kCFBooleanTrue)
                    }
                    CFDictionarySetValue(attributes, kSecPrivateKeyAttrs, privateAttributes)
                    memScoped {
                        val error = alloc<CFErrorRefVar>()
                        val key = SecKeyCreateRandomKey(attributes, error.ptr)
                        if (key != null) {
                            CFRelease(key)
                            errSecSuccess
                        } else {
                            val cause = error.value
                            val status = cause?.let { CFErrorGetCode(it).toInt() } ?: errSecParam
                            cause?.let { CFRelease(it) }
                            status
                        }
                    }
                }
            }
        } finally {
            accessControl?.let { CFRelease(it) }
        }
    }

    /** Runs [block] with the first matching private key and its attributes, or returns `null` if no keychain has it. */
    private fun <T> withKey(
        alias: String,
        block: (SecKeyRef, CFDictionaryRef) -> T,
    ): T? {
        for (dataProtection in listOf(true, false)) {
            val item =
                keyQuery(alias, dataProtection) { query ->
                    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue)
                    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue)
                    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
                    memScoped {
                        val result = alloc<CFTypeRefVar>()
                        result.value = null
                        val status = SecItemCopyMatching(query, result.ptr)
                        if (status == errSecItemNotFound || status == errSecMissingEntitlement) return@memScoped null
                        checkSecStatus(status)
                        val found: CFDictionaryRef =
                            result.value?.reinterpret() ?: throw secFailure(Reason.Failed, "Apple Keychain returned no key")
                        found
                    }
                } ?: continue
            try {
                val key: SecKeyRef =
                    CFDictionaryGetValue(item, kSecValueRef)?.reinterpret()
                        ?: throw secFailure(Reason.Corrupted, "Apple Keychain item has no key")
                return block(key, item)
            } finally {
                CFRelease(item)
            }
        }
        return null
    }

    private fun deleteMatching(alias: String?) {
        for (dataProtection in listOf(true, false)) {
            keyQuery(alias, dataProtection) { query ->
                repeat(MAX_CLEAR_ITERATIONS) {
                    val status = SecItemDelete(query)
                    if (status == errSecItemNotFound || status == errSecMissingEntitlement) return@keyQuery
                    checkSecStatus(status)
                }
                throw secFailure(Reason.Failed, "Apple Keychain key delete did not finish")
            }
        }
    }

    private fun <T> keyQuery(
        alias: String?,
        dataProtection: Boolean,
        block: (CFMutableDictionaryRef) -> T,
    ): T =
        withRetainingDictionary { query ->
            CFDictionarySetValue(query, kSecClass, kSecClassKey)
            CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
            CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
            query.setData(kSecAttrApplicationTag, tag)
            if (alias != null) query.setString(kSecAttrLabel, alias)
            if (dataProtection) CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue)
            block(query)
        }

    private fun publicKeyDer(privateKey: SecKeyRef): ByteArray {
        val publicKey = SecKeyCopyPublicKey(privateKey) ?: throw secFailure(Reason.Corrupted, "Apple key has no public key")
        try {
            return memScoped {
                val error = alloc<CFErrorRefVar>()
                val data =
                    SecKeyCopyExternalRepresentation(publicKey, error.ptr)
                        ?: throw errorFailure(error.value, "Apple public key export failed")
                try {
                    p256SubjectPublicKeyInfo(data.toByteArray()) ?: throw secFailure(Reason.Corrupted, "Apple key is not P-256")
                } finally {
                    CFRelease(data)
                }
            }
        } finally {
            CFRelease(publicKey)
        }
    }

    private fun securityLevel(attributes: CFDictionaryRef): SecurityLevel {
        val token: CFStringRef? = CFDictionaryGetValue(attributes, kSecAttrTokenID)?.reinterpret()
        val secureEnclave = kSecAttrTokenIDSecureEnclave
        return if (token != null && secureEnclave != null && token.toKotlinString() == secureEnclave.toKotlinString()) {
            SecurityLevel.SecureEnclave
        } else {
            SecurityLevel.Software
        }
    }

    private fun errorFailure(
        error: CFErrorRef?,
        message: String,
    ): KeychainUnavailableException {
        val status = error?.let { CFErrorGetCode(it).toInt() } ?: errSecParam
        error?.let { CFRelease(it) }
        return try {
            checkSecStatus(status)
            secFailure(Reason.Failed, message)
        } catch (failure: KeychainUnavailableException) {
            failure
        }
    }
}
