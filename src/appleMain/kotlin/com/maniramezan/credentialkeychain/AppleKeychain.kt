@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.UnsafeNumber::class)

package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Security.*

internal actual fun platformKeychain(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CredentialKeychain = AppleKeychain(serviceName, accountName, options.appleAccessibility)

/**
 * Generic-password items whose service attribute is the length-prefixed service/account
 * namespace and whose account attribute is the entry key, so [clear] can match the whole
 * namespace with a single query.
 */
internal class AppleKeychain(
    service: String,
    account: String,
    accessibility: AppleAccessibility,
) : CredentialKeychain {
    private val namespace = credentialNamespace(service, account)
    private val accessible =
        when (accessibility) {
            AppleAccessibility.WhenUnlocked -> kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            AppleAccessibility.AfterFirstUnlock -> kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }

    override fun read(key: String): String? =
        query(key) { query ->
            CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue)
            CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
            memScoped {
                val result = alloc<CFTypeRefVar>()
                result.value = null
                val status = SecItemCopyMatching(query, result.ptr)
                if (status == errSecItemNotFound) return@memScoped null
                checkStatus(status)
                val data: CFDataRef = result.value?.reinterpret() ?: throw failure(Reason.Failed, "Apple Keychain returned no data")
                try {
                    val size = CFDataGetLength(data).toInt()
                    val bytes = if (size == 0) ByteArray(0) else CFDataGetBytePtr(data)?.readBytes(size) ?: ByteArray(0)
                    try {
                        bytes.decodeToString(throwOnInvalidSequence = true)
                    } catch (_: CharacterCodingException) {
                        throw failure(Reason.Corrupted, "Apple Keychain returned invalid UTF-8")
                    }
                } finally {
                    CFRelease(data)
                }
            }
        }

    override fun write(
        key: String,
        value: String,
    ) {
        val bytes = value.encodeToByteArray()
        bytes.usePinned { pinned ->
            val data =
                CFDataCreate(kCFAllocatorDefault, pinned.addressOf(0).reinterpret(), bytes.size.convert())
                    ?: throw failure(Reason.Failed, "cannot allocate Keychain data")
            try {
                val updates = dictionary()
                try {
                    CFDictionarySetValue(updates, kSecValueData, data)
                    CFDictionarySetValue(updates, kSecAttrAccessible, accessible)
                    query(key) { query ->
                        var status = SecItemUpdate(query, updates)
                        if (status == errSecItemNotFound) {
                            CFDictionarySetValue(query, kSecValueData, data)
                            CFDictionarySetValue(query, kSecAttrAccessible, accessible)
                            status = SecItemAdd(query, null)
                            // Another instance may have inserted between update and add.
                            if (status == errSecDuplicateItem) {
                                CFDictionaryRemoveValue(query, kSecValueData)
                                CFDictionaryRemoveValue(query, kSecAttrAccessible)
                                status = SecItemUpdate(query, updates)
                            }
                        }
                        checkStatus(status)
                    }
                } finally {
                    CFRelease(updates)
                }
            } finally {
                CFRelease(data)
            }
        }
    }

    override fun delete(key: String) =
        query(key) { query ->
            val status = SecItemDelete(query)
            if (status != errSecItemNotFound) checkStatus(status)
        }

    override fun clear() =
        query(key = null) { query ->
            // The file-based macOS keychain may delete one match per call; repeat until none remain.
            repeat(MAX_CLEAR_ITERATIONS) {
                val status = SecItemDelete(query)
                if (status == errSecItemNotFound) return@query
                checkStatus(status)
            }
            throw failure(Reason.Failed, "Apple Keychain clear did not finish")
        }

    /** Builds a query for one entry, or for the whole namespace when [key] is `null`. */
    private fun <T> query(
        key: String?,
        block: (CFMutableDictionaryRef) -> T,
    ): T {
        val query = dictionary()
        var serviceValue: CFStringRef? = null
        var accountValue: CFStringRef? = null
        try {
            serviceValue = cfString(namespace)
            CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionarySetValue(query, kSecAttrService, serviceValue)
            if (key != null) {
                accountValue = cfString(key)
                CFDictionarySetValue(query, kSecAttrAccount, accountValue)
            }
            CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse)
            return block(query)
        } finally {
            CFRelease(query)
            serviceValue?.let(::CFRelease)
            accountValue?.let(::CFRelease)
        }
    }

    private fun cfString(value: String): CFStringRef =
        CFStringCreateWithCString(null, value, kCFStringEncodingUTF8) ?: throw failure(Reason.Failed, "cannot allocate Keychain string")

    private fun dictionary(): CFMutableDictionaryRef =
        CFDictionaryCreateMutable(null, 0, null, null) ?: throw failure(Reason.Failed, "cannot allocate Keychain query")

    private fun checkStatus(status: Int) {
        if (status == errSecSuccess) return
        val reason =
            when (status) {
                errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled -> Reason.Locked
                errSecMissingEntitlement, errSecNotAvailable -> Reason.Unsupported
                else -> Reason.Failed
            }
        throw failure(reason, "Apple Keychain status $status")
    }

    private fun failure(
        reason: Reason,
        message: String,
    ) = KeychainUnavailableException(reason, message)
}
