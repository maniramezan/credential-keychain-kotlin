@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package dev.amoo.credentialkeychain

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Security.*

internal actual fun platformKeychain(serviceName: String, accountName: String): CredentialKeychain =
    AppleKeychain(serviceName, accountName)

internal class AppleKeychain(private val service: String, private val account: String) : CredentialKeychain {
    override fun read(key: String): String? = query(key) { query ->
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue)
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
        memScoped {
            val result = alloc<CFTypeRefVar>()
            result.value = null
            val status = SecItemCopyMatching(query, result.ptr)
            if (status == errSecItemNotFound) return@memScoped null
            checkStatus(status)
            val data: CFDataRef = checkNotNull(result.value).reinterpret()
            try {
                val size = CFDataGetLength(data).toInt()
                if (size == 0) "" else checkNotNull(CFDataGetBytePtr(data)).readBytes(size).decodeToString()
            } finally { CFRelease(data) }
        }
    }

    override fun write(key: String, value: String) {
        if (value.isBlank()) { delete(key); return }
        val bytes = value.encodeToByteArray()
        bytes.usePinned { pinned ->
            val data = checkNotNull(CFDataCreate(kCFAllocatorDefault, pinned.addressOf(0).reinterpret(), bytes.size.convert()))
            val updates = dictionary()
            try {
                CFDictionarySetValue(updates, kSecValueData, data)
                query(key) { query ->
                    var status = SecItemUpdate(query, updates)
                    if (status == errSecItemNotFound) {
                        CFDictionarySetValue(query, kSecValueData, data)
                        CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
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
            } finally { CFRelease(updates); CFRelease(data) }
        }
    }

    override fun delete(key: String) = query(key) { query ->
        val status = SecItemDelete(query)
        if (status != errSecItemNotFound) checkStatus(status)
    }

    private fun <T> query(key: String, block: (CFMutableDictionaryRef) -> T): T {
        val query = dictionary()
        val serviceValue = checkNotNull(CFStringCreateWithCString(null, credentialNamespace(service, key), kCFStringEncodingUTF8))
        val accountValue = checkNotNull(CFStringCreateWithCString(null, account, kCFStringEncodingUTF8))
        try {
            CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionarySetValue(query, kSecAttrService, serviceValue)
            CFDictionarySetValue(query, kSecAttrAccount, accountValue)
            CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse)
            return block(query)
        } finally { CFRelease(query); CFRelease(serviceValue); CFRelease(accountValue) }
    }

    private fun dictionary(): CFMutableDictionaryRef =
        checkNotNull(CFDictionaryCreateMutable(null, 0, null, null))

    private fun checkStatus(status: Int) {
        if (status != errSecSuccess) throw KeychainUnavailableException("Apple Keychain status $status")
    }
}
