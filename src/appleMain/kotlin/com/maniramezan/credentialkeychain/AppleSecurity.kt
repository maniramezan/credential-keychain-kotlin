@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.UnsafeNumber::class)

package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Security.*

internal fun secFailure(
    reason: Reason,
    message: String,
) = KeychainUnavailableException(reason, message)

internal fun checkSecStatus(status: Int) {
    if (status == errSecSuccess) return
    val reason =
        when (status) {
            errSecUserCanceled -> Reason.Canceled
            errSecInteractionNotAllowed, errSecAuthFailed -> Reason.Locked
            errSecMissingEntitlement, errSecNotAvailable -> Reason.Unsupported
            else -> Reason.Failed
        }
    throw secFailure(reason, "Apple Keychain status $status")
}

internal fun accessibleAttribute(accessibility: AppleAccessibility): CFStringRef? =
    when (accessibility) {
        AppleAccessibility.WhenUnlocked -> kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        AppleAccessibility.AfterFirstUnlock -> kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }

/**
 * Builds a non-synchronizable query for [itemClass] with every non-null string attribute in
 * [attributes], runs [block], and releases everything it created.
 */
internal fun <T> withSecQuery(
    itemClass: CFStringRef?,
    attributes: List<Pair<CFStringRef?, String?>>,
    block: (CFMutableDictionaryRef) -> T,
): T {
    val query =
        CFDictionaryCreateMutable(null, 0, null, null) ?: throw secFailure(Reason.Failed, "cannot allocate Keychain query")
    val strings = mutableListOf<CFStringRef>()
    try {
        CFDictionarySetValue(query, kSecClass, itemClass)
        for ((attribute, value) in attributes) {
            if (value == null) continue
            val string =
                CFStringCreateWithCString(null, value, kCFStringEncodingUTF8)
                    ?: throw secFailure(Reason.Failed, "cannot allocate Keychain string")
            strings += string
            CFDictionarySetValue(query, attribute, string)
        }
        CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse)
        return block(query)
    } finally {
        CFRelease(query)
        strings.forEach { CFRelease(it) }
    }
}

/** Runs [block] with a CFData copy of [bytes], which must not be empty. */
internal fun <T> withCFData(
    bytes: ByteArray,
    block: (CFDataRef) -> T,
): T {
    val data =
        bytes.usePinned { pinned -> CFDataCreate(kCFAllocatorDefault, pinned.addressOf(0).reinterpret(), bytes.size.convert()) }
            ?: throw secFailure(Reason.Failed, "cannot allocate Keychain data")
    try {
        return block(data)
    } finally {
        CFRelease(data)
    }
}

/** Updates the item matching [query] with [data], or adds it when missing, retrying the update after an insert race. */
internal fun secItemUpsert(
    query: CFMutableDictionaryRef,
    data: CFDataRef,
    accessible: CFStringRef?,
) {
    val updates =
        CFDictionaryCreateMutable(null, 0, null, null) ?: throw secFailure(Reason.Failed, "cannot allocate Keychain query")
    try {
        CFDictionarySetValue(updates, kSecValueData, data)
        CFDictionarySetValue(updates, kSecAttrAccessible, accessible)
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
        checkSecStatus(status)
    } finally {
        CFRelease(updates)
    }
}

/** Returns the strictly decoded UTF-8 data of the single item matching [query], or `null` if none matches. */
internal fun secItemCopyString(query: CFMutableDictionaryRef): String? {
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue)
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
    return memScoped {
        val result = alloc<CFTypeRefVar>()
        result.value = null
        val status = SecItemCopyMatching(query, result.ptr)
        if (status == errSecItemNotFound) return@memScoped null
        checkSecStatus(status)
        val data: CFDataRef = result.value?.reinterpret() ?: throw secFailure(Reason.Failed, "Apple Keychain returned no data")
        try {
            val size = CFDataGetLength(data).toInt()
            val bytes = if (size == 0) ByteArray(0) else CFDataGetBytePtr(data)?.readBytes(size) ?: ByteArray(0)
            try {
                bytes.decodeToString(throwOnInvalidSequence = true)
            } catch (_: CharacterCodingException) {
                throw secFailure(Reason.Corrupted, "Apple Keychain returned invalid UTF-8")
            }
        } finally {
            CFRelease(data)
        }
    }
}

/** Returns the account attribute of every item matching [query]. */
internal fun secItemCopyAccounts(query: CFMutableDictionaryRef): List<String> {
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue)
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll)
    return memScoped {
        val result = alloc<CFTypeRefVar>()
        result.value = null
        val status = SecItemCopyMatching(query, result.ptr)
        if (status == errSecItemNotFound) return@memScoped emptyList()
        checkSecStatus(status)
        val items: CFArrayRef = result.value?.reinterpret() ?: throw secFailure(Reason.Failed, "Apple Keychain returned no items")
        try {
            (0 until CFArrayGetCount(items).toInt()).map { index ->
                val item: CFDictionaryRef =
                    CFArrayGetValueAtIndex(items, index.convert())?.reinterpret()
                        ?: throw secFailure(Reason.Corrupted, "Apple Keychain returned an invalid item")
                val account: CFStringRef =
                    CFDictionaryGetValue(item, kSecAttrAccount)?.reinterpret()
                        ?: throw secFailure(Reason.Corrupted, "Apple Keychain item has no account")
                account.toKotlinString()
            }
        } finally {
            CFRelease(items)
        }
    }
}

/** Deletes the items matching [query]; a missing item is not an error. */
internal fun secItemDelete(query: CFMutableDictionaryRef) {
    val status = SecItemDelete(query)
    if (status != errSecItemNotFound) checkSecStatus(status)
}

/** Deletes every item matching [query]; the file-based macOS keychain may delete one match per call. */
internal fun secItemDeleteAll(query: CFMutableDictionaryRef) {
    repeat(MAX_CLEAR_ITERATIONS) {
        val status = SecItemDelete(query)
        if (status == errSecItemNotFound) return
        checkSecStatus(status)
    }
    throw secFailure(Reason.Failed, "Apple Keychain clear did not finish")
}

/** Runs [block] with a dictionary that retains its keys and values, then releases it. */
internal fun <T> withRetainingDictionary(block: (CFMutableDictionaryRef) -> T): T {
    val dictionary =
        CFDictionaryCreateMutable(null, 0, kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
            ?: throw secFailure(Reason.Failed, "cannot allocate Keychain dictionary")
    try {
        return block(dictionary)
    } finally {
        CFRelease(dictionary)
    }
}

/** Sets a string value; the dictionary must retain its values. */
internal fun CFMutableDictionaryRef.setString(
    key: CFStringRef?,
    value: String,
) {
    val string =
        CFStringCreateWithCString(null, value, kCFStringEncodingUTF8) ?: throw secFailure(Reason.Failed, "cannot allocate Keychain string")
    CFDictionarySetValue(this, key, string)
    CFRelease(string)
}

/** Sets a data value; the dictionary must retain its values. */
internal fun CFMutableDictionaryRef.setData(
    key: CFStringRef?,
    value: ByteArray,
) = withAnyCFData(value) { CFDictionarySetValue(this, key, it) }

/** Sets an integer value; the dictionary must retain its values. */
internal fun CFMutableDictionaryRef.setInt(
    key: CFStringRef?,
    value: Int,
) = memScoped {
    val number = alloc<IntVar>()
    number.value = value
    val cfNumber = CFNumberCreate(null, kCFNumberIntType, number.ptr) ?: throw secFailure(Reason.Failed, "cannot allocate Keychain number")
    CFDictionarySetValue(this@setInt, key, cfNumber)
    CFRelease(cfNumber)
}

/** Runs [block] with a CFData copy of [bytes], which may be empty. */
internal fun <T> withAnyCFData(
    bytes: ByteArray,
    block: (CFDataRef) -> T,
): T {
    if (bytes.isNotEmpty()) return withCFData(bytes, block)
    val data = CFDataCreate(kCFAllocatorDefault, null, 0) ?: throw secFailure(Reason.Failed, "cannot allocate Keychain data")
    try {
        return block(data)
    } finally {
        CFRelease(data)
    }
}

internal fun CFDataRef.toByteArray(): ByteArray {
    val size = CFDataGetLength(this).toInt()
    return if (size == 0) ByteArray(0) else CFDataGetBytePtr(this)?.readBytes(size) ?: ByteArray(0)
}

internal fun CFStringRef.toKotlinString(): String =
    memScoped {
        val length = CFStringGetLength(this@toKotlinString)
        val capacity = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8).toLong() + 1
        val buffer = allocArray<ByteVar>(capacity)
        if (!CFStringGetCString(this@toKotlinString, buffer, capacity.convert(), kCFStringEncodingUTF8)) {
            throw secFailure(Reason.Corrupted, "Apple Keychain returned an invalid string")
        }
        buffer.toKString()
    }
