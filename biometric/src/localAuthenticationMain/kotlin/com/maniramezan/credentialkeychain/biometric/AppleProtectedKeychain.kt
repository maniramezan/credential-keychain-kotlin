@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.UnsafeNumber::class, kotlinx.cinterop.BetaInteropApi::class)

package com.maniramezan.credentialkeychain.biometric

import com.maniramezan.credentialkeychain.KeychainUnavailableException
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlinx.cinterop.*
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.CoreFoundation.*
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSError
import platform.LocalAuthentication.*
import platform.Security.*
import platform.darwin.DISPATCH_QUEUE_PRIORITY_DEFAULT
import platform.darwin.dispatch_async
import platform.darwin.dispatch_get_global_queue
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal actual fun platformProtectedKeychain(
    serviceName: String,
    accountName: String,
): ProtectedKeychain = AppleProtectedKeychain(serviceName, accountName)

/**
 * Generic-password items in the data-protection keychain whose access control requires the
 * current biometric enrollment (`biometryCurrentSet`). The service attribute is the biometric
 * namespace and the account attribute is the entry key. Reads pass an `LAContext` carrying the
 * prompt text; attribute-only lookups need no authentication.
 */
internal class AppleProtectedKeychain(
    service: String,
    account: String,
) : ProtectedKeychain {
    private val namespace = credentialNamespace(BIOMETRIC_NAMESPACE, service, account)

    override suspend fun read(
        key: String,
        prompt: AuthenticationPrompt,
    ): String? {
        if (!exists(key)) return null
        biometryFailure(biometryErrorCode(), reading = true)?.let { throw it }
        val context = LAContext().apply { localizedReason = prompt.reason }
        return suspendCancellableCoroutine { continuation ->
            // Invalidating the context dismisses a visible prompt; the blocked lookup then returns.
            continuation.invokeOnCancellation { context.invalidate() }
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT.convert(), 0u)) {
                val result = runCatching { copyValue(key, context) }
                if (continuation.isActive) {
                    result.fold({ continuation.resume(it) }, { continuation.resumeWithException(it) })
                }
            }
        }
    }

    override fun write(
        key: String,
        value: String,
    ) {
        biometryFailure(biometryErrorCode(), reading = false)?.let { throw it }
        // Updating a protected item would require authentication, so replace it instead.
        delete(key)
        query(key) { query ->
            val access =
                SecAccessControlCreateWithFlags(
                    null,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    kSecAccessControlBiometryCurrentSet,
                    null,
                )
                    ?: throw failure(Reason.Failed, "cannot create Keychain access control")
            CFDictionarySetValue(query, kSecAttrAccessControl, access)
            CFRelease(access)
            val bytes = value.encodeToByteArray()
            val data =
                bytes.usePinned { CFDataCreate(null, it.addressOf(0).reinterpret(), bytes.size.convert()) }
                    ?: throw failure(Reason.Failed, "cannot allocate Keychain data")
            CFDictionarySetValue(query, kSecValueData, data)
            CFRelease(data)
            checkStatus(SecItemAdd(query, null))
        }
    }

    override fun delete(key: String) =
        query(key) { query ->
            val status = SecItemDelete(query)
            if (status != errSecItemNotFound) checkStatus(status)
        }

    override fun clear() =
        query(key = null) { query ->
            repeat(MAX_CLEAR_ITERATIONS) {
                val status = SecItemDelete(query)
                if (status == errSecItemNotFound) return@query
                checkStatus(status)
            }
            throw failure(Reason.Failed, "Apple Keychain clear did not finish")
        }

    /** Looks up attributes only, which never requires authentication. */
    private fun exists(key: String): Boolean =
        query(key) { query ->
            CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue)
            CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
            setContext(query, LAContext().apply { interactionNotAllowed = true })
            memScoped {
                val result = alloc<CFTypeRefVar>()
                result.value = null
                val status = SecItemCopyMatching(query, result.ptr)
                result.value?.let { CFRelease(it) }
                when (status) {
                    errSecSuccess, errSecInteractionNotAllowed -> true
                    errSecItemNotFound -> false
                    else -> throw statusFailure(status)
                }
            }
        }

    /** Blocks while the system prompt is visible. */
    private fun copyValue(
        key: String,
        context: LAContext,
    ): String =
        query(key) { query ->
            CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue)
            CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
            setContext(query, context)
            memScoped {
                val result = alloc<CFTypeRefVar>()
                result.value = null
                val status = SecItemCopyMatching(query, result.ptr)
                // The attribute lookup found the item, so a missing item here means its access
                // control no longer matches the enrolled biometrics.
                if (status == errSecItemNotFound) {
                    throw failure(Reason.AuthenticationInvalidated, "biometric enrollment changed")
                }
                checkStatus(status)
                val data: CFDataRef = result.value?.reinterpret() ?: throw failure(Reason.Failed, "Apple Keychain returned no data")
                try {
                    val size = CFDataGetLength(data).toInt()
                    val bytes = if (size == 0) ByteArray(0) else CFDataGetBytePtr(data)?.readBytes(size) ?: ByteArray(0)
                    try {
                        bytes.decodeToString(throwOnInvalidSequence = true)
                    } catch (_: CharacterCodingException) {
                        throw failure(Reason.Corrupted, "Apple Keychain returned invalid UTF-8")
                    } finally {
                        bytes.fill(0)
                    }
                } finally {
                    CFRelease(data)
                }
            }
        }

    /** Runs [block] with a retaining query for one entry, or for the whole namespace when [key] is `null`. */
    private fun <T> query(
        key: String?,
        block: (CFMutableDictionaryRef) -> T,
    ): T {
        val query =
            CFDictionaryCreateMutable(null, 0, kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
                ?: throw failure(Reason.Failed, "cannot allocate Keychain query")
        try {
            CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword)
            query.setString(kSecAttrService, namespace)
            if (key != null) query.setString(kSecAttrAccount, key)
            CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse)
            // macOS only stores access-controlled items in the data-protection keychain.
            CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue)
            return block(query)
        } finally {
            CFRelease(query)
        }
    }

    private fun setContext(
        query: CFMutableDictionaryRef,
        context: LAContext,
    ) {
        val reference = CFBridgingRetain(context)
        CFDictionarySetValue(query, kSecUseAuthenticationContext, reference)
        CFRelease(reference)
    }

    private fun CFMutableDictionaryRef.setString(
        attribute: CFStringRef?,
        value: String,
    ) {
        val string =
            CFStringCreateWithCString(null, value, kCFStringEncodingUTF8)
                ?: throw failure(Reason.Failed, "cannot allocate Keychain string")
        CFDictionarySetValue(this, attribute, string)
        CFRelease(string)
    }
}

/** The `LAError` code that prevents biometric authentication right now, or `null` if it is available. */
private fun biometryErrorCode(): Long? =
    memScoped {
        val error = alloc<ObjCObjectVar<NSError?>>()
        if (LAContext().canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, error.ptr)) {
            null
        } else {
            error.value?.code ?: LAErrorBiometryNotAvailable
        }
    }

/**
 * Maps an `LAError` code from `canEvaluatePolicy` to a failure. An entry that exists while no
 * biometric is enrolled was written under an enrollment that has since been removed.
 */
internal fun biometryFailure(
    code: Long?,
    reading: Boolean,
): KeychainUnavailableException? =
    when (code) {
        null -> {
            null
        }

        LAErrorBiometryLockout -> {
            failure(Reason.Locked, "biometry is locked out")
        }

        LAErrorBiometryNotEnrolled, LAErrorPasscodeNotSet -> {
            if (reading) {
                failure(Reason.AuthenticationInvalidated, "biometric enrollment changed")
            } else {
                failure(Reason.Unsupported, "no biometric is enrolled")
            }
        }

        else -> {
            failure(Reason.Unsupported, "biometric authentication is not available ($code)")
        }
    }

/** Maps a Security framework status to a failure. */
internal fun statusFailure(status: Int): KeychainUnavailableException {
    val reason =
        when (status) {
            errSecUserCanceled -> Reason.Canceled
            errSecAuthFailed, errSecInteractionNotAllowed -> Reason.Locked
            errSecMissingEntitlement, errSecNotAvailable -> Reason.Unsupported
            else -> Reason.Failed
        }
    return failure(reason, "Apple Keychain status $status")
}

private fun checkStatus(status: Int) {
    if (status != errSecSuccess) throw statusFailure(status)
}

private fun failure(
    reason: Reason,
    message: String,
) = KeychainUnavailableException(reason, message)

/** Upper bound on delete-until-empty loops, so a misbehaving backend cannot spin forever. */
private const val MAX_CLEAR_ITERATIONS: Int = 100_000
