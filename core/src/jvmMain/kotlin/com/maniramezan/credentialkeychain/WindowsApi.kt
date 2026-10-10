package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason

/** A current-user generic Credential Manager entry. */
internal class WindowsCredential(
    val target: String,
    val userName: String,
    val secret: ByteArray,
)

/**
 * The Win32 operations behind the Windows backends. [JnaWindowsApi] calls them in-process; tests
 * substitute fakes. Every failure throws, and callers replace it with a sanitized error.
 */
internal interface WindowsApi {
    /** Encrypts with current-user DPAPI (`CryptProtectData`), without entropy or UI. */
    fun protect(plaintext: ByteArray): ByteArray

    /** Decrypts current-user DPAPI ciphertext (`CryptUnprotectData`), without entropy or UI. */
    fun unprotect(ciphertext: ByteArray): ByteArray

    /** Creates or replaces the generic credential [target] (`CredWriteW`). */
    fun writeCredential(
        target: String,
        userName: String,
        secret: ByteArray,
    )

    /** Returns the generic credential [target], or `null` if none exists (`CredReadW`). */
    fun readCredential(target: String): WindowsCredential?

    /** Returns the generic credentials matching [filter], which may end in `*` (`CredEnumerateW`). */
    fun enumerateCredentials(filter: String): List<WindowsCredential>

    /** Deletes the generic credential [target]; a missing credential is not an error (`CredDeleteW`). */
    fun deleteCredential(target: String)

    /**
     * Imports the PKCS#12 identity into the current-user `My` store with a persisted,
     * non-exportable private key, named [friendlyName]. Existing certificates with that name are
     * removed with their keys first.
     */
    fun importIdentity(
        friendlyName: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    )

    /** Removes every current-user `My` certificate named [friendlyName], together with its key. */
    fun deleteIdentities(friendlyName: String)
}

private val jnaWindowsApi: WindowsApi by lazy { JnaWindowsApi() }

/** The in-process Win32 implementation, loaded on first use. */
internal fun systemWindowsApi(): WindowsApi = jnaWindowsApi

/**
 * Runs [block] against the [api]. A native layer that cannot be loaded is [Reason.Unsupported];
 * any other failure becomes [failureMessage] with no detail attached, because native errors can
 * describe stored data. [KeychainUnavailableException]s thrown by [block] pass through.
 */
internal inline fun <T> windowsCall(
    api: () -> WindowsApi,
    failureMessage: String,
    block: (WindowsApi) -> T,
): T =
    try {
        block(api())
    } catch (error: KeychainUnavailableException) {
        throw error
    } catch (_: LinkageError) {
        throw KeychainUnavailableException(Reason.Unsupported, "Windows native APIs are not available")
    } catch (_: Exception) {
        throw commandFailure(failureMessage)
    }
