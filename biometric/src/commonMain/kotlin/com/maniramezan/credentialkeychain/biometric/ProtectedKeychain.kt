package com.maniramezan.credentialkeychain.biometric

import com.maniramezan.credentialkeychain.KeychainUnavailableException
import kotlin.coroutines.cancellation.CancellationException

/**
 * Secret storage whose reads require the user to authenticate with a strong biometric
 * (Class 3 on Android; Face ID or Touch ID on Apple platforms). Writing, deleting, and
 * clearing need no authentication.
 *
 * Each entry is protected by a key that is invalidated when biometric enrollment changes, so
 * adding a fingerprint or face makes existing entries unreadable: [read] then throws
 * [KeychainUnavailableException] with
 * [AuthenticationInvalidated][KeychainUnavailableException.Reason.AuthenticationInvalidated],
 * and the caller must [delete] the entry and write it again after the user signs in another way.
 *
 * Supported on Android (API 23+), iOS 15+, and macOS 12+ in apps with keychain entitlements.
 * tvOS, watchOS, and desktop JVM stores throw
 * [Unsupported][KeychainUnavailableException.Reason.Unsupported] from every operation.
 *
 * Obtain an instance with [forCurrentPlatform]. On Android, use the overload that takes a
 * `Context` and an activity provider instead.
 */
public interface ProtectedKeychain {
    /**
     * Shows a biometric prompt and, once the user authenticates, returns the value stored under
     * [key]. Suspends without blocking the calling thread while the prompt is visible.
     *
     * @return the stored value, or `null` if no entry exists for [key]. No prompt is shown for
     *   a missing entry.
     * @throws KeychainUnavailableException with
     *   [Canceled][KeychainUnavailableException.Reason.Canceled] if the user dismissed the prompt,
     *   [AuthenticationInvalidated][KeychainUnavailableException.Reason.AuthenticationInvalidated]
     *   if biometric enrollment changed since the entry was written,
     *   [Unsupported][KeychainUnavailableException.Reason.Unsupported] if no strong biometric is
     *   available or enrolled, or another reason if the read fails.
     * @throws IllegalArgumentException if [key] is blank or contains NUL, CR, or LF.
     * @throws CancellationException if the coroutine is cancelled; the prompt is dismissed.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class, CancellationException::class)
    public suspend fun read(
        key: String,
        prompt: AuthenticationPrompt,
    ): String?

    /**
     * Stores [value] under [key], replacing any existing entry, without authentication.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the write fails;
     *   [Unsupported][KeychainUnavailableException.Reason.Unsupported] if no strong biometric is
     *   enrolled, because the entry could never be read.
     * @throws IllegalArgumentException if [key] is blank or contains NUL/CR/LF, or [value] is
     *   blank or contains NUL.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun write(
        key: String,
        value: String,
    ): Unit

    /**
     * Deletes the entry stored under [key] without authentication. Deleting a missing entry
     * succeeds silently.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     * @throws IllegalArgumentException if [key] is blank or contains NUL, CR, or LF.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun delete(key: String): Unit

    /**
     * Deletes every entry in this store's service/account namespace without authentication.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     */
    @Throws(KeychainUnavailableException::class)
    public fun clear(): Unit

    /** Platform-specific factories for creating an application-scoped store. */
    public companion object {
        /**
         * Creates a store isolated by both [serviceName] and [accountName]. Entries never
         * collide with `CredentialKeychain` entries that use the same names.
         *
         * Android callers must use the overload that takes a `Context`; this overload returns a
         * store that throws [KeychainUnavailableException] on Android.
         *
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String,
        ): ProtectedKeychain {
            validateIdentifier(serviceName, "serviceName")
            validateIdentifier(accountName, "accountName")
            return ValidatingProtectedKeychain(platformProtectedKeychain(serviceName, accountName))
        }
    }
}

/**
 * Text for the system biometric prompt.
 *
 * @property title the prompt's title; must not be blank.
 * @property subtitle optional supporting text, shown under the title on Android and as the
 *   authentication reason on Apple platforms (which falls back to [title]).
 * @property cancelLabel the label of the button that dismisses the prompt on Android; must not
 *   be blank. Apple platforms use the system label.
 */
public class AuthenticationPrompt(
    public val title: String,
    public val subtitle: String? = null,
    public val cancelLabel: String,
) {
    init {
        require(title.isNotBlank()) { "title must not be blank." }
        require(subtitle == null || subtitle.isNotBlank()) { "subtitle must not be blank when set." }
        require(cancelLabel.isNotBlank()) { "cancelLabel must not be blank." }
    }

    /** The text Apple platforms show as the authentication reason. */
    internal val reason: String get() = subtitle ?: title
}

internal expect fun platformProtectedKeychain(
    serviceName: String,
    accountName: String,
): ProtectedKeychain

internal class UnsupportedProtectedKeychain(
    private val platform: String,
) : ProtectedKeychain {
    override suspend fun read(
        key: String,
        prompt: AuthenticationPrompt,
    ): String? = throw unsupported()

    override fun write(
        key: String,
        value: String,
    ): Unit = throw unsupported()

    override fun delete(key: String): Unit = throw unsupported()

    override fun clear(): Unit = throw unsupported()

    private fun unsupported() = KeychainUnavailableException(KeychainUnavailableException.Reason.Unsupported, platform)
}

internal class ValidatingProtectedKeychain(
    internal val delegate: ProtectedKeychain,
) : ProtectedKeychain {
    override suspend fun read(
        key: String,
        prompt: AuthenticationPrompt,
    ): String? {
        validateIdentifier(key, "key")
        return delegate.read(key, prompt)
    }

    override fun write(
        key: String,
        value: String,
    ) {
        validateIdentifier(key, "key")
        validateSecretValue(value, "value")
        delegate.write(key, value)
    }

    override fun delete(key: String) {
        validateIdentifier(key, "key")
        delegate.delete(key)
    }

    override fun clear() {
        delegate.clear()
    }
}

// Copies of core's internal validators, which Kotlin `internal` hides from other modules.
// ValidationParityTest keeps the messages identical.

internal fun validateIdentifier(
    value: String,
    field: String,
) {
    require(value.isNotBlank()) { "$field must not be blank." }
    require(value.none { it == '\u0000' || it == '\n' || it == '\r' }) {
        "$field must not contain NUL or line breaks."
    }
}

internal fun validateSecretValue(
    value: String,
    field: String,
) {
    require(value.isNotBlank()) { "$field must not be blank; use delete() to remove an entry." }
    require('\u0000' !in value) { "$field must not contain NUL." }
}

/** First namespace component, so entries never collide with core stores using the same names. */
internal const val BIOMETRIC_NAMESPACE: String = "credential-keychain-kotlin-biometric"

/** Length-prefixed components avoid ambiguous service/account/key concatenations. */
internal fun credentialNamespace(vararg parts: String): String = parts.joinToString("") { "${it.length}:$it" }
