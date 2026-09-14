package dev.amoo.credentialkeychain

/**
 * Synchronous secure credential storage, backed by the current platform's native secure
 * storage (Android Keystore, Apple Keychain, macOS Keychain, Linux Secret Service, or
 * Windows DPAPI). Call from a worker thread: native stores may block or prompt the user.
 * Implementations never persist plaintext as a fallback — an unavailable or failing
 * backend throws [KeychainUnavailableException] instead.
 *
 * Obtain an instance with [forCurrentPlatform]. On Android, use the `Context`-taking
 * overload declared in the `dev.amoo.credentialkeychain` Android package instead.
 *
 * ```kotlin
 * val keychain = CredentialKeychain.forCurrentPlatform(serviceName = "my-app", accountName = "user-123")
 * keychain.write("api-key", "secret-token")
 * val token: String? = keychain.read("api-key")
 * keychain.delete("api-key")
 * ```
 */
public interface CredentialKeychain {
    /**
     * Reads the value stored under [key].
     *
     * @return the stored value, or `null` if no entry exists for [key].
     * @throws KeychainUnavailableException if the backend is unavailable or the read fails.
     * @throws IllegalArgumentException if [key] is blank or contains NUL, CR, or LF.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun read(key: String): String?

    /**
     * Stores [value] under [key], replacing any existing entry. For compatibility with
     * clearing a field by writing an empty string, a blank [value] deletes the entry
     * instead of storing it; non-blank values preserve leading/trailing whitespace.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the write fails.
     * @throws IllegalArgumentException if [key] is blank, [key] contains NUL/CR/LF, or
     *   [value] contains NUL.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun write(
        key: String,
        value: String,
    ): Unit

    /**
     * Deletes the entry stored under [key]. Deleting a [key] that has no entry succeeds
     * silently as long as the backend itself is available.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     * @throws IllegalArgumentException if [key] is blank or contains NUL, CR, or LF.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun delete(key: String): Unit

    /** Platform-specific factories for creating an application-scoped store. */
    public companion object {
        /**
         * Creates a store isolated by both [serviceName] and [accountName] — two calls
         * with different values for either parameter address disjoint sets of entries,
         * so one process can keep separate stores per app, environment, or signed-in user.
         *
         * Android callers must use the `Context`-taking overload declared alongside
         * `AndroidKeychain` instead; this overload always returns a store that throws
         * [KeychainUnavailableException] on Android. Web targets (`js`, `wasmJs`) have no
         * OS keychain, so every operation on the returned store also throws
         * [KeychainUnavailableException].
         *
         * @param serviceName identifies the calling application or integration; must be
         *   nonblank and free of NUL/CR/LF.
         * @param accountName identifies the credential owner (for example, a signed-in
         *   user id); defaults to [serviceName]. Same validity rules as [serviceName].
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String = serviceName,
        ): CredentialKeychain {
            validateIdentifier(serviceName)
            validateIdentifier(accountName)
            return ValidatingKeychain(platformKeychain(serviceName, accountName))
        }
    }
}

/**
 * Secure persistence failed or is unavailable for the current platform, session, or
 * environment (for example: a web target, a headless Linux session with no Secret
 * Service, or an Android call made without a `Context`). Error messages never include
 * credentials — only the platform/reason string passed to the constructor.
 *
 * This is distinct from a `null` read result: `null` means the key is genuinely absent,
 * while this exception means the backend itself could not be reached.
 */
public class KeychainUnavailableException(
    platform: String,
) : IllegalStateException("Secure credential storage is not available: $platform.")

internal expect fun platformKeychain(
    serviceName: String,
    accountName: String,
): CredentialKeychain

internal class UnsupportedKeychainStore(
    private val platform: String,
) : CredentialKeychain {
    override fun read(key: String): String? = throw KeychainUnavailableException(platform)

    override fun write(
        key: String,
        value: String,
    ): Unit = throw KeychainUnavailableException(platform)

    override fun delete(key: String): Unit = throw KeychainUnavailableException(platform)
}

internal fun validateIdentifier(value: String) {
    require(value.isNotBlank()) { "Credential identifiers must not be blank." }
    require(value.none { it == '\u0000' || it == '\n' || it == '\r' }) {
        "Credential identifiers must not contain NUL or line breaks."
    }
}

internal class ValidatingKeychain(
    private val delegate: CredentialKeychain,
) : CredentialKeychain {
    override fun read(key: String): String? {
        validateIdentifier(key)
        return delegate.read(key)
    }

    override fun write(
        key: String,
        value: String,
    ) {
        validateIdentifier(key)
        require('\u0000' !in value) { "Credential values must not contain NUL." }
        if (value.isBlank()) delegate.delete(key) else delegate.write(key, value)
    }

    override fun delete(key: String) {
        validateIdentifier(key)
        delegate.delete(key)
    }
}

internal fun String.removeTrailingLineBreaks(): String = removeSuffix("\n").removeSuffix("\r")

/** Length-prefixed components avoid ambiguous service/account/key concatenations. */
internal fun credentialNamespace(vararg parts: String): String = parts.joinToString("") { "${it.length}:$it" }
