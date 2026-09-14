package com.maniramezan.credentialkeychain

import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Synchronous secure credential storage, backed by the current platform's native secure
 * storage (Android Keystore, Apple Keychain, macOS Keychain, Linux Secret Service, or
 * Windows DPAPI). Call from a worker thread: native stores may block or prompt the user.
 * Implementations never persist plaintext as a fallback — an unavailable or failing
 * backend throws [KeychainUnavailableException] instead.
 *
 * Obtain an instance with [forCurrentPlatform]. On Android, use the `Context`-taking
 * overload declared in the `com.maniramezan.credentialkeychain` Android package instead.
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
     * Stores [value] under [key], replacing any existing entry. Values are stored exactly,
     * including leading/trailing whitespace. To remove an entry, call [delete].
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the write fails.
     * @throws IllegalArgumentException if [key] is blank, [key] contains NUL/CR/LF, [value]
     *   is blank, or [value] contains NUL.
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

    /**
     * Deletes every entry in this store's service/account namespace, without needing to
     * know the individual keys. Other namespaces are untouched. Clearing an empty
     * namespace succeeds silently as long as the backend itself is available.
     *
     * This is also the recovery path after [KeychainUnavailableException.Reason.Corrupted]
     * — for example, when Android Keystore lost the namespace's encryption key.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     */
    @Throws(KeychainUnavailableException::class)
    public fun clear(): Unit

    /** Platform-specific factories for creating an application-scoped store. */
    public companion object {
        /**
         * Creates a store isolated by both [serviceName] and [accountName] using default
         * [KeychainOptions]. See the three-argument overload for details.
         *
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String = serviceName,
        ): CredentialKeychain = forCurrentPlatform(serviceName, accountName, KeychainOptions())

        /**
         * Creates a store isolated by both [serviceName] and [accountName] — two calls
         * with different values for either parameter address disjoint sets of entries,
         * so one process can keep separate stores per app, environment, or signed-in user.
         *
         * Android callers must use the `Context`-taking overload declared alongside
         * `AndroidKeychain` instead; this overload always returns a store that throws
         * [KeychainUnavailableException] on Android.
         *
         * @param serviceName identifies the calling application or integration; must be
         *   nonblank and free of NUL/CR/LF.
         * @param accountName identifies the credential owner (for example, a signed-in
         *   user id). Same validity rules as [serviceName].
         * @param options platform-specific behavior; options that don't apply to the
         *   current platform are ignored.
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String,
            options: KeychainOptions,
        ): CredentialKeychain {
            validateIdentifier(serviceName)
            validateIdentifier(accountName)
            return ValidatingKeychain(platformKeychain(serviceName, accountName, options))
        }
    }
}

/**
 * Platform-specific store configuration. Each option only affects the platforms named in
 * its documentation and is ignored elsewhere.
 *
 * @property appleAccessibility when native iOS, tvOS, and watchOS entries can be read.
 *   Ignored by macOS, which stores entries in the file-based login keychain.
 * @property desktopCommandTimeout the maximum time a desktop JVM backend waits for its
 *   OS tool (`security`, `secret-tool`, or PowerShell), including time spent on an access
 *   prompt. Must be positive.
 */
public class KeychainOptions(
    public val appleAccessibility: AppleAccessibility = AppleAccessibility.WhenUnlocked,
    public val desktopCommandTimeout: Duration = DEFAULT_DESKTOP_COMMAND_TIMEOUT,
) {
    init {
        require(desktopCommandTimeout.isPositive() && desktopCommandTimeout.isFinite()) {
            "desktopCommandTimeout must be positive and finite."
        }
    }

    private companion object {
        val DEFAULT_DESKTOP_COMMAND_TIMEOUT: Duration = 30.seconds
    }
}

/**
 * When a native Apple Keychain entry can be read. Every option is device-only: entries are
 * never synchronized to iCloud Keychain or restored onto another device.
 */
public enum class AppleAccessibility {
    /** Readable only while the device is unlocked (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). */
    WhenUnlocked,

    /**
     * Readable after the first unlock following a restart, including while the device is
     * later locked — use for background refresh (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
     */
    AfterFirstUnlock,
}

/**
 * Secure persistence failed or is unavailable for the current platform, session, or
 * environment (for example: a headless Linux session with no Secret
 * Service, or an Android call made without a `Context`). Error messages never include
 * credentials.
 *
 * This is distinct from a `null` read result: `null` means the key is genuinely absent,
 * while this exception means the backend could not complete the operation.
 *
 * The constructor is public so that test fakes of [CredentialKeychain] can simulate
 * backend failures.
 *
 * @property reason the failure category; use it to decide whether to retry, prompt the
 *   user, or [clear][CredentialKeychain.clear] the store.
 */
public class KeychainUnavailableException(
    public val reason: Reason,
    message: String,
    cause: Throwable? = null,
) : IllegalStateException("Secure credential storage is not available ($reason): $message.", cause) {
    /** Failure categories for [KeychainUnavailableException]. */
    public enum class Reason {
        /** This platform, OS, or environment has no usable secure-storage backend. */
        Unsupported,

        /**
         * The store is locked or access was denied (for example, a locked device or a
         * dismissed access prompt). Retrying later may succeed.
         */
        Locked,

        /**
         * Stored data exists but cannot be decrypted or decoded, for example after
         * tampering or a lost Android Keystore key. Delete the entry or [clear][CredentialKeychain.clear]
         * the store to recover.
         */
        Corrupted,

        /** Any other operational failure, such as an I/O error or a timeout. */
        Failed,
    }
}

internal expect fun platformKeychain(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CredentialKeychain

internal class UnsupportedKeychainStore(
    private val platform: String,
) : CredentialKeychain {
    override fun read(key: String): String? = throw unsupported()

    override fun write(
        key: String,
        value: String,
    ): Unit = throw unsupported()

    override fun delete(key: String): Unit = throw unsupported()

    override fun clear(): Unit = throw unsupported()

    private fun unsupported() = KeychainUnavailableException(KeychainUnavailableException.Reason.Unsupported, platform)
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
        require(value.isNotBlank()) { "Credential values must not be blank; use delete() to remove an entry." }
        require('\u0000' !in value) { "Credential values must not contain NUL." }
        delegate.write(key, value)
    }

    override fun delete(key: String) {
        validateIdentifier(key)
        delegate.delete(key)
    }

    override fun clear() {
        delegate.clear()
    }
}

internal fun String.removeTrailingLineBreaks(): String = removeSuffix("\n").removeSuffix("\r")

/** Length-prefixed components avoid ambiguous service/account/key concatenations. */
internal fun credentialNamespace(vararg parts: String): String = parts.joinToString("") { "${it.length}:$it" }

/** Upper bound on delete-until-empty loops, so a misbehaving backend cannot spin forever. */
internal const val MAX_CLEAR_ITERATIONS: Int = 100_000
