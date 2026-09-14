package com.maniramezan.credentialkeychain

/**
 * Username/password credentials for servers, backed by the current platform's native password
 * storage: Keystore-encrypted files on Android, internet-password items in the Apple Keychain
 * and the macOS login keychain, Secret Service on Linux, or Credential Manager on Windows.
 *
 * Like [CredentialKeychain], operations are synchronous and may block or prompt the user, so
 * call them from a worker thread. Nothing is ever persisted as plaintext; an unavailable or
 * failing backend throws [KeychainUnavailableException].
 *
 * Entries are isolated by the store's service/account namespace and addressed by server and
 * username. A [PasswordStore] and a [CredentialKeychain] created with the same names are
 * independent: neither sees nor clears the other's entries.
 *
 * Every platform accepts the same credentials. Servers and usernames must be nonblank and free
 * of NUL, CR, and LF, and usernames are at most 512 characters. Passwords must be nonblank,
 * free of NUL, CR, and LF, and at most 2,560 UTF-8 bytes.
 *
 * ```kotlin
 * val passwords = PasswordStore.forCurrentPlatform(serviceName = "my-app", accountName = "user-123")
 * passwords.save(PasswordCredential(server = "api.example.com", username = "alice", password = "s3cret"))
 * val alice: PasswordCredential? = passwords.find(server = "api.example.com", username = "alice")
 * val everyone: List<PasswordCredential> = passwords.findAll(server = "api.example.com")
 * ```
 */
public interface PasswordStore {
    /**
     * Saves [credential], replacing any password already saved for its server and username.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the save fails.
     * @throws IllegalArgumentException if the server, username, or password breaks the rules
     *   described on [PasswordStore].
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun save(credential: PasswordCredential): Unit

    /**
     * Finds the credential saved for [server] and [username].
     *
     * @return the credential, or `null` if none is saved.
     * @throws KeychainUnavailableException if the backend is unavailable or the lookup fails.
     * @throws IllegalArgumentException if [server] or [username] is invalid.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun find(
        server: String,
        username: String,
    ): PasswordCredential?

    /**
     * Returns every credential saved for [server] in this store, sorted by username.
     *
     * @return the credentials, or an empty list if none are saved.
     * @throws KeychainUnavailableException if the backend is unavailable or the lookup fails.
     * @throws IllegalArgumentException if [server] is invalid.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun findAll(server: String): List<PasswordCredential>

    /**
     * Deletes the credential saved for [server] and [username]. Deleting a credential that is
     * not saved succeeds silently as long as the backend itself is available.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     * @throws IllegalArgumentException if [server] or [username] is invalid.
     */
    @Throws(KeychainUnavailableException::class, IllegalArgumentException::class)
    public fun delete(
        server: String,
        username: String,
    ): Unit

    /**
     * Deletes every credential in this store's service/account namespace, for every server.
     * Other namespaces and [CredentialKeychain] entries are untouched.
     *
     * @throws KeychainUnavailableException if the backend is unavailable or the delete fails.
     */
    @Throws(KeychainUnavailableException::class)
    public fun clear(): Unit

    /** Platform-specific factories for creating an application-scoped password store. */
    public companion object {
        /**
         * Creates a password store isolated by [serviceName] and [accountName] using default
         * [KeychainOptions]. See the three-argument overload for details.
         *
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String = serviceName,
        ): PasswordStore = forCurrentPlatform(serviceName, accountName, KeychainOptions())

        /**
         * Creates a password store isolated by both [serviceName] and [accountName].
         *
         * Android callers must use the `Context`-taking overload instead; this overload always
         * returns a store that throws [KeychainUnavailableException] on Android.
         *
         * @param serviceName identifies the calling application or integration; must be
         *   nonblank and free of NUL/CR/LF.
         * @param accountName identifies the credential owner. Same validity rules as
         *   [serviceName].
         * @param options platform-specific behavior; options that don't apply to the current
         *   platform are ignored.
         * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or
         *   contains NUL, CR, or LF.
         */
        @Throws(IllegalArgumentException::class)
        public fun forCurrentPlatform(
            serviceName: String,
            accountName: String,
            options: KeychainOptions,
        ): PasswordStore {
            validateIdentifier(serviceName, "serviceName")
            validateIdentifier(accountName, "accountName")
            return ValidatingPasswordStore(platformPasswordStore(serviceName, accountName, options))
        }
    }
}

/**
 * A username and password for a server. [toString] never includes the password.
 *
 * @property server the host or logical service the credential signs in to, for example
 *   `api.example.com`.
 * @property username the account name on [server].
 * @property password the secret for [username].
 */
public class PasswordCredential(
    public val server: String,
    public val username: String,
    public val password: String,
) {
    /** Credentials are equal when their server, username, and password are all equal. */
    override fun equals(other: Any?): Boolean =
        other is PasswordCredential && server == other.server && username == other.username && password == other.password

    /** Combines [server], [username], and [password]. */
    override fun hashCode(): Int = (server.hashCode() * 31 + username.hashCode()) * 31 + password.hashCode()

    /** Describes the server and username; the password is always redacted. */
    override fun toString(): String = "PasswordCredential(server=$server, username=$username, password=<redacted>)"
}

internal expect fun platformPasswordStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): PasswordStore

internal const val MAX_USERNAME_LENGTH: Int = 512

/** Windows Credential Manager's blob limit, applied everywhere so credentials stay portable. */
internal const val MAX_PASSWORD_BYTES: Int = 2560

internal fun validateServer(server: String) = validateIdentifier(server, "server")

internal fun validateUsername(username: String) {
    validateIdentifier(username, "username")
    require(username.length <= MAX_USERNAME_LENGTH) { "username must be at most $MAX_USERNAME_LENGTH characters." }
}

internal fun validatePassword(password: String) {
    validateSecretValue(password, "password")
    require(password.none { it == '\n' || it == '\r' }) { "password must not contain line breaks." }
    require(password.encodeToByteArray().size <= MAX_PASSWORD_BYTES) {
        "password must be at most $MAX_PASSWORD_BYTES UTF-8 bytes."
    }
}

internal class ValidatingPasswordStore(
    private val delegate: PasswordStore,
) : PasswordStore {
    override fun save(credential: PasswordCredential) {
        validateServer(credential.server)
        validateUsername(credential.username)
        validatePassword(credential.password)
        delegate.save(credential)
    }

    override fun find(
        server: String,
        username: String,
    ): PasswordCredential? {
        validateServer(server)
        validateUsername(username)
        return delegate.find(server, username)
    }

    override fun findAll(server: String): List<PasswordCredential> {
        validateServer(server)
        return delegate.findAll(server).sortedBy { it.username }
    }

    override fun delete(
        server: String,
        username: String,
    ) {
        validateServer(server)
        validateUsername(username)
        delegate.delete(server, username)
    }

    override fun clear() {
        delegate.clear()
    }
}

internal class UnsupportedPasswordStore(
    private val platform: String,
) : PasswordStore {
    override fun save(credential: PasswordCredential): Unit = throw unsupported()

    override fun find(
        server: String,
        username: String,
    ): PasswordCredential? = throw unsupported()

    override fun findAll(server: String): List<PasswordCredential> = throw unsupported()

    override fun delete(
        server: String,
        username: String,
    ): Unit = throw unsupported()

    override fun clear(): Unit = throw unsupported()

    private fun unsupported() = KeychainUnavailableException(KeychainUnavailableException.Reason.Unsupported, platform)
}

/** Reverses [credentialNamespace]; returns `null` when [value] is not a well-formed encoding. */
internal fun parseCredentialNamespace(value: String): List<String>? {
    val parts = mutableListOf<String>()
    var index = 0
    while (index < value.length) {
        val colon = value.indexOf(':', index)
        if (colon <= index || value.substring(index, colon).any { it !in '0'..'9' }) return null
        val length = value.substring(index, colon).toIntOrNull() ?: return null
        val start = colon + 1
        if (length > value.length - start) return null
        parts += value.substring(start, start + length)
        index = start + length
    }
    return parts
}
