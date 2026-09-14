package dev.amoo.credentialkeychain

/**
 * Synchronous secure credential storage. Call from a worker thread: native stores may
 * block or prompt the user. Implementations never persist plaintext as a fallback.
 */
public interface CredentialKeychain {
    /** Returns null only when the key is absent; storage failures throw. */
    public fun read(key: String): String?

    /** Stores [value]. For compatibility, a blank value deletes the entry. */
    public fun write(key: String, value: String): Unit

    /** Deletes an entry. An absent entry is not an error; storage failures throw. */
    public fun delete(key: String): Unit

    /** Platform-specific factories for creating an application-scoped store. */
    public companion object {
        /**
         * Creates a store isolated by both service and account.
         * Android callers must use the Context-taking overload in androidMain.
         * Web has no OS keychain and all operations throw [KeychainUnavailableException].
         */
        public fun forCurrentPlatform(serviceName: String, accountName: String = serviceName): CredentialKeychain {
            validateIdentifier(serviceName)
            validateIdentifier(accountName)
            return ValidatingKeychain(platformKeychain(serviceName, accountName))
        }
    }
}

/** Secure persistence failed or is unavailable. Error messages never include credentials. */
public class KeychainUnavailableException(platform: String) :
    IllegalStateException("Secure credential storage is not available: $platform.")

internal expect fun platformKeychain(serviceName: String, accountName: String): CredentialKeychain

internal class UnsupportedKeychainStore(private val platform: String) : CredentialKeychain {
    override fun read(key: String): String? = throw KeychainUnavailableException(platform)
    override fun write(key: String, value: String): Unit = throw KeychainUnavailableException(platform)
    override fun delete(key: String): Unit = throw KeychainUnavailableException(platform)
}

internal fun validateIdentifier(value: String) {
    require(value.isNotBlank()) { "Credential identifiers must not be blank." }
    require(value.none { it == '\u0000' || it == '\n' || it == '\r' }) {
        "Credential identifiers must not contain NUL or line breaks."
    }
}

internal class ValidatingKeychain(private val delegate: CredentialKeychain) : CredentialKeychain {
    override fun read(key: String): String? { validateIdentifier(key); return delegate.read(key) }
    override fun write(key: String, value: String) {
        validateIdentifier(key)
        require('\u0000' !in value) { "Credential values must not contain NUL." }
        if (value.isBlank()) delegate.delete(key) else delegate.write(key, value)
    }
    override fun delete(key: String) { validateIdentifier(key); delegate.delete(key) }
}

internal fun String.removeTrailingLineBreaks(): String = removeSuffix("\n").removeSuffix("\r")

/** Length-prefixed components avoid ambiguous service/account/key concatenations. */
internal fun credentialNamespace(vararg parts: String): String =
    parts.joinToString("") { "${it.length}:$it" }
