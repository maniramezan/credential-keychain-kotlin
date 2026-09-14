package consumer

import dev.amoo.credentialkeychain.CredentialKeychain
import dev.amoo.credentialkeychain.KeychainUnavailableException

// Compile-only example. No real credentials are created by this publication check.
class CredentialRepository(private val keychain: CredentialKeychain) {
    fun token(): String? = keychain.read("api-token")
    fun store(token: String) = keychain.write("api-token", token)
    fun clear() = keychain.delete("api-token")
}

fun createRepository(): CredentialRepository =
    CredentialRepository(CredentialKeychain.forCurrentPlatform("consumer", "account"))

fun unavailableMessage(error: KeychainUnavailableException): String? = error.message

// A deterministic failure fixture verifies Swift error bridging without OS storage access.
fun unavailableForSwift(): CredentialKeychain = object : CredentialKeychain {
    override fun read(key: String): String? = throw KeychainUnavailableException("Swift verification")
    override fun write(key: String, value: String): Unit = throw KeychainUnavailableException("Swift verification")
    override fun delete(key: String): Unit = throw KeychainUnavailableException("Swift verification")
}
