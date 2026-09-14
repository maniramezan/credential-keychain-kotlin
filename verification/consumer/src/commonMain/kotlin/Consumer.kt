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
