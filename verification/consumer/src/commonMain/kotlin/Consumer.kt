package consumer

import com.maniramezan.credentialkeychain.AppleAccessibility
import com.maniramezan.credentialkeychain.CredentialKeychain
import com.maniramezan.credentialkeychain.KeychainOptions
import com.maniramezan.credentialkeychain.KeychainUnavailableException
import kotlin.time.Duration.Companion.seconds

// Compile-only example. No real credentials are created by this publication check.
class CredentialRepository(private val keychain: CredentialKeychain) {
    fun token(): String? = keychain.read("api-token")
    fun store(token: String) = keychain.write("api-token", token)
    fun remove() = keychain.delete("api-token")
    fun signOut() = keychain.clear()
}

fun createRepository(): CredentialRepository =
    CredentialRepository(CredentialKeychain.forCurrentPlatform("consumer", "account"))

fun createBackgroundRepository(): CredentialRepository =
    CredentialRepository(
        CredentialKeychain.forCurrentPlatform(
            "consumer",
            "account",
            KeychainOptions(appleAccessibility = AppleAccessibility.AfterFirstUnlock, desktopCommandTimeout = 60.seconds),
        ),
    )

fun shouldRetryLater(error: KeychainUnavailableException): Boolean =
    error.reason == KeychainUnavailableException.Reason.Locked

// A deterministic failure fixture verifies Swift error bridging without OS storage access.
fun unavailableForSwift(): CredentialKeychain = object : CredentialKeychain {
    private fun failure() = KeychainUnavailableException(KeychainUnavailableException.Reason.Failed, "Swift verification")
    override fun read(key: String): String? = throw failure()
    override fun write(key: String, value: String): Unit = throw failure()
    override fun delete(key: String): Unit = throw failure()
    override fun clear(): Unit = throw failure()
}
