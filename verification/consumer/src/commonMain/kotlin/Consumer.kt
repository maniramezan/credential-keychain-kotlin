package consumer

import com.maniramezan.credentialkeychain.AppleAccessibility
import com.maniramezan.credentialkeychain.CertificateInfo
import com.maniramezan.credentialkeychain.CertificateStore
import com.maniramezan.credentialkeychain.CredentialKeychain
import com.maniramezan.credentialkeychain.HardwareKeySpec
import com.maniramezan.credentialkeychain.HardwareKeyStore
import com.maniramezan.credentialkeychain.KeychainOptions
import com.maniramezan.credentialkeychain.KeychainUnavailableException
import com.maniramezan.credentialkeychain.PasswordCredential
import com.maniramezan.credentialkeychain.PasswordStore
import com.maniramezan.credentialkeychain.SecurityLevel
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

class AccountRepository(private val passwords: PasswordStore) {
    fun remember(server: String, username: String, password: String) =
        passwords.save(PasswordCredential(server, username, password))
    fun accounts(server: String): List<String> = passwords.findAll(server).map { it.username }
    fun password(server: String, username: String): String? = passwords.find(server, username)?.password
    fun forget(server: String, username: String) = passwords.delete(server, username)
    fun signOut() = passwords.clear()
}

fun createAccountRepository(): AccountRepository =
    AccountRepository(PasswordStore.forCurrentPlatform("consumer", "account", KeychainOptions()))

class DeviceBinding(private val keys: HardwareKeyStore) {
    fun enroll(): ByteArray = keys.generate("device-binding", HardwareKeySpec(allowSoftwareKeys = false)).publicKeyDer
    fun level(): SecurityLevel? = keys.info("device-binding")?.securityLevel
    fun answer(challenge: ByteArray): ByteArray? = keys.sign("device-binding", challenge)
    fun reset() = keys.clear()
}

fun createDeviceBinding(): DeviceBinding = DeviceBinding(HardwareKeyStore.forCurrentPlatform("consumer", "account"))

class ClientIdentity(private val certificates: CertificateStore) {
    fun install(pkcs12: ByteArray, passphrase: CharArray): CertificateInfo = certificates.importPkcs12("client", pkcs12, passphrase)
    fun pin(certificateDer: ByteArray): CertificateInfo = certificates.importCertificate("pinned", certificateDer)
    fun leaf(): ByteArray? = certificates.info("client")?.certificateChainDer?.firstOrNull()
    fun installed(): List<String> = certificates.aliases()
    fun remove() = certificates.clear()
}

fun createClientIdentity(): ClientIdentity = ClientIdentity(CertificateStore.forCurrentPlatform("consumer", "account"))

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
