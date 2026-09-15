package com.maniramezan.credentialkeychain

import androidx.test.platform.app.InstrumentationRegistry
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.security.KeyStore
import java.util.UUID
import kotlin.test.*

class AndroidPasswordStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val server = "api.example.com"

    @Test fun roundTripFindAllAndIsolation() =
        withService { service ->
            val first = PasswordStore.forCurrentPlatform(context, service, "first")
            val second = PasswordStore.forCurrentPlatform(context, service, "second")
            val secrets = CredentialKeychain.forCurrentPlatform(context, service, "first")
            try {
                assertNull(first.find(server, "alice"))
                assertEquals(emptyList(), first.findAll(server))
                first.save(PasswordCredential(server, "bob", "  spaced  "))
                first.save(PasswordCredential(server, "alice", "secret ' \" \\ 秘密"))
                first.save(PasswordCredential("other.example.com", "carol", "other server"))
                second.save(PasswordCredential(server, "alice", "second account"))
                secrets.write("alice", "generic secret")
                assertEquals(
                    listOf("alice", "bob"),
                    PasswordStore.forCurrentPlatform(context, service, "first").findAll(server).map { it.username },
                )
                assertEquals("secret ' \" \\ 秘密", first.find(server, "alice")?.password)
                first.save(PasswordCredential(server, "alice", "updated"))
                assertEquals("updated", first.find(server, "alice")?.password)
                first.delete(server, "bob")
                assertNull(first.find(server, "bob"))
                first.delete(server, "missing")
                first.clear()
                assertFalse(File(context.noBackupFilesDir, alias(service, "first")).exists())
                assertEquals(emptyList(), first.findAll(server))
                assertNull(first.find("other.example.com", "carol"))
                assertEquals("second account", second.find(server, "alice")?.password)
                assertEquals("generic secret", secrets.read("alice"))
            } finally {
                second.clear()
                secrets.clear()
            }
        }

    @Test fun ciphertextCannotBeMovedBetweenUsernamesOrServers() =
        withService { service ->
            val store = PasswordStore.forCurrentPlatform(context, service, "first")
            store.save(PasswordCredential(server, "alice", "alice secret"))
            store.save(PasswordCredential(server, "bob", "bob secret"))
            store.save(PasswordCredential("other.example.com", "alice", "other secret"))
            file(service, server, "alice").writeBytes(file(service, server, "bob").readBytes())
            assertEquals(Reason.Corrupted, assertFailsWith<KeychainUnavailableException> { store.find(server, "alice") }.reason)
            file(service, "other.example.com", "alice").writeBytes(file(service, server, "bob").readBytes())
            assertEquals(
                Reason.Corrupted,
                assertFailsWith<KeychainUnavailableException> { store.find("other.example.com", "alice") }.reason,
            )
            assertEquals("bob secret", store.find(server, "bob")?.password)
            assertEquals(Reason.Corrupted, assertFailsWith<KeychainUnavailableException> { store.findAll(server) }.reason)
        }

    @Test fun lostKeyBlocksWritesUntilTheStoreIsCleared() =
        withService { service ->
            val store = PasswordStore.forCurrentPlatform(context, service, "first")
            store.save(PasswordCredential(server, "alice", "secret"))
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias(service, "first"))
            assertEquals(Reason.Corrupted, assertFailsWith<KeychainUnavailableException> { store.find(server, "alice") }.reason)
            assertEquals(
                Reason.Corrupted,
                assertFailsWith<KeychainUnavailableException> { store.save(PasswordCredential("x", "y", "z")) }.reason,
            )
            store.clear()
            store.save(PasswordCredential(server, "alice", "after clear"))
            assertEquals("after clear", store.find(server, "alice")?.password)
        }

    private fun alias(
        service: String,
        account: String,
    ) = "com.maniramezan.credentialkeychain.password.${sha256Hex(credentialNamespace(service, account))}"

    private fun file(
        service: String,
        server: String,
        username: String,
    ) = File(File(File(context.noBackupFilesDir, alias(service, "first")), sha256Hex(server)), "${sha256Hex(username)}.bin")

    private fun withService(block: (String) -> Unit) {
        val service = "keychain-test-${UUID.randomUUID()}"
        try {
            block(service)
        } finally {
            PasswordStore.forCurrentPlatform(context, service, "first").clear()
        }
    }
}
