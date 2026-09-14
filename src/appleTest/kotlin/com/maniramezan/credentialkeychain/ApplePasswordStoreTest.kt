package com.maniramezan.credentialkeychain

import platform.Foundation.NSUUID
import kotlin.test.*

/** Uses a unique service and clears every test namespace, including on assertion failure. */
class ApplePasswordStoreTest {
    private val server = "api.example.com"

    @Test fun nativeRoundTripFindAllAndUpdate() {
        val service = uniqueService()
        val store = PasswordStore.forCurrentPlatform(service, "first")
        try {
            assertNull(store.find(server, "alice"))
            assertEquals(emptyList(), store.findAll(server))
            store.save(PasswordCredential(server, "bob", "  spaced  "))
            store.save(PasswordCredential(server, "alice", "secret ' \" \\ 秘密"))
            store.save(PasswordCredential(server, "秘密", "unicode user"))
            store.save(PasswordCredential("other.example.com", "carol", "other server"))
            assertEquals(PasswordCredential(server, "alice", "secret ' \" \\ 秘密"), store.find(server, "alice"))
            assertEquals(
                listOf("alice", "bob", "秘密"),
                PasswordStore.forCurrentPlatform(service, "first").findAll(server).map { it.username },
            )
            store.save(PasswordCredential(server, "alice", "updated"))
            assertEquals("updated", store.find(server, "alice")?.password)
            store.delete(server, "bob")
            assertNull(store.find(server, "bob"))
            store.delete(server, "missing")
        } finally {
            store.clear()
        }
    }

    @Test fun passwordsAndGenericSecretsAreIsolatedAndClearedIndependently() {
        val service = uniqueService()
        val first = PasswordStore.forCurrentPlatform(service, "first")
        val second = PasswordStore.forCurrentPlatform(service, "second", KeychainOptions(AppleAccessibility.AfterFirstUnlock))
        val secrets = CredentialKeychain.forCurrentPlatform(service, "first")
        try {
            first.save(PasswordCredential(server, "alice", "first account"))
            first.save(PasswordCredential("other.example.com", "carol", "other server"))
            second.save(PasswordCredential(server, "alice", "second account"))
            secrets.write("alice", "generic secret")
            first.clear()
            assertEquals(emptyList(), first.findAll(server))
            assertNull(first.find("other.example.com", "carol"))
            assertEquals("second account", second.find(server, "alice")?.password)
            assertEquals("generic secret", secrets.read("alice"))
            secrets.clear()
            assertEquals("second account", second.find(server, "alice")?.password)
            first.clear()
        } finally {
            first.clear()
            second.clear()
            secrets.clear()
        }
    }

    private fun uniqueService() = "credential-keychain-test-${NSUUID().UUIDString}"
}
