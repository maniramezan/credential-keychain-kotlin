package com.maniramezan.credentialkeychain

import kotlin.test.*

class PasswordStoreTest {
    @Test fun factoriesValidateTheNamespace() {
        assertNotNull(PasswordStore.forCurrentPlatform("password-test"))
        assertNotNull(PasswordStore.forCurrentPlatform("password-test", "account", KeychainOptions()))
        assertInvalid("serviceName must not be blank.") { PasswordStore.forCurrentPlatform(" ") }
        assertInvalid(
            "accountName must not contain NUL or line breaks.",
        ) { PasswordStore.forCurrentPlatform("service", "a\nb", KeychainOptions()) }
    }

    @Test fun invalidArgumentsNeverReachTheBackend() {
        val backend = RecordingPasswordStore()
        val store = ValidatingPasswordStore(backend)
        assertInvalid("server must not be blank.") { store.find(" ", "alice") }
        assertInvalid("server must not contain NUL or line breaks.") { store.findAll("a\u0000b") }
        assertInvalid("username must not contain NUL or line breaks.") { store.find("api", "a\nb") }
        assertInvalid("username must be at most 512 characters.") { store.delete("api", "a".repeat(513)) }
        assertInvalid(
            "password must not be blank; use delete() to remove an entry.",
        ) { store.save(PasswordCredential("api", "alice", " ")) }
        assertInvalid("password must not contain NUL.") { store.save(PasswordCredential("api", "alice", "a\u0000b")) }
        assertInvalid("password must not contain line breaks.") { store.save(PasswordCredential("api", "alice", "a\rb")) }
        assertInvalid("password must be at most 2560 UTF-8 bytes.") { store.save(PasswordCredential("api", "alice", "秘".repeat(854))) }
        assertEquals(emptyList(), backend.calls)
    }

    @Test fun validCallsReachTheBackendAndFindAllIsSortedByUsername() {
        val backend = RecordingPasswordStore()
        val store = ValidatingPasswordStore(backend)
        store.save(PasswordCredential("api", "bob", "  spaced  "))
        store.save(PasswordCredential("api", "a".repeat(512), "a".repeat(2560)))
        store.save(PasswordCredential("api", "alice", "secret"))
        assertEquals(listOf("a".repeat(512), "alice", "bob"), store.findAll("api").map { it.username })
        assertEquals("  spaced  ", store.find("api", "bob")?.password)
        store.delete("api", "bob")
        store.clear()
        assertEquals(
            listOf("save:bob", "save:${"a".repeat(512)}", "save:alice", "findAll:api", "find:bob", "delete:bob", "clear"),
            backend.calls,
        )
    }

    @Test fun credentialsCompareByValueAndNeverPrintThePassword() {
        val credential = PasswordCredential("api.example.com", "alice", "top-secret")
        assertEquals(PasswordCredential("api.example.com", "alice", "top-secret"), credential)
        assertEquals(PasswordCredential("api.example.com", "alice", "top-secret").hashCode(), credential.hashCode())
        assertNotEquals(PasswordCredential("api.example.com", "alice", "other"), credential)
        assertNotEquals(PasswordCredential("api.example.com", "bob", "top-secret"), credential)
        assertNotEquals(PasswordCredential("other.example.com", "alice", "top-secret"), credential)
        assertEquals("PasswordCredential(server=api.example.com, username=alice, password=<redacted>)", credential.toString())
    }

    @Test fun unsupportedStoreFailsEveryOperation() {
        val store = UnsupportedPasswordStore("BeOS")
        val failures =
            listOf(
                assertFailsWith<KeychainUnavailableException> { store.save(PasswordCredential("api", "alice", "secret")) },
                assertFailsWith<KeychainUnavailableException> { store.find("api", "alice") },
                assertFailsWith<KeychainUnavailableException> { store.findAll("api") },
                assertFailsWith<KeychainUnavailableException> { store.delete("api", "alice") },
                assertFailsWith<KeychainUnavailableException> { store.clear() },
            )
        failures.forEach { assertEquals(KeychainUnavailableException.Reason.Unsupported, it.reason) }
    }

    @Test fun credentialNamespaceRoundTripsAndRejectsMalformedInput() {
        for (parts in listOf(emptyList(), listOf(""), listOf("a", "bc"), listOf("12:3", "秘密", ":"))) {
            assertEquals(parts, parseCredentialNamespace(credentialNamespace(*parts.toTypedArray())))
        }
        for (malformed in listOf("1", "x:a", "2:a", ":a", "-1:a", "+1:a", "1a:b", "1:ab")) {
            assertNull(parseCredentialNamespace(malformed), malformed)
        }
    }

    private fun assertInvalid(
        message: String,
        block: () -> Unit,
    ) {
        assertEquals(message, assertFailsWith<IllegalArgumentException> { block() }.message)
    }

    private class RecordingPasswordStore : PasswordStore {
        val calls = mutableListOf<String>()
        private val saved = mutableMapOf<String, PasswordCredential>()

        override fun save(credential: PasswordCredential) {
            calls += "save:${credential.username}"
            saved[credential.username] = credential
        }

        override fun find(
            server: String,
            username: String,
        ): PasswordCredential? {
            calls += "find:$username"
            return saved[username]
        }

        override fun findAll(server: String): List<PasswordCredential> {
            calls += "findAll:$server"
            return saved.values.toList()
        }

        override fun delete(
            server: String,
            username: String,
        ) {
            calls += "delete:$username"
            saved.remove(username)
        }

        override fun clear() {
            calls += "clear"
            saved.clear()
        }
    }
}
