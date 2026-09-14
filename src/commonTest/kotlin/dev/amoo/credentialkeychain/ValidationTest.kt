package dev.amoo.credentialkeychain

import kotlin.test.*

class ValidationTest {
    @Test fun namespacesCannotCollide() {
        assertNotEquals(credentialNamespace("a", "bc"), credentialNamespace("ab", "c"))
        assertNotEquals(credentialNamespace("a:b", "c"), credentialNamespace("a", "b:c"))
    }

    @Test fun rejectsIdentifiersBeforeCallingPlatform() {
        for (invalid in listOf("", " ", "a\nb", "a\rb", "a\u0000b")) {
            assertFailsWith<IllegalArgumentException> { CredentialKeychain.forCurrentPlatform(invalid) }
            assertFailsWith<IllegalArgumentException> { CredentialKeychain.forCurrentPlatform("test", invalid) }
            val keychain = ValidatingKeychain(UnsupportedKeychainStore("test"))
            assertFailsWith<IllegalArgumentException> { keychain.read(invalid) }
            assertFailsWith<IllegalArgumentException> { keychain.write(invalid, "secret") }
            assertFailsWith<IllegalArgumentException> { keychain.delete(invalid) }
        }
    }

    @Test fun validReadsAndDeletesReachTheDelegateAndPreserveFailures() {
        val calls = mutableListOf<String>()
        val keychain =
            ValidatingKeychain(
                object : CredentialKeychain {
                    override fun read(key: String): String {
                        calls += "read:$key"
                        return "value"
                    }

                    override fun write(
                        key: String,
                        value: String,
                    ) = Unit

                    override fun delete(key: String) {
                        calls += "delete:$key"
                    }
                },
            )
        assertEquals("value", keychain.read("key"))
        keychain.delete("key")
        assertEquals(listOf("read:key", "delete:key"), calls)
        val unavailable = ValidatingKeychain(UnsupportedKeychainStore("test"))
        assertFailsWith<KeychainUnavailableException> { unavailable.read("key") }
        assertFailsWith<KeychainUnavailableException> { unavailable.delete("key") }
    }

    @Test fun blankWritesDeleteAndValuesAreNotTrimmed() {
        val calls = mutableListOf<String>()
        val keychain =
            ValidatingKeychain(
                object : CredentialKeychain {
                    override fun read(key: String): String? = null

                    override fun write(
                        key: String,
                        value: String,
                    ) {
                        calls += value
                    }

                    override fun delete(key: String) {
                        calls += "delete:$key"
                    }
                },
            )
        keychain.write("key", "  secret  ")
        keychain.write("key", " \n")
        assertEquals(listOf("  secret  ", "delete:key"), calls)
        assertFailsWith<IllegalArgumentException> { keychain.write("key", "a\u0000b") }
    }
}
