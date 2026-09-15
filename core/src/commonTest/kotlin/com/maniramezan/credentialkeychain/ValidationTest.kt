package com.maniramezan.credentialkeychain

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
            assertFailsWith<IllegalArgumentException> { CredentialKeychain.forCurrentPlatform(invalid, "test", KeychainOptions()) }
            val keychain = ValidatingKeychain(UnsupportedKeychainStore("test"))
            assertFailsWith<IllegalArgumentException> { keychain.read(invalid) }
            assertFailsWith<IllegalArgumentException> { keychain.write(invalid, "secret") }
            assertFailsWith<IllegalArgumentException> { keychain.delete(invalid) }
        }
    }

    @Test fun validationMessagesNameTheFieldButNeverTheValue() {
        val blankService = assertFailsWith<IllegalArgumentException> { CredentialKeychain.forCurrentPlatform(" ", "account") }
        assertEquals("serviceName must not be blank.", blankService.message)
        val badAccount = assertFailsWith<IllegalArgumentException> { CredentialKeychain.forCurrentPlatform("service", "a\nb") }
        assertEquals("accountName must not contain NUL or line breaks.", badAccount.message)
        val keychain = ValidatingKeychain(RecordingKeychain())
        assertEquals("key must not be blank.", assertFailsWith<IllegalArgumentException> { keychain.read("") }.message)
        val badValue = assertFailsWith<IllegalArgumentException> { keychain.write("key", "top-secret\u0000") }
        assertEquals("value must not contain NUL.", badValue.message)
        assertFalse(badValue.message.orEmpty().contains("top-secret"))
    }

    @Test fun validOperationsReachTheDelegateAndPreserveFailures() {
        val calls = RecordingKeychain()
        val keychain = ValidatingKeychain(calls)
        assertEquals("value", keychain.read("key"))
        keychain.delete("key")
        keychain.clear()
        assertEquals(listOf("read:key", "delete:key", "clear"), calls.calls)
        val unavailable = ValidatingKeychain(UnsupportedKeychainStore("test"))
        assertFailsWith<KeychainUnavailableException> { unavailable.read("key") }
        assertFailsWith<KeychainUnavailableException> { unavailable.delete("key") }
        assertFailsWith<KeychainUnavailableException> { unavailable.clear() }
    }

    @Test fun blankValuesAreRejectedAndOthersAreNotTrimmed() {
        val calls = RecordingKeychain()
        val keychain = ValidatingKeychain(calls)
        keychain.write("key", "  secret  ")
        for (blank in listOf("", " ", " \n", "\t")) {
            assertFailsWith<IllegalArgumentException> { keychain.write("key", blank) }
        }
        assertFailsWith<IllegalArgumentException> { keychain.write("key", "a\u0000b") }
        assertEquals(listOf("write:key=  secret  "), calls.calls)
    }

    private class RecordingKeychain : CredentialKeychain {
        val calls = mutableListOf<String>()

        override fun read(key: String): String {
            calls += "read:$key"
            return "value"
        }

        override fun write(
            key: String,
            value: String,
        ) {
            calls += "write:$key=$value"
        }

        override fun delete(key: String) {
            calls += "delete:$key"
        }

        override fun clear() {
            calls += "clear"
        }
    }
}
