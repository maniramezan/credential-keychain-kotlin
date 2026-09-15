package com.maniramezan.credentialkeychain.biometric

import com.maniramezan.credentialkeychain.KeychainUnavailableException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProtectedKeychainTest {
    private val prompt = AuthenticationPrompt(title = "Unlock", cancelLabel = "Cancel")

    @Test fun invalidInputNeverReachesTheBackend() =
        runTest {
            val backend = RecordingKeychain()
            val store = ValidatingProtectedKeychain(backend)
            assertFailsWith<IllegalArgumentException> { store.read(" ", prompt) }
            assertFailsWith<IllegalArgumentException> { store.write("key", " ") }
            assertFailsWith<IllegalArgumentException> { store.write("key", "a${Char(0)}b") }
            assertFailsWith<IllegalArgumentException> { store.write("a\nb", "value") }
            assertFailsWith<IllegalArgumentException> { store.delete("a\rb") }
            assertTrue(backend.calls.isEmpty())

            store.write("key", "  value with spaces ")
            assertEquals("  value with spaces ", store.read("key", prompt))
            store.delete("key")
            assertNull(store.read("key", prompt))
            store.clear()
            assertEquals(listOf("write key", "read key Unlock", "delete key", "read key Unlock", "clear"), backend.calls)
        }

    @Test fun promptTextIsValidated() {
        assertEquals(
            "title must not be blank.",
            assertFailsWith<IllegalArgumentException> { AuthenticationPrompt(" ", cancelLabel = "Cancel") }.message,
        )
        assertEquals(
            "subtitle must not be blank when set.",
            assertFailsWith<IllegalArgumentException> { AuthenticationPrompt("Unlock", " ", "Cancel") }.message,
        )
        assertEquals(
            "cancelLabel must not be blank.",
            assertFailsWith<IllegalArgumentException> { AuthenticationPrompt("Unlock", cancelLabel = "") }.message,
        )
        assertEquals("Unlock", AuthenticationPrompt("Unlock", cancelLabel = "Cancel").reason)
        assertEquals("Sign in to your account", AuthenticationPrompt("Unlock", "Sign in to your account", "Cancel").reason)
    }

    @Test fun unsupportedStoresFailEveryOperation() =
        runTest {
            val store = ValidatingProtectedKeychain(UnsupportedProtectedKeychain("BeOS"))
            val operations =
                listOf<suspend () -> Unit>(
                    { store.read("key", prompt) },
                    { store.write("key", "value") },
                    { store.delete("key") },
                    { store.clear() },
                )
            for (operation in operations) {
                val error = assertFailsWith<KeychainUnavailableException> { operation() }
                assertEquals(KeychainUnavailableException.Reason.Unsupported, error.reason)
                assertTrue("BeOS" in error.message.orEmpty())
            }
        }

    @Test fun namespacesDifferFromCoreStoresWithTheSameNames() {
        assertEquals("36:credential-keychain-kotlin-biometric3:app4:user", credentialNamespace(BIOMETRIC_NAMESPACE, "app", "user"))
    }

    private class RecordingKeychain : ProtectedKeychain {
        val calls = mutableListOf<String>()
        private val values = mutableMapOf<String, String>()

        override suspend fun read(
            key: String,
            prompt: AuthenticationPrompt,
        ): String? {
            calls += "read $key ${prompt.title}"
            return values[key]
        }

        override fun write(
            key: String,
            value: String,
        ) {
            calls += "write $key"
            values[key] = value
        }

        override fun delete(key: String) {
            calls += "delete $key"
            values.remove(key)
        }

        override fun clear() {
            calls += "clear"
            values.clear()
        }
    }
}
