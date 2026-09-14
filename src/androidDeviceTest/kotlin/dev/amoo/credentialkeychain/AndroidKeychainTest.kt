package dev.amoo.credentialkeychain

import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

class AndroidKeychainTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun roundTripPersistsAndIsolatesAccounts() =
        withStore { service, first ->
            val second = CredentialKeychain.forCurrentPlatform(context, service, "second")
            try {
                assertNull(first.read("key"))
                first.write("key", "秘密\nline two\n")
                assertEquals("秘密\nline two\n", create(service).read("key"))
                assertNull(second.read("key"))
                second.write("key", "other")
                first.write("key", "updated")
                assertEquals("updated", first.read("key"))
                assertEquals("other", second.read("key"))
                first.write("key", " ")
                assertNull(first.read("key"))
                first.delete("missing")
            } finally {
                second.delete("key")
                removeNamespace(service, "second")
            }
        }

    @Test fun tamperingAndTruncationFailWithoutReturningPlaintext() =
        withStore { service, store ->
            store.write("key", "secret")
            val file = file(service, "key")
            val bytes = file.readBytes()
            val tampered = bytes.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
            file.writeBytes(tampered)
            assertFailsWith<KeychainUnavailableException> { store.read("key") }
            file.writeBytes(bytes.copyOf(8))
            assertFailsWith<KeychainUnavailableException> { store.read("key") }
            file.writeBytes(bytes.copyOf().apply { this[0] = 99 })
            assertFailsWith<KeychainUnavailableException> { store.read("key") }
        }

    @Test fun ciphertextCannotBeMovedBetweenKeys() =
        withStore { service, store ->
            store.write("first", "secret-one")
            store.write("second", "secret-two")
            file(service, "second").writeBytes(file(service, "first").readBytes())
            assertFailsWith<KeychainUnavailableException> { store.read("second") }
            assertEquals("secret-one", store.read("first"))
        }

    @Test fun missingEncryptionKeyIsNeverSilentlyReplaced() =
        withStore { service, store ->
            store.write("key", "secret")
            val original = file(service, "key").readBytes()
            val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            keystore.deleteEntry(alias(service))
            assertFailsWith<KeychainUnavailableException> { store.read("key") }
            assertFailsWith<KeychainUnavailableException> { store.write("key", "replacement") }
            assertFalse(keystore.containsAlias(alias(service)))
            assertContentEquals(original, file(service, "key").readBytes())
            store.delete("key")
            store.write("key", "new credential after explicit deletion")
            assertEquals("new credential after explicit deletion", store.read("key"))
        }

    @Test fun writesUseFreshIvsAndNeverPersistPlaintext() =
        withStore { service, store ->
            val secret = "recognizable-test-secret-1234567890"
            store.write("key", secret)
            val first = file(service, "key").readBytes()
            store.write("key", secret)
            val second = file(service, "key").readBytes()
            assertFalse(first.contentEquals(second))
            assertFalse(first.copyOfRange(1, 13).contentEquals(second.copyOfRange(1, 13)))
            assertFalse(first.toString(Charsets.UTF_8).contains(secret))
            assertEquals(secret, store.read("key"))
        }

    @Test fun concurrentInstancesKeepIndependentEntriesIntact() =
        withStore { service, _ ->
            val executor = Executors.newFixedThreadPool(4)
            try {
                val futures =
                    (0 until 12).map { index ->
                        executor.submit {
                            val store = create(service)
                            repeat(3) { store.write("key-$index", "value-$index-$it") }
                            assertEquals("value-$index-2", store.read("key-$index"))
                        }
                    }
                futures.forEach { it.get(30, TimeUnit.SECONDS) }
            } finally {
                executor.shutdownNow()
            }
        }

    @Test fun legacyAtomicBackupIsRecovered() =
        withStore { service, store ->
            store.write("key", "secret")
            val file = file(service, "key")
            assertTrue(file.renameTo(File(file.path + ".bak")))
            assertEquals("secret", store.read("key"))
        }

    private fun create(service: String) = CredentialKeychain.forCurrentPlatform(context, service, "first")

    private fun alias(
        service: String,
        account: String = "first",
    ) = "dev.amoo.credentialkeychain.${digest(credentialNamespace(service, account))}"

    private fun file(
        service: String,
        key: String,
    ) = File(File(context.noBackupFilesDir, alias(service)), "${digest(key)}.bin")

    private fun digest(value: String) =
        MessageDigest
            .getInstance("SHA-256")
            .digest(value.toByteArray())
            .joinToString("") { "%02x".format(it) }

    private fun removeNamespace(
        service: String,
        account: String = "first",
    ) {
        File(context.noBackupFilesDir, alias(service, account)).deleteRecursively()
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            deleteEntry(alias(service, account))
        }
    }

    private fun withStore(block: (String, CredentialKeychain) -> Unit) {
        val service = "keychain-test-${UUID.randomUUID()}"
        try {
            block(service, create(service))
        } finally {
            removeNamespace(service)
        }
    }
}
