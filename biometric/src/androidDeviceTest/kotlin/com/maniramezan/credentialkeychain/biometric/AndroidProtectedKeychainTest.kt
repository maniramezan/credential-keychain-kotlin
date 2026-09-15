package com.maniramezan.credentialkeychain.biometric

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maniramezan.credentialkeychain.KeychainUnavailableException
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

/**
 * Emulators in CI have no secure lock screen or enrolled biometric, so these tests cover every
 * path that needs no prompt. Prompted reads and enrollment invalidation need a device with an
 * enrolled Class 3 biometric.
 */
@RunWith(AndroidJUnit4::class)
class AndroidProtectedKeychainTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val service = "credential-keychain-biometric-tests-${UUID.randomUUID()}"
    private val prompt = AuthenticationPrompt("Unlock", cancelLabel = "Cancel")
    private val noPrompt = BiometricAuthenticator { _, _ -> error("no prompt expected") }
    private val directory =
        File(
            context.noBackupFilesDir,
            "com.maniramezan.credentialkeychain.biometric.${sha256Hex(credentialNamespace(BIOMETRIC_NAMESPACE, service, "account"))}",
        )

    private fun store(strongBiometric: Boolean) =
        ValidatingProtectedKeychain(AndroidProtectedKeychain(context, service, "account", noPrompt) { strongBiometric })

    @After fun clear() {
        store(strongBiometric = false).clear()
    }

    @Test fun writesWithoutAnEnrolledBiometricAreUnsupported() {
        val store = store(strongBiometric = false)
        assertEquals(Reason.Unsupported, assertFailsWith<KeychainUnavailableException> { store.write("key", "value") }.reason)
        assertNull(runBlocking { store.read("key", prompt) })
    }

    @Test fun keyGenerationWithoutASecureLockScreenIsUnsupportedAndStoresNothing() {
        // BiometricManager can report success on devices whose Keystore still refuses the key.
        val store = store(strongBiometric = true)
        val error = runCatching { store.write("key", "value") }.exceptionOrNull() as? KeychainUnavailableException ?: return
        assertEquals(Reason.Unsupported, error.reason)
        assertFalse(directory.walkTopDown().any { it.isFile })
        assertNull(runBlocking { store.read("key", prompt) })
    }

    @Test fun missingEntriesReadAsNullWithoutPrompting() {
        val store = ProtectedKeychain.forCurrentPlatform(context, { null }, service, "account")
        assertNull(runBlocking { store.read("missing", prompt) })
        store.delete("missing")
        store.clear()
    }

    @Test fun unreadableRecordsAreCorruptedUntilDeleted() {
        val store = store(strongBiometric = false)
        val file = File(directory, "${sha256Hex("key")}.bin")
        createDirectory()

        file.writeBytes(byteArrayOf(9, 0, 1))
        assertEquals(Reason.Corrupted, readFailure(store).reason)

        // A well-formed record whose Keystore key does not exist.
        file.writeBytes(byteArrayOf(1, 0, 4) + ByteArray(4) + ByteArray(12) + ByteArray(32))
        assertEquals(Reason.Corrupted, readFailure(store).reason)

        store.delete("key")
        assertNull(runBlocking { store.read("key", prompt) })
    }

    @Test fun clearRemovesEveryRecord() {
        val store = store(strongBiometric = false)
        createDirectory()
        File(directory, "${sha256Hex("a")}.bin").writeBytes(byteArrayOf(1))
        File(directory, "${sha256Hex("b")}.bin").writeBytes(byteArrayOf(1))
        store.clear()
        assertFalse(directory.exists())
        assertNull(runBlocking { store.read("a", prompt) })
    }

    private fun createDirectory() {
        val parent = directory.parentFile
        check(directory.mkdirs() || directory.isDirectory) {
            "cannot create $directory: " +
                "parent exists=${parent?.exists()} directory=${parent?.isDirectory} writable=${parent?.canWrite()}, " +
                "path exists=${directory.exists()} file=${directory.isFile}"
        }
    }

    private fun readFailure(store: ProtectedKeychain) =
        assertFailsWith<KeychainUnavailableException> { runBlocking { store.read("key", prompt) } }
}
