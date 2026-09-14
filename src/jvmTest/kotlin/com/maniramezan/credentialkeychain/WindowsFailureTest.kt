package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.nio.file.Files
import java.util.Base64
import kotlin.test.*

class WindowsFailureTest {
    @Test fun missingEntriesDoNotLaunchPowerShell() =
        withDirectory { directory ->
            val store = store(directory, CommandRunner { _, _ -> error("Must not launch") })
            assertNull(store.read("missing"))
            store.delete("missing")
        }

    @Test fun readsDecodeExactUnicodeAndMultilineData() =
        withDirectory { directory ->
            val secret = "  秘密\r\nline two\n"
            val store =
                store(
                    directory,
                    CommandRunner { _, input ->
                        assertTrue(assertNotNull(input).contains("::Unprotect"))
                        CommandResult(0, Base64.getEncoder().encodeToString(secret.toByteArray()), "")
                    },
                )
            store.fileFor("key").writeBytes(byteArrayOf(1)) // Fake ciphertext; never used by a real backend.
            assertEquals(secret, store.read("key"))
        }

    @Test fun invalidBase64AndDpapiErrorsNeverBecomeMissingEntries() =
        withDirectory { directory ->
            for ((result, reason) in listOf(
                CommandResult(0, "not base64!", "") to Reason.Corrupted,
                CommandResult(1, "", "sensitive") to Reason.Failed,
            )) {
                val store = store(directory, CommandRunner { _, _ -> result })
                store.fileFor("key").writeBytes(byteArrayOf(1))
                val error = assertFailsWith<KeychainUnavailableException> { store.read("key") }
                assertFalse(error.toString().contains("sensitive"))
                assertEquals(reason, error.reason)
            }
        }

    @Test fun failedWritesKeepPreviousCiphertext() =
        withDirectory { directory ->
            val store = store(directory, CommandRunner { _, _ -> CommandResult(1, "", "") })
            val previous = byteArrayOf(1, 2, 3)
            store.fileFor("key").writeBytes(previous)
            assertFailsWith<KeychainUnavailableException> { store.write("key", "replacement") }
            assertContentEquals(previous, store.fileFor("key").readBytes())
        }

    @Test fun writesFailWhenDirectoryCannotBeCreated() =
        withDirectory { directory ->
            val occupied = File(directory, "occupied").apply { writeBytes(byteArrayOf(1)) }
            val store = store(File(occupied, "child"), CommandRunner { _, _ -> error("Must not launch") })
            assertFailsWith<KeychainUnavailableException> { store.write("key", "secret") }
        }

    @Test fun deletesRemoveCiphertextAndFailedDeletesThrow() =
        withDirectory { directory ->
            val store = store(directory, CommandRunner { _, _ -> error("Must not launch") })
            store.fileFor("key").writeBytes(byteArrayOf(1))
            store.delete("key")
            assertFalse(store.fileFor("key").exists())
            store.fileFor("key").mkdir()
            File(store.fileFor("key"), "child").writeBytes(byteArrayOf(1))
            assertFailsWith<KeychainUnavailableException> { store.delete("key") }
        }

    @Test fun clearRemovesTheNamespaceDirectoryWithoutLaunchingPowerShell() =
        withDirectory { directory ->
            val namespace = File(directory, "namespace")
            val sibling = File(directory, "sibling").apply { mkdirs() }
            File(sibling, "other.bin").writeBytes(byteArrayOf(1))
            val store = store(namespace, CommandRunner { _, _ -> error("Must not launch") })
            store.clear()
            namespace.mkdirs()
            store.fileFor("a").writeBytes(byteArrayOf(1))
            store.fileFor("b").writeBytes(byteArrayOf(2))
            File(namespace, "leftover.tmp").writeBytes(byteArrayOf(3))
            store.clear()
            assertFalse(namespace.exists())
            assertTrue(File(sibling, "other.bin").exists())
            namespace.mkdirs()
            File(namespace, "stuck").mkdir()
            File(namespace, "stuck/child").writeBytes(byteArrayOf(1))
            assertEquals(Reason.Failed, assertFailsWith<KeychainUnavailableException> { store.clear() }.reason)
        }

    @Test fun serviceAndAccountEachIsolateStoragePaths() {
        val first = WindowsDpapiStore("service", "first").fileFor("key")
        assertNotEquals(first, WindowsDpapiStore("service", "second").fileFor("key"))
        assertNotEquals(first, WindowsDpapiStore("other", "first").fileFor("key"))
        assertEquals(first, WindowsDpapiStore("service", "first").fileFor("key"))
    }

    private fun store(
        directory: File,
        runner: CommandRunner,
    ) = WindowsDpapiStore("test", powershell = File("powershell.exe"), storageDir = directory, runner = runner)

    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("keychain-windows-test").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }
}
