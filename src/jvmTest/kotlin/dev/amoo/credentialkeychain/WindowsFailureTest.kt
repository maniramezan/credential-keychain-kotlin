package dev.amoo.credentialkeychain

import java.io.File
import java.nio.file.Files
import java.util.Base64
import kotlin.test.*

class WindowsFailureTest {
    @Test fun missingEntriesDoNotLaunchPowerShell() = withDirectory { directory ->
        val store = store(directory, CommandRunner { _, _ -> error("Must not launch") })
        assertNull(store.read("missing"))
        store.delete("missing")
    }

    @Test fun readsDecodeExactUnicodeAndMultilineData() = withDirectory { directory ->
        val secret = "  秘密\r\nline two\n"
        val store = store(directory, CommandRunner { _, input ->
            assertTrue(assertNotNull(input).contains("::Unprotect"))
            CommandResult(0, Base64.getEncoder().encodeToString(secret.toByteArray()), "")
        })
        store.fileFor("key").writeBytes(byteArrayOf(1)) // Fake ciphertext; never used by a real backend.
        assertEquals(secret, store.read("key"))
    }

    @Test fun invalidBase64AndDpapiErrorsNeverBecomeMissingEntries() = withDirectory { directory ->
        for (result in listOf(CommandResult(0, "not base64!", ""), CommandResult(1, "", "sensitive"))) {
            val store = store(directory, CommandRunner { _, _ -> result })
            store.fileFor("key").writeBytes(byteArrayOf(1))
            val error = assertFailsWith<KeychainUnavailableException> { store.read("key") }
            assertFalse(error.toString().contains("sensitive"))
        }
    }

    @Test fun failedWritesKeepPreviousCiphertext() = withDirectory { directory ->
        val store = store(directory, CommandRunner { _, _ -> CommandResult(1, "", "") })
        val previous = byteArrayOf(1, 2, 3)
        store.fileFor("key").writeBytes(previous)
        assertFailsWith<KeychainUnavailableException> { store.write("key", "replacement") }
        assertContentEquals(previous, store.fileFor("key").readBytes())
    }

    @Test fun writesFailWhenDirectoryCannotBeCreated() = withDirectory { directory ->
        val occupied = File(directory, "occupied").apply { writeBytes(byteArrayOf(1)) }
        val store = store(File(occupied, "child"), CommandRunner { _, _ -> error("Must not launch") })
        assertFailsWith<KeychainUnavailableException> { store.write("key", "secret") }
    }

    @Test fun blankWritesDeleteAndFailedDeletesThrow() = withDirectory { directory ->
        val store = store(directory, CommandRunner { _, _ -> error("Must not launch") })
        store.fileFor("key").writeBytes(byteArrayOf(1))
        store.write("key", " ")
        assertFalse(store.fileFor("key").exists())
        store.fileFor("key").mkdir()
        File(store.fileFor("key"), "child").writeBytes(byteArrayOf(1))
        assertFailsWith<KeychainUnavailableException> { store.delete("key") }
    }

    @Test fun serviceAndAccountEachIsolateStoragePaths() {
        val first = WindowsDpapiStore("service", "first").fileFor("key")
        assertNotEquals(first, WindowsDpapiStore("service", "second").fileFor("key"))
        assertNotEquals(first, WindowsDpapiStore("other", "first").fileFor("key"))
        assertEquals(first, WindowsDpapiStore("service", "first").fileFor("key"))
    }

    private fun store(directory: File, runner: CommandRunner) =
        WindowsDpapiStore("test", powershell = File("powershell.exe"), storageDir = directory, runner = runner)

    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("keychain-windows-test").toFile()
        try { block(directory) } finally { directory.deleteRecursively() }
    }
}
