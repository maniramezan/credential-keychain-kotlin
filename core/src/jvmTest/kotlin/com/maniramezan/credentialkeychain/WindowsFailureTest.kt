package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.nio.file.Files
import kotlin.test.*

class WindowsFailureTest {
    @Test fun missingEntriesNeverCallDpapi() =
        withDirectory { directory ->
            val api = FakeWindowsApi()
            val store = store(directory, api)
            assertNull(store.read("missing"))
            store.delete("missing")
            assertEquals(emptyList(), api.calls)
        }

    @Test fun roundTripsExactUnicodeAndMultilineDataAsCiphertextOnly() =
        withDirectory { directory ->
            val secret = "  秘密\r\nline two\n"
            val store = store(directory, FakeWindowsApi())
            store.write("key", secret)
            assertEquals(secret, store.read("key"))
            assertContentEquals(FakeWindowsApi.MARKER + secret.toByteArray().reversedArray(), store.fileFor("key").readBytes())
            assertEquals(listOf(store.fileFor("key")), directory.listFiles()?.toList())
            store.write("key", "")
            assertEquals("", store.read("key"))
        }

    @Test fun invalidPlaintextAndDpapiErrorsNeverBecomeMissingEntries() =
        withDirectory { directory ->
            val api = FakeWindowsApi()
            val store = store(directory, api)
            store.fileFor("key").writeBytes(FakeWindowsApi.MARKER + byteArrayOf(-1))
            assertEquals(Reason.Corrupted, assertFailsWith<KeychainUnavailableException> { store.read("key") }.reason)
            store.fileFor("key").writeBytes(byteArrayOf(1))
            val error = assertFailsWith<KeychainUnavailableException> { store.read("key") }
            assertEquals(Reason.Failed, error.reason)
            assertFalse(error.toString().contains("sensitive"))
        }

    @Test fun failedWritesKeepPreviousCiphertext() =
        withDirectory { directory ->
            val api = FakeWindowsApi().apply { failure = IllegalStateException("sensitive") }
            val store = store(directory, api)
            val previous = byteArrayOf(1, 2, 3)
            store.fileFor("key").writeBytes(previous)
            val error = assertFailsWith<KeychainUnavailableException> { store.write("key", "replacement") }
            assertEquals(Reason.Failed, error.reason)
            assertFalse(error.toString().contains("sensitive"))
            assertContentEquals(previous, store.fileFor("key").readBytes())
            assertEquals(listOf(store.fileFor("key")), directory.listFiles()?.toList())
        }

    @Test fun writesFailWhenDirectoryCannotBeCreated() =
        withDirectory { directory ->
            val occupied = File(directory, "occupied").apply { writeBytes(byteArrayOf(1)) }
            val api = FakeWindowsApi()
            val store = store(File(occupied, "child"), api)
            assertFailsWith<KeychainUnavailableException> { store.write("key", "secret") }
            assertEquals(emptyList(), api.calls)
        }

    @Test fun deletesRemoveCiphertextAndFailedDeletesThrow() =
        withDirectory { directory ->
            val store = store(directory, FakeWindowsApi())
            store.fileFor("key").writeBytes(byteArrayOf(1))
            store.delete("key")
            assertFalse(store.fileFor("key").exists())
            store.fileFor("key").mkdir()
            File(store.fileFor("key"), "child").writeBytes(byteArrayOf(1))
            assertFailsWith<KeychainUnavailableException> { store.delete("key") }
        }

    @Test fun clearRemovesTheNamespaceDirectoryWithoutCallingDpapi() =
        withDirectory { directory ->
            val namespace = File(directory, "namespace")
            val sibling = File(directory, "sibling").apply { mkdirs() }
            File(sibling, "other.bin").writeBytes(byteArrayOf(1))
            val api = FakeWindowsApi()
            val store = store(namespace, api)
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
            assertEquals(emptyList(), api.calls)
        }

    @Test fun serviceAndAccountEachIsolateStoragePaths() {
        val first = WindowsDpapiStore("service", "first").fileFor("key")
        assertNotEquals(first, WindowsDpapiStore("service", "second").fileFor("key"))
        assertNotEquals(first, WindowsDpapiStore("other", "first").fileFor("key"))
        assertEquals(first, WindowsDpapiStore("service", "first").fileFor("key"))
    }

    private fun store(
        directory: File,
        api: WindowsApi,
    ) = WindowsDpapiStore("test", storageDir = directory, windowsApi = { api })

    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("keychain-windows-test").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }
}
