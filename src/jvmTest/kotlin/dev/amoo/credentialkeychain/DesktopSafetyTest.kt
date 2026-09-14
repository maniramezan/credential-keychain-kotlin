package dev.amoo.credentialkeychain

import java.io.File
import java.nio.file.Files
import kotlin.test.*

class DesktopSafetyTest {
    @Test fun windowsKeysCannotEscapeDirectory() {
        val directory = Files.createTempDirectory("keychain-test").toFile()
        try {
            val store = WindowsDpapiStore("service", storageDir = directory)
            val keys = listOf("../outside", "/absolute/path", "a/b", "a\\b", "CON", "a", "A", "😀")
            val files = keys.map(store::fileFor)
            assertEquals(keys.size, files.toSet().size)
            files.forEach { assertEquals(directory.canonicalFile, it.canonicalFile.parentFile) }
        } finally { directory.deleteRecursively() }
    }

    @Test fun missingToolsAreErrorsIncludingReadsAndDeletes() {
        for (store in listOf(LinuxSecretServiceStore("test", secretTool = null), WindowsDpapiStore("test", powershell = null))) {
            assertFailsWith<KeychainUnavailableException> { store.read("key") }
            assertFailsWith<KeychainUnavailableException> { store.write("key", "secret") }
            assertFailsWith<KeychainUnavailableException> { store.delete("key") }
        }
    }

    @Test fun commandClosesStdinAndDrainsBothStreams() {
        val result = fixture("streams")
        assertEquals(0, result.exitCode)
        assertEquals(200_000, result.stdout.length)
        assertEquals(200_000, result.stderr.length)
    }

    @Test fun commandTransmitsUnicodeThroughStdin() {
        assertEquals("秘密 🔑", fixture("echo", "秘密 🔑").stdout)
    }

    @Test fun commandHasBoundedWait() {
        assertFailsWith<KeychainUnavailableException> { fixture("sleep", timeout = 1) }
    }

    private fun fixture(mode: String, input: String? = null, timeout: Long = 10): CommandResult {
        val java = File(System.getProperty("java.home"), "bin/java").absolutePath
        val classpath = listOf(
            CommandFixture::class.java.protectionDomain.codeSource.location.toURI(),
            Unit::class.java.protectionDomain.codeSource.location.toURI(),
        ).joinToString(File.pathSeparator) { File(it).path }
        return runCommand(java, "-cp", classpath, CommandFixture::class.java.name, mode, stdin = input, timeoutSeconds = timeout)
    }
}

object CommandFixture {
    @JvmStatic fun main(args: Array<String>) {
        when (args[0]) {
            "streams" -> {
                System.`in`.readBytes()
                repeat(200_000) { System.err.print('e') }
                repeat(200_000) { print('o') }
            }
            "echo" -> System.out.write(System.`in`.readBytes()).also { System.out.flush() }
            "sleep" -> Thread.sleep(60_000)
        }
    }
}
