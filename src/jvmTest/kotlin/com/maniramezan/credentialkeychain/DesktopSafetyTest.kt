package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.nio.file.Files
import kotlin.test.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

class DesktopSafetyTest {
    @Test fun windowsKeysCannotEscapeDirectory() {
        val directory = Files.createTempDirectory("keychain-test").toFile()
        try {
            val store = WindowsDpapiStore("service", storageDir = directory)
            val keys = listOf("../outside", "/absolute/path", "a/b", "a\\b", "CON", "a", "A", "😀")
            val files = keys.map(store::fileFor)
            assertEquals(keys.size, files.toSet().size)
            files.forEach { assertEquals(directory.canonicalFile, it.canonicalFile.parentFile) }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun missingToolsAreUnsupportedIncludingReadsAndDeletes() {
        for (store in listOf(LinuxKeyringStore("test", secretTool = null), WindowsDpapiStore("test", powershell = null))) {
            val failures =
                listOf(
                    assertFailsWith<KeychainUnavailableException> { store.read("key") },
                    assertFailsWith<KeychainUnavailableException> { store.write("key", "secret") },
                    assertFailsWith<KeychainUnavailableException> { store.delete("key") },
                    assertFailsWith<KeychainUnavailableException> { store.clear() },
                )
            failures.forEach { assertEquals(Reason.Unsupported, it.reason) }
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
        val error = assertFailsWith<KeychainUnavailableException> { fixture("sleep", timeout = 1.seconds) }
        assertEquals(Reason.Failed, error.reason)
    }

    @Test fun earlyFailureKeepsItsExitCodeWhenStdinIsNotRead() {
        assertEquals(3, fixture("exit3", LARGE_INPUT).exitCode)
    }

    @Test fun successWithoutConsumingStdinIsNotTrusted() {
        val error = assertFailsWith<KeychainUnavailableException> { fixture("exit0", LARGE_INPUT) }
        assertEquals(Reason.Failed, error.reason)
    }

    @Test fun platformFactoryAppliesTheConfiguredTimeout() {
        assertNotNull(CredentialKeychain.forCurrentPlatform("test", "test", KeychainOptions(desktopCommandTimeout = 5.seconds)))
    }

    private fun fixture(
        mode: String,
        input: String? = null,
        timeout: Duration = 10.seconds,
    ): CommandResult {
        val java = File(System.getProperty("java.home"), "bin/java").absolutePath
        val classpath =
            listOf(
                CommandFixture::class.java.protectionDomain.codeSource.location
                    .toURI(),
                Unit::class.java.protectionDomain.codeSource.location
                    .toURI(),
            ).joinToString(File.pathSeparator) { File(it).path }
        return runCommand(java, "-cp", classpath, CommandFixture::class.java.name, mode, stdin = input, timeout = timeout)
    }

    private companion object {
        // Larger than any OS pipe buffer, so an exited child makes the stdin writer fail.
        val LARGE_INPUT = "x".repeat(4 * 1024 * 1024)
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

            "echo" -> {
                System.out.write(System.`in`.readBytes()).also { System.out.flush() }
            }

            "sleep" -> {
                Thread.sleep(60_000)
            }

            "exit3" -> {
                Runtime.getRuntime().halt(3)
            }

            "exit0" -> {
                Runtime.getRuntime().halt(0)
            }
        }
    }
}
