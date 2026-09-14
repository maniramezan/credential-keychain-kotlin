package com.maniramezan.credentialkeychain

import java.io.File
import java.nio.file.Files
import java.util.Base64
import kotlin.test.*

class BackendCommandTest {
    @Test fun linuxPreservesNewlinesAndScopesAccounts() {
        val commands = mutableListOf<List<String>>()
        val runner =
            CommandRunner { args, _ ->
                commands += args
                CommandResult(0, "secret\r\n", "")
            }
        val first = LinuxKeyringStore("service", "first", File("secret-tool"), runner)
        val second = LinuxKeyringStore("service", "second", File("secret-tool"), runner)
        assertEquals("secret\r\n", first.read("--help"))
        second.read("--help")
        assertTrue(commands[0].contains("--"))
        assertTrue(commands[0].indexOf("--") < commands[0].indexOf("--help"))
        assertTrue(commands[0].contains("first"))
        assertTrue(commands[1].contains("second"))
        assertNotEquals(commands[0], commands[1])
    }

    @Test fun linuxWritesSendSecretsOnlyThroughStdin() {
        var called = false
        val store =
            LinuxKeyringStore(
                "service",
                "account",
                File("secret-tool"),
                CommandRunner { args, stdin ->
                    called = true
                    assertFalse(args.joinToString().contains("top-secret"))
                    assertEquals("top-secret", stdin)
                    assertEquals("store", args[1])
                    CommandResult(0, "", "")
                },
            )
        store.write("key", "top-secret")
        assertTrue(called)
    }

    @Test fun linuxDistinguishesMissingEntriesFromFailuresWithoutLeakingStderr() {
        val missing = linuxStore(CommandResult(1, "", ""))
        assertNull(missing.read("key"))
        missing.delete("key")
        missing.clear()
        val broken = linuxStore(CommandResult(1, "", "sensitive error"))
        val error = assertFailsWith<KeychainUnavailableException> { broken.read("key") }
        assertFalse(error.toString().contains("sensitive"))
        assertEquals(KeychainUnavailableException.Reason.Failed, error.reason)
        assertFailsWith<KeychainUnavailableException> { broken.delete("key") }
        assertFailsWith<KeychainUnavailableException> { broken.clear() }
        assertFailsWith<KeychainUnavailableException> { linuxStore(CommandResult(2, "", "")).write("key", "secret") }
    }

    @Test fun linuxClearMatchesOnlyThisLibrarysNamespace() {
        val commands = mutableListOf<List<String>>()
        val runner =
            CommandRunner { args, _ ->
                commands += args
                CommandResult(0, "", "")
            }
        LinuxKeyringStore("service", "account", File("secret-tool"), runner).clear()
        LinuxKeyringStore("service", "account", File("secret-tool"), runner).delete("key")
        val clear = commands[0].drop(1)
        assertEquals(listOf("clear", "--", "library", "credential-keychain-kotlin", "service", "service", "account", "account"), clear)
        assertEquals(clear + listOf("key", "key"), commands[1].drop(1))
    }

    @Test fun linuxRejectsOversizedUtf8BeforeStartingCommand() {
        val store =
            LinuxKeyringStore(
                "test",
                secretTool = File("tool"),
                runner = CommandRunner { _, _ -> error("Command should not start") },
            )
        assertFailsWith<IllegalArgumentException> { store.write("key", "秘".repeat(3000)) }
    }

    @Test fun windowsSendsSecretsOnlyThroughStdin() {
        val directory = Files.createTempDirectory("keychain-command").toFile()
        try {
            val secret = "secret ' with unicode 秘密"
            val encoded = Base64.getEncoder().encodeToString(secret.toByteArray())
            var called = false
            val store =
                WindowsDpapiStore(
                    "test",
                    powershell = File("powershell.exe"),
                    storageDir = directory,
                    runner =
                        CommandRunner { args, input ->
                            called = true
                            assertFalse(args.joinToString().contains(secret))
                            assertFalse(args.joinToString().contains(encoded))
                            assertTrue(checkNotNull(input).contains(encoded))
                            assertTrue(input.contains("File]::Replace"))
                            assertTrue(input.contains("ErrorActionPreference = 'Stop'"))
                            CommandResult(0, "", "")
                        },
                )
            store.write("../escape", secret)
            assertTrue(called)
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun linuxStore(result: CommandResult) =
        LinuxKeyringStore("test", secretTool = File("tool"), runner = CommandRunner { _, _ -> result })
}
