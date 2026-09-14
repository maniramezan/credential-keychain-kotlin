package dev.amoo.credentialkeychain

import java.io.File
import java.nio.file.Files
import java.util.Base64
import kotlin.test.*

class BackendCommandTest {
    @Test fun linuxPreservesNewlinesAndScopesAccounts() {
        val commands = mutableListOf<List<String>>()
        val runner = CommandRunner { args, _ -> commands += args; CommandResult(0, "secret\r\n", "") }
        val first = LinuxSecretServiceStore("service", "first", File("secret-tool"), runner)
        val second = LinuxSecretServiceStore("service", "second", File("secret-tool"), runner)
        assertEquals("secret\r\n", first.read("--help"))
        second.read("--help")
        assertTrue(commands[0].contains("--"))
        assertTrue(commands[0].contains("first"))
        assertTrue(commands[1].contains("second"))
        assertNotEquals(commands[0], commands[1])
    }

    @Test fun linuxDistinguishesMissingEntriesFromFailuresWithoutLeakingStderr() {
        val missing = LinuxSecretServiceStore("test", secretTool = File("tool"), runner = CommandRunner { _, _ -> CommandResult(1, "", "") })
        assertNull(missing.read("key"))
        missing.delete("key")
        val broken = LinuxSecretServiceStore("test", secretTool = File("tool"), runner = CommandRunner { _, _ -> CommandResult(1, "", "sensitive error") })
        val error = assertFailsWith<KeychainUnavailableException> { broken.read("key") }
        assertFalse(error.toString().contains("sensitive"))
        assertFailsWith<KeychainUnavailableException> { broken.delete("key") }
    }

    @Test fun linuxRejectsOversizedUtf8BeforeStartingCommand() {
        val store = LinuxSecretServiceStore("test", secretTool = File("tool"),
            runner = CommandRunner { _, _ -> error("Command should not start") })
        assertFailsWith<IllegalArgumentException> { store.write("key", "秘".repeat(3000)) }
    }

    @Test fun windowsSendsSecretsOnlyThroughStdin() {
        val directory = Files.createTempDirectory("keychain-command").toFile()
        try {
            val secret = "secret ' with unicode 秘密"
            val encoded = Base64.getEncoder().encodeToString(secret.toByteArray())
            var called = false
            val store = WindowsDpapiStore("test", powershell = File("powershell.exe"), storageDir = directory,
                runner = CommandRunner { args, input ->
                    called = true
                    assertFalse(args.joinToString().contains(secret))
                    assertFalse(args.joinToString().contains(encoded))
                    assertTrue(checkNotNull(input).contains(encoded))
                    assertTrue(input.contains("File]::Replace"))
                    assertTrue(input.contains("ErrorActionPreference = 'Stop'"))
                    CommandResult(0, "", "")
                })
            store.write("../escape", secret)
            assertTrue(called)
        } finally { directory.deleteRecursively() }
    }
}
