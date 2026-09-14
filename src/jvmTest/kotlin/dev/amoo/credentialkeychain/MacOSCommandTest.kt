package dev.amoo.credentialkeychain

import java.io.File
import java.nio.file.Files
import kotlin.test.*

class MacOSCommandTest {
    // Only existence/executability is checked; the injected runner never launches this binary.
    private val executable = File(System.getProperty("java.home"), "bin/java" +
        if (System.getProperty("os.name").startsWith("Windows")) ".exe" else "")

    @Test fun readsPreserveWhitespaceAndDistinguishMissingFromDenied() {
        val found = store(CommandResult(0, "  secret  \n", ""))
        assertEquals("  secret  ", found.read("key"))
        assertNull(store(CommandResult(44, "", "")).read("missing"))
        val error = assertFailsWith<KeychainUnavailableException> {
            store(CommandResult(1, "", "secret could not be found in error output")).read("key")
        }
        assertFalse(error.toString().contains("secret could"))
    }

    @Test fun secretsAreQuotedAndOnlySentThroughStdin() {
        val secret = "spaces ' quotes \" and \\ unicode 秘密"
        var called = false
        val store = MacOSKeychainStore("service", "account", executable, CommandRunner { args, stdin ->
            called = true
            assertEquals(listOf(executable.path, "-i"), args)
            assertFalse(args.joinToString().contains(secret))
            val input = assertNotNull(stdin)
            assertTrue(input.contains("-w \"spaces ' quotes \\\" and \\\\ unicode 秘密\""))
            assertTrue(input.endsWith(" -U\n"))
            CommandResult(0, "", "")
        })
        store.write("key", secret)
        assertTrue(called)
    }

    @Test fun writesRejectLineBreaksAndPropagateFailures() {
        val store = store(CommandResult(1, "", "sensitive"))
        assertFailsWith<IllegalArgumentException> { store.write("key", "one\ntwo") }
        assertFailsWith<IllegalArgumentException> { store.write("key", "one\rtwo") }
        assertFailsWith<KeychainUnavailableException> { store.write("key", "secret") }
    }

    @Test fun deletesAndBlankWritesAreIdempotentOnlyForMissingItems() {
        store(CommandResult(0, "", "")).delete("key")
        store(CommandResult(44, "", "")).delete("missing")
        store(CommandResult(44, "", "")).write("key", " ")
        assertFailsWith<KeychainUnavailableException> { store(CommandResult(1, "", "")).delete("key") }
    }

    @Test fun namespacesCannotCollideAndAccountsAreIncluded() {
        val commands = mutableListOf<List<String>>()
        val runner = CommandRunner { args, _ -> commands += args; CommandResult(44, "", "") }
        MacOSKeychainStore("a.b", "first", executable, runner).read("c")
        MacOSKeychainStore("a", "second", executable, runner).read("b.c")
        assertNotEquals(commands[0][commands[0].indexOf("-s") + 1], commands[1][commands[1].indexOf("-s") + 1])
        assertTrue(commands[0].contains("first"))
        assertTrue(commands[1].contains("second"))
    }

    @Test fun absentExecutableFailsWithoutLaunching() {
        val directory = Files.createTempDirectory("keychain-missing-tool").toFile()
        try {
            val store = MacOSKeychainStore("test", "test", File(directory, "missing"),
                CommandRunner { _, _ -> error("Must not launch") })
            assertFailsWith<KeychainUnavailableException> { store.read("key") }
        } finally { directory.deleteRecursively() }
    }

    private fun store(result: CommandResult) =
        MacOSKeychainStore("test", "test", executable, CommandRunner { _, _ -> result })
}
