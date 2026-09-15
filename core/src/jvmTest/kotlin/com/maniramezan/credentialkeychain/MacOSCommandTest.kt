package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.nio.file.Files
import kotlin.test.*

class MacOSCommandTest {
    // Only existence/executability is checked; the injected runner never launches this binary.
    private val executable =
        File(
            System.getProperty("java.home"),
            "bin/java" +
                if (System.getProperty("os.name").startsWith("Windows")) ".exe" else "",
        )

    @Test fun readsPreserveWhitespaceAndDistinguishMissingFromDenied() {
        val found = store(CommandResult(0, "attributes", "password: \"  secret  \"\n"))
        assertEquals("  secret  ", found.read("key"))
        assertNull(store(CommandResult(44, "", "")).read("missing"))
        val error =
            assertFailsWith<KeychainUnavailableException> {
                store(CommandResult(1, "", "secret could not be found in error output")).read("key")
            }
        assertFalse(error.toString().contains("secret could"))
        assertEquals(Reason.Failed, error.reason)
    }

    @Test fun lockedDeniedAndCanceledStatusesMapToReasons() {
        for ((exitCode, reason) in listOf(36 to Reason.Locked, 51 to Reason.Locked, 128 to Reason.Canceled)) {
            val error = assertFailsWith<KeychainUnavailableException> { store(CommandResult(exitCode, "", "")).read("key") }
            assertEquals(reason, error.reason)
        }
    }

    @Test fun secretsAreQuotedAndOnlySentThroughStdin() {
        val secret = "spaces ' quotes \" and \\ unicode 秘密"
        var called = false
        val store =
            MacOSKeychainStore(
                "service",
                "account",
                executable,
                CommandRunner { args, stdin ->
                    called = true
                    assertEquals(listOf(executable.path, "-i"), args)
                    assertFalse(args.joinToString().contains(secret))
                    val input = assertNotNull(stdin)
                    assertTrue(input.contains("-w \"spaces ' quotes \\\" and \\\\ unicode 秘密\""))
                    assertTrue(input.contains("-a \"key\""))
                    assertTrue(input.endsWith(" -U\n"))
                    CommandResult(0, "", "")
                },
            )
        store.write("key", secret)
        assertTrue(called)
    }

    @Test fun writesRejectLineBreaksAndPropagateFailures() {
        val store = store(CommandResult(1, "", "sensitive"))
        assertFailsWith<IllegalArgumentException> { store.write("key", "one\ntwo") }
        assertFailsWith<IllegalArgumentException> { store.write("key", "one\rtwo") }
        assertFailsWith<KeychainUnavailableException> { store.write("key", "secret") }
    }

    @Test fun deletesAreIdempotentOnlyForMissingItems() {
        store(CommandResult(0, "", "")).delete("key")
        store(CommandResult(44, "", "")).delete("missing")
        assertFailsWith<KeychainUnavailableException> { store(CommandResult(1, "", "")).delete("key") }
    }

    @Test fun namespacesCannotCollideAndAccountsAreIncluded() {
        val commands = mutableListOf<List<String>>()
        val runner =
            CommandRunner { args, _ ->
                commands += args
                CommandResult(44, "", "")
            }
        MacOSKeychainStore("a.b", "first", executable, runner).read("c")
        MacOSKeychainStore("a", "second", executable, runner).read("b.c")
        MacOSKeychainStore("a", "first", executable, runner).read("c")
        val services = commands.map { it[it.indexOf("-s") + 1] }
        assertEquals(3, services.toSet().size)
        assertTrue(services[0].endsWith("5:first"))
        assertTrue(services[1].endsWith("6:second"))
        assertEquals(listOf("c", "b.c", "c"), commands.map { it[it.indexOf("-a") + 1] })
    }

    @Test fun clearDeletesByServiceUntilNothingRemains() {
        val commands = mutableListOf<List<String>>()
        val results = ArrayDeque(listOf(CommandResult(0, "", ""), CommandResult(0, "", ""), CommandResult(44, "", "")))
        MacOSKeychainStore(
            "service",
            "account",
            executable,
            CommandRunner { args, _ ->
                commands += args
                results.removeFirst()
            },
        ).clear()
        assertEquals(3, commands.size)
        commands.forEach {
            assertEquals(listOf(executable.path, "delete-generic-password", "-s", credentialNamespace("service", "account")), it)
        }
        assertFailsWith<KeychainUnavailableException> { store(CommandResult(1, "", "")).clear() }
        store(CommandResult(44, "", "")).clear()
    }

    @Test fun clearGivesUpOnABackendThatNeverEmpties() {
        val error = assertFailsWith<KeychainUnavailableException> { store(CommandResult(0, "", "")).clear() }
        assertEquals(Reason.Failed, error.reason)
    }

    @Test fun absentExecutableFailsWithoutLaunching() {
        val directory = Files.createTempDirectory("keychain-missing-tool").toFile()
        try {
            val store =
                MacOSKeychainStore(
                    "test",
                    "test",
                    File(directory, "missing"),
                    CommandRunner { _, _ -> error("Must not launch") },
                )
            assertEquals(Reason.Unsupported, assertFailsWith<KeychainUnavailableException> { store.read("key") }.reason)
            assertEquals(Reason.Unsupported, assertFailsWith<KeychainUnavailableException> { store.clear() }.reason)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun taggedOutputPreservesHexPasswordsAndDecodesBinaryValues() {
        for (value in listOf("616263", "e7a798e5af86", "0x616263", "a \"quoted\" value")) {
            assertEquals(value, store(CommandResult(0, "", "password: \"$value\"\n")).read("key"))
        }
        assertEquals("秘密", store(CommandResult(0, "", "password: 0xE7A798E5AF86 \n")).read("key"))
        assertEquals("a\\b", store(CommandResult(0, "", "password: 0x615C62  \"a\\134b\"\n")).read("key"))
        assertEquals("", store(CommandResult(0, "", "password: \n")).read("key"))
    }

    @Test
    fun malformedOutputFailsWithoutDisclosingIt() {
        for (output in listOf(
            "sensitive",
            "password: unquoted",
            "password: 0x",
            "password: 0x1 ",
            "password: 0xGG ",
            "password: 0xFF ",
        )) {
            val error =
                assertFailsWith<KeychainUnavailableException> {
                    store(CommandResult(0, "", output + "\n")).read("key")
                }
            assertFalse(error.toString().contains(output))
            assertEquals(Reason.Corrupted, error.reason)
        }
    }

    private fun store(result: CommandResult) = MacOSKeychainStore("test", "test", executable, CommandRunner { _, _ -> result })
}
