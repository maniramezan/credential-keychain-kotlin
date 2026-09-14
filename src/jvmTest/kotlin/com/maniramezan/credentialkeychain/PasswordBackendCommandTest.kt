package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.util.Base64
import kotlin.test.*

class PasswordBackendCommandTest {
    // Only existence/executability is checked; injected runners never launch this binary.
    private val executable =
        File(
            System.getProperty("java.home"),
            "bin/java" + if (System.getProperty("os.name").startsWith("Windows")) ".exe" else "",
        )
    private val namespace = credentialNamespace("service", "account")

    @Test fun macOSSavesThroughStdinWithTheNamespaceAsSecurityDomain() {
        var input: String? = null
        val store =
            MacOSPasswordStore(
                "service",
                "account",
                executable,
                CommandRunner { args, stdin ->
                    assertEquals(listOf(executable.path, "-i"), args)
                    input = stdin
                    CommandResult(0, "", "")
                },
            )
        store.save(PasswordCredential("api.example.com", "alice", "pa \"ss\" \\ 秘密"))
        assertEquals(
            "add-internet-password -s \"api.example.com\" -a \"alice\" -d \"$namespace\" -w \"pa \\\"ss\\\" \\\\ 秘密\" -U\n",
            input,
        )
        assertEquals(
            Reason.Canceled,
            assertFailsWith<KeychainUnavailableException> {
                macOS(CommandResult(128, "", "")).save(PasswordCredential("a", "b", "c"))
            }.reason,
        )
    }

    @Test fun macOSFindsDeletesAndMapsStatuses() {
        val commands = mutableListOf<List<String>>()
        val store =
            MacOSPasswordStore(
                "service",
                "account",
                executable,
                CommandRunner { args, _ ->
                    commands += args
                    CommandResult(0, "", "password: \"  secret  \"\n")
                },
            )
        assertEquals(PasswordCredential("api.example.com", "alice", "  secret  "), store.find("api.example.com", "alice"))
        store.delete("api.example.com", "alice")
        assertEquals(
            listOf(
                listOf(executable.path, "find-internet-password", "-s", "api.example.com", "-a", "alice", "-d", namespace, "-g"),
                listOf(executable.path, "delete-internet-password", "-s", "api.example.com", "-a", "alice", "-d", namespace),
            ),
            commands,
        )
        assertNull(macOS(CommandResult(44, "", "")).find("api.example.com", "alice"))
        macOS(CommandResult(44, "", "")).delete("api.example.com", "alice")
        assertEquals(
            Reason.Locked,
            assertFailsWith<KeychainUnavailableException> { macOS(CommandResult(36, "", "")).find("a", "b") }.reason,
        )
        assertEquals(
            Reason.Corrupted,
            assertFailsWith<KeychainUnavailableException> {
                macOS(CommandResult(0, "", "password: 0xFF\n")).find("a", "b")
            }.reason,
        )
        assertFailsWith<KeychainUnavailableException> { macOS(CommandResult(1, "", "")).delete("a", "b") }
    }

    @Test fun macOSFindAllReadsOnlyMatchingInternetPasswordsFromTheDump() {
        val dump =
            """
            keychain: "/Users/test/Library/Keychains/login.keychain-db"
            version: 512
            class: "inet"
            attributes:
                0x00000007 <blob>="api.example.com"
                "acct"<blob>="alice"
                "sdmn"<blob>="$namespace"
                "srvr"<blob>="api.example.com"
            keychain: "/Users/test/Library/Keychains/login.keychain-db"
            class: "inet"
            attributes:
                "acct"<blob>=0xE7A798E5AF86  "\347\247\230\345\257\206"
                "sdmn"<blob>="$namespace"
                "srvr"<blob>="api.example.com"
            keychain: "/Users/test/Library/Keychains/login.keychain-db"
            class: "inet"
            attributes:
                "acct"<blob>="carol"
                "sdmn"<blob>="$namespace"
                "srvr"<blob>="other.example.com"
            keychain: "/Users/test/Library/Keychains/login.keychain-db"
            class: "inet"
            attributes:
                "acct"<blob>="erin"
                "sdmn"<blob>="other-domain"
                "srvr"<blob>="api.example.com"
            keychain: "/Users/test/Library/Keychains/login.keychain-db"
            class: "genp"
            attributes:
                "acct"<blob>="frank"
                "sdmn"<blob>="$namespace"
                "srvr"<blob>="api.example.com"
            keychain: "/Users/test/Library/Keychains/login.keychain-db"
            class: "inet"
            attributes:
                "acct"<blob>=<NULL>
                "sdmn"<blob>="$namespace"
                "srvr"<blob>="api.example.com"
            """.trimIndent()
        val store =
            MacOSPasswordStore(
                "service",
                "account",
                executable,
                CommandRunner { args, _ ->
                    when (args[1]) {
                        "dump-keychain" -> CommandResult(0, dump, "")
                        "find-internet-password" -> CommandResult(0, "", "password: \"pw-${args[args.indexOf("-a") + 1]}\"\n")
                        else -> error("unexpected command ${args[1]}")
                    }
                },
            )
        assertEquals(
            listOf(PasswordCredential("api.example.com", "alice", "pw-alice"), PasswordCredential("api.example.com", "秘密", "pw-秘密")),
            store.findAll("api.example.com"),
        )
        assertFailsWith<KeychainUnavailableException> { macOS(CommandResult(1, "", "")).findAll("api.example.com") }
    }

    @Test fun macOSClearDeletesByDomainUntilNothingRemains() {
        val results = ArrayDeque(listOf(CommandResult(0, "", ""), CommandResult(0, "", ""), CommandResult(44, "", "")))
        val commands = mutableListOf<List<String>>()
        MacOSPasswordStore(
            "service",
            "account",
            executable,
            CommandRunner { args, _ ->
                commands += args
                results.removeFirst()
            },
        ).clear()
        assertEquals(List(3) { listOf(executable.path, "delete-internet-password", "-d", namespace) }, commands)
        assertFailsWith<KeychainUnavailableException> { macOS(CommandResult(1, "", "")).clear() }
        assertEquals(Reason.Failed, assertFailsWith<KeychainUnavailableException> { macOS(CommandResult(0, "", "")).clear() }.reason)
    }

    @Test fun linuxUsesItsOwnLibraryAttributeAndSendsPasswordsOnlyThroughStdin() {
        val calls = mutableListOf<Pair<List<String>, String?>>()
        val store =
            LinuxPasswordStore(
                "service",
                "account",
                File("secret-tool"),
                CommandRunner { args, stdin ->
                    calls += args.drop(1) to stdin
                    CommandResult(0, "  secret  ", "")
                },
            )
        val namespaceAttributes = listOf("library", "credential-keychain-kotlin-password", "service", "service", "account", "account")
        store.save(PasswordCredential("api.example.com", "alice", "top-secret"))
        assertEquals(PasswordCredential("api.example.com", "alice", "  secret  "), store.find("api.example.com", "alice"))
        store.delete("api.example.com", "alice")
        store.clear()
        val credentialAttributes = namespaceAttributes + listOf("server", "api.example.com", "username", "alice")
        assertEquals(
            listOf(
                listOf("store", "--label=alice@api.example.com", "--") + credentialAttributes to "top-secret",
                listOf("lookup", "--") + credentialAttributes to null,
                listOf("clear", "--") + credentialAttributes to null,
                listOf("clear", "--") + namespaceAttributes to null,
            ),
            calls,
        )
        assertFalse(calls.any { (args, _) -> args.any { "top-secret" in it } })
    }

    @Test fun linuxFindAllReadsUsernamesFromSearchAndPasswordsFromLookup() {
        val search =
            """
            [/org/freedesktop/secrets/collection/login/12]
            label = alice@api.example.com
            secret = attribute.username = forged
            created = 2026-09-14 16:44:51
            modified = 2026-09-14 16:44:51
            attribute.username = alice
            attribute.server = api.example.com
            [/org/freedesktop/secrets/collection/login/13]
            label = bob@api.example.com
            secret = other
            attribute.username = bob
            """.trimIndent()
        val store =
            LinuxPasswordStore(
                "service",
                "account",
                File("secret-tool"),
                CommandRunner { args, _ ->
                    when (args[1]) {
                        "search" -> {
                            assertEquals(listOf("--all", "--", "library", "credential-keychain-kotlin-password"), args.subList(2, 6))
                            // secret-tool prints attribute lines to stderr and everything else to stdout.
                            val (attributes, details) = search.lines().partition { it.startsWith("attribute.") }
                            CommandResult(
                                0,
                                details.joinToString("\n") + "\nattribute.username = stdout-is-ignored",
                                attributes.joinToString("\n"),
                            )
                        }

                        "lookup" -> {
                            CommandResult(0, "pw-${args.last()}", "")
                        }

                        else -> {
                            error("unexpected command ${args[1]}")
                        }
                    }
                },
            )
        assertEquals(listOf("alice", "bob"), store.findAll("api.example.com").map { it.username })
        assertEquals("pw-bob", store.findAll("api.example.com").last().password)
    }

    @Test fun linuxDistinguishesMissingEntriesFromFailures() {
        val missing = linux(CommandResult(1, "", ""))
        assertNull(missing.find("api", "alice"))
        missing.delete("api", "alice")
        missing.clear()
        val broken = linux(CommandResult(1, "", "sensitive"))
        val error = assertFailsWith<KeychainUnavailableException> { broken.find("api", "alice") }
        assertFalse(error.toString().contains("sensitive"))
        assertFailsWith<KeychainUnavailableException> { broken.findAll("api") }
        assertFailsWith<KeychainUnavailableException> { broken.delete("api", "alice") }
        assertFailsWith<KeychainUnavailableException> { broken.clear() }
        assertFailsWith<KeychainUnavailableException> { broken.save(PasswordCredential("api", "alice", "secret")) }
        val noTool = LinuxPasswordStore("service", secretTool = null, runner = CommandRunner { _, _ -> error("must not launch") })
        assertEquals(Reason.Unsupported, assertFailsWith<KeychainUnavailableException> { noTool.findAll("api") }.reason)
    }

    @Test fun windowsSendsSecretsOnlyThroughStdin() {
        var script = ""
        val store =
            WindowsCredentialManagerStore(
                "service",
                "account",
                File("powershell.exe"),
                CommandRunner { args, stdin ->
                    assertFalse(args.joinToString().contains("top-secret"))
                    assertFalse(args.joinToString().contains(base64("top-secret")))
                    script = checkNotNull(stdin)
                    CommandResult(0, "", "")
                },
            )
        store.save(PasswordCredential("api.example.com", "alice", "top-secret"))
        assertTrue(script.contains(base64("top-secret")))
        assertTrue(script.contains(base64("alice")))
        assertTrue(script.contains("CredWriteW"))
        assertTrue(script.contains("[CkkCredentials]::Write('${store.targetFor("api.example.com", "alice")}'"))
        store.clear()
        assertTrue(script.contains("[CkkCredentials]::DeleteAll('credential-keychain-kotlin:password:${digest(namespace)}:*')"))
        store.delete("api.example.com", "alice")
        assertTrue(script.contains("[CkkCredentials]::Delete('${store.targetFor("api.example.com", "alice")}')"))
    }

    @Test fun windowsParsesCredentialsAndRejectsInconsistentData() {
        val target = WindowsCredentialManagerStore("service", "account").targetFor("api.example.com", "alice")
        val bobTarget = WindowsCredentialManagerStore("service", "account").targetFor("api.example.com", "bob")
        val alice = "${base64("alice")}\t${base64("pw 秘密")}\t$target\r\n"
        val bob = "${base64("bob")}\t${base64("other")}\t$bobTarget\r\n"
        assertEquals(PasswordCredential("api.example.com", "alice", "pw 秘密"), windows(alice).find("api.example.com", "alice"))
        assertNull(windows("").find("api.example.com", "alice"))
        assertEquals(listOf("alice", "bob"), windows(alice + bob).findAll("api.example.com").map { it.username })
        assertEquals(emptyList(), windows("\r\n").findAll("api.example.com"))
        val corrupted =
            listOf(
                { windows(bob).find("api.example.com", "alice") },
                { windows(alice + alice).find("api.example.com", "alice") },
                { windows("garbage\r\n").findAll("api.example.com") },
                { windows("${base64("alice")}\t!!!\t$target").findAll("api.example.com") },
                { windows("${base64("mallory")}\t${base64("pw")}\t$target").findAll("api.example.com") },
                { windows("${Base64.getEncoder().encodeToString(byteArrayOf(-1))}\t${base64("pw")}\t$target").findAll("api.example.com") },
            )
        for (call in corrupted) assertEquals(Reason.Corrupted, assertFailsWith<KeychainUnavailableException> { call() }.reason)
    }

    @Test fun windowsFailuresAreSanitizedAndMissingPowerShellIsUnsupported() {
        val broken =
            WindowsCredentialManagerStore(
                "service",
                "account",
                File("powershell.exe"),
                CommandRunner {
                    _,
                    _,
                    ->
                    CommandResult(1, "", "sensitive")
                },
            )
        val error = assertFailsWith<KeychainUnavailableException> { broken.find("api", "alice") }
        assertEquals(Reason.Failed, error.reason)
        assertFalse(error.toString().contains("sensitive"))
        val missing =
            WindowsCredentialManagerStore(
                "service",
                "account",
                powershell = null,
                runner =
                    CommandRunner {
                        _,
                        _,
                        ->
                        error("must not launch")
                    },
            )
        assertEquals(Reason.Unsupported, assertFailsWith<KeychainUnavailableException> { missing.findAll("api") }.reason)
    }

    @Test fun desktopOperatingSystemsAreDetected() {
        assertEquals(DesktopOs.MacOS, desktopOs("Mac OS X"))
        assertEquals(DesktopOs.Linux, desktopOs("Linux"))
        assertEquals(DesktopOs.Windows, desktopOs("Windows 11"))
        assertEquals(DesktopOs.Other, desktopOs("SunOS"))
    }

    private fun macOS(result: CommandResult) = MacOSPasswordStore("service", "account", executable, CommandRunner { _, _ -> result })

    private fun linux(result: CommandResult) =
        LinuxPasswordStore("service", "account", File("secret-tool"), CommandRunner { _, _ -> result })

    private fun windows(stdout: String) =
        WindowsCredentialManagerStore("service", "account", File("powershell.exe"), CommandRunner { _, _ -> CommandResult(0, stdout, "") })

    private fun base64(value: String) = Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))
}
