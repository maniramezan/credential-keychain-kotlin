package dev.amoo.credentialkeychain

import java.io.File

/** Backs [CredentialKeychain] with the macOS Keychain via the `/usr/bin/security` CLI. */
internal class MacOSKeychainStore(
    serviceName: String,
    private val accountName: String,
    private val securityTool: File = File(SECURITY_TOOL_PATH),
    private val runner: CommandRunner = systemCommandRunner,
) : CredentialKeychain {
    private val servicePrefix = serviceName

    override fun read(key: String): String? {
        val result = runSecurityCommand("find-generic-password", "-a", accountName, "-s", serviceName(key), "-w")
        return when {
            result.exitCode == 0 -> result.stdout.removeTrailingLineBreaks()
            result.isMissingEntry -> null
            else -> throw KeychainUnavailableException("macOS security exited with ${result.exitCode}")
        }
    }

    override fun write(key: String, value: String) {
        if (value.isBlank()) {
            delete(key)
            return
        }
        require("\n" !in value && "\r" !in value) { "Credential values must not contain line breaks." }
        // The secret is piped to `security -i` on stdin instead of being passed as a
        // process argument, where it would be visible to other local processes via `ps`.
        val command = "add-generic-password -a ${quote(accountName)} -s ${quote(serviceName(key))} -w ${quote(value)} -U\n"
        val result = runSecurityCommand("-i", stdin = command)
        if (result.exitCode != 0) throw KeychainUnavailableException("macOS security exited with ${result.exitCode}")
    }

    override fun delete(key: String) {
        val result = runSecurityCommand("delete-generic-password", "-a", accountName, "-s", serviceName(key))
        if (result.exitCode != 0 && !result.isMissingEntry) {
            throw KeychainUnavailableException("macOS security exited with ${result.exitCode}")
        }
    }

    private fun runSecurityCommand(vararg args: String, stdin: String? = null): CommandResult {
        if (!securityTool.canExecute()) throw KeychainUnavailableException("macOS security tool is missing")
        return runner.run(listOf(securityTool.path) + args, stdin)
    }

    private fun serviceName(key: String): String = credentialNamespace(servicePrefix, key)

    /** Quotes a value for the `security -i` interactive command parser. */
    private fun quote(value: String): String {
        val escaped = value.replace("\\", "\\\\").replace("\"", "\\\"")
        return "\"$escaped\""
    }

    private val CommandResult.isMissingEntry: Boolean
        get() = exitCode == ERR_SEC_ITEM_NOT_FOUND

    private companion object {
        /** `security` exits with 44 (errSecItemNotFound) when no matching keychain entry exists. */
        const val ERR_SEC_ITEM_NOT_FOUND = 44
        const val SECURITY_TOOL_PATH = "/usr/bin/security"
    }
}
