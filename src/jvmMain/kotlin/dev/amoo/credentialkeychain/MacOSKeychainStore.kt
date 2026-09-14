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
        val result = runSecurityCommand("find-generic-password", "-a", accountName, "-s", serviceName(key), "-g")
        return when {
            result.exitCode == 0 -> result.stderr.decodeSecurityOutput()
            result.isMissingEntry -> null
            else -> throw KeychainUnavailableException("macOS security exited with ${result.exitCode}")
        }
    }

    override fun write(
        key: String,
        value: String,
    ) {
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

    private fun runSecurityCommand(
        vararg args: String,
        stdin: String? = null,
    ): CommandResult {
        if (!securityTool.canExecute()) throw KeychainUnavailableException("macOS security tool is missing")
        return runner.run(listOf(securityTool.path) + args, stdin)
    }

    private fun serviceName(key: String): String = credentialNamespace(servicePrefix, key)

    /** The diagnostic form tags binary output with 0x; -w is ambiguous for hex-looking secrets. */
    private fun String.decodeSecurityOutput(): String {
        val output = removeTrailingLineBreaks()
        if (!output.startsWith("password: ")) throw invalidOutput()
        val payload = output.removePrefix("password: ")
        if (payload.isEmpty()) return ""
        if (payload.startsWith('"') && payload.endsWith('"') && payload.length >= 2) {
            return payload.substring(1, payload.lastIndex)
        }
        if (!payload.startsWith("0x")) throw invalidOutput()
        val hex = payload.removePrefix("0x").substringBefore(' ')
        if (hex.isEmpty() || hex.length % 2 != 0 || hex.any { it !in "0123456789abcdefABCDEF" }) {
            throw invalidOutput()
        }
        val bytes = ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        return bytes.decodeStrictUtf8() ?: throw invalidOutput()
    }

    private fun invalidOutput() = KeychainUnavailableException("macOS security returned invalid data")

    private fun ByteArray.decodeStrictUtf8(): String? {
        val decoder =
            Charsets.UTF_8
                .newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        return try {
            decoder.decode(java.nio.ByteBuffer.wrap(this)).toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            null
        }
    }

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
