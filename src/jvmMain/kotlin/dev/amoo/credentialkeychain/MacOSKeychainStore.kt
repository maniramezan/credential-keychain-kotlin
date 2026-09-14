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
            result.exitCode == 0 -> result.stdout.removeTrailingLineBreaks().decodeSecurityOutput()
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

    /**
     * macOS 26 hex-encodes `security -w` output whenever the stored password contains
     * non-ASCII bytes, instead of printing it raw as prior macOS versions did. Decode that
     * form back to text; ASCII-only values round-trip through `security` unchanged and are
     * returned as-is.
     */
    private fun String.decodeSecurityOutput(): String {
        if (isEmpty() || length % 2 != 0 || any { Character.digit(it, 16) < 0 }) return this
        val bytes = ByteArray(length / 2) { i ->
            ((Character.digit(this[i * 2], 16) shl 4) or Character.digit(this[i * 2 + 1], 16)).toByte()
        }
        return bytes.decodeStrictUtf8() ?: this
    }

    private fun ByteArray.decodeStrictUtf8(): String? {
        val decoder = Charsets.UTF_8.newDecoder()
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
