package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File

/**
 * Backs [CredentialKeychain] with the macOS login keychain via the `/usr/bin/security` CLI.
 * Items use the service/account namespace as their service attribute and the entry key as
 * their account attribute, so [clear] can remove the whole namespace by service.
 */
internal class MacOSKeychainStore(
    serviceName: String,
    accountName: String,
    private val securityTool: File = File(SECURITY_TOOL_PATH),
    private val runner: CommandRunner = systemCommandRunner,
) : CredentialKeychain {
    private val namespace = credentialNamespace(serviceName, accountName)

    override fun read(key: String): String? {
        val result = runSecurityCommand("find-generic-password", "-s", namespace, "-a", key, "-g")
        return when {
            result.exitCode == 0 -> result.stderr.decodeSecurityOutput()
            result.isMissingEntry -> null
            else -> throw statusFailure(result.exitCode)
        }
    }

    override fun write(
        key: String,
        value: String,
    ) {
        require("\n" !in value && "\r" !in value) { "Credential values must not contain line breaks." }
        // The secret is piped to `security -i` on stdin instead of being passed as a
        // process argument, where it would be visible to other local processes via `ps`.
        val command = "add-generic-password -s ${quote(namespace)} -a ${quote(key)} -w ${quote(value)} -U\n"
        val result = runSecurityCommand("-i", stdin = command)
        if (result.exitCode != 0) throw statusFailure(result.exitCode)
    }

    override fun delete(key: String) {
        val result = runSecurityCommand("delete-generic-password", "-s", namespace, "-a", key)
        if (result.exitCode != 0 && !result.isMissingEntry) throw statusFailure(result.exitCode)
    }

    override fun clear() {
        // Each call deletes one matching item; repeat until the namespace is empty.
        repeat(MAX_CLEAR_ITERATIONS) {
            val result = runSecurityCommand("delete-generic-password", "-s", namespace)
            if (result.isMissingEntry) return
            if (result.exitCode != 0) throw statusFailure(result.exitCode)
        }
        throw commandFailure("macOS Keychain clear did not finish")
    }

    private fun runSecurityCommand(
        vararg args: String,
        stdin: String? = null,
    ): CommandResult {
        if (!securityTool.canExecute()) throw KeychainUnavailableException(Reason.Unsupported, "macOS security tool is missing")
        return runner.run(listOf(securityTool.path) + args, stdin)
    }

    /** `security` exits with the low byte of the failing OSStatus. */
    private fun statusFailure(exitCode: Int): KeychainUnavailableException {
        val reason = if (exitCode in LOCKED_EXIT_CODES) Reason.Locked else Reason.Failed
        return KeychainUnavailableException(reason, "macOS security exited with $exitCode")
    }

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

    private fun invalidOutput() = KeychainUnavailableException(Reason.Corrupted, "macOS security returned invalid data")

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
        /** errSecItemNotFound (-25300). */
        const val ERR_SEC_ITEM_NOT_FOUND = 44

        /** errSecInteractionNotAllowed (-25308), errSecAuthFailed (-25293), errSecUserCanceled (-128). */
        val LOCKED_EXIT_CODES = setOf(36, 51, 128)
        const val SECURITY_TOOL_PATH = "/usr/bin/security"
    }
}
