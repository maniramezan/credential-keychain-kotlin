package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File

/** Runs the macOS `/usr/bin/security` tool and interprets its exit codes and value output. */
internal class SecurityTool(
    private val executable: File,
    private val runner: CommandRunner,
) {
    fun run(
        vararg args: String,
        stdin: String? = null,
    ): CommandResult {
        if (!executable.canExecute()) throw KeychainUnavailableException(Reason.Unsupported, "macOS security tool is missing")
        return runner.run(listOf(executable.path) + args, stdin)
    }

    /** `security` exits with the low byte of the failing OSStatus. */
    fun failure(exitCode: Int): KeychainUnavailableException {
        val reason =
            when (exitCode) {
                USER_CANCELED_EXIT_CODE -> Reason.Canceled
                in LOCKED_EXIT_CODES -> Reason.Locked
                else -> Reason.Failed
            }
        return KeychainUnavailableException(reason, "macOS security exited with $exitCode")
    }

    /** Parses the `password: ...` line that `-g` writes to stderr. */
    fun decodePassword(output: String): String {
        val line = output.removeTrailingLineBreaks()
        if (!line.startsWith("password: ")) throw invalidOutput()
        return decodeValue(line.removePrefix("password: ")) ?: throw invalidOutput()
    }

    private fun invalidOutput() = KeychainUnavailableException(Reason.Corrupted, "macOS security returned invalid data")

    companion object {
        /** errSecItemNotFound (-25300). */
        const val ITEM_NOT_FOUND_EXIT_CODE = 44
        const val DEFAULT_PATH = "/usr/bin/security"

        /** errSecInteractionNotAllowed (-25308), errSecAuthFailed (-25293). */
        private val LOCKED_EXIT_CODES = setOf(36, 51)

        /** errSecUserCanceled (-128). */
        private const val USER_CANCELED_EXIT_CODE = 128

        /** Quotes a value for the `security -i` interactive command parser. */
        fun quote(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

        /**
         * Decodes a value as printed by `-g` or `dump-keychain`: empty, `"quoted"`, or a `0x…`
         * hex form (optionally followed by a quoted rendering). The hex form is used for
         * non-ASCII data, and `-w` output would be ambiguous for hex-looking secrets.
         * Returns `null` for anything else, including `<NULL>`.
         */
        fun decodeValue(payload: String): String? {
            if (payload.isEmpty()) return ""
            if (payload.length >= 2 && payload.startsWith('"') && payload.endsWith('"')) {
                return payload.substring(1, payload.lastIndex)
            }
            if (!payload.startsWith("0x")) return null
            val hex = payload.removePrefix("0x").substringBefore(' ')
            if (hex.isEmpty() || hex.length % 2 != 0 || hex.any { it !in "0123456789abcdefABCDEF" }) return null
            return ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }.decodeStrictUtf8()
        }
    }
}

internal val CommandResult.isSecurityItemNotFound: Boolean
    get() = exitCode == SecurityTool.ITEM_NOT_FOUND_EXIT_CODE
