package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File

/**
 * Backs [CredentialKeychain] with the Linux Secret Service (GNOME Keyring / KWallet) via
 * `secret-tool`. Items carry `library`, `service`, `account`, and `key` attributes; the
 * `library` marker keeps [clear] from matching other applications' items that happen to use
 * the same service/account attribute values.
 */
internal class LinuxKeyringStore(
    private val serviceName: String,
    private val accountName: String = serviceName,
    secretTool: File? = findExecutable("secret-tool"),
    runner: CommandRunner = systemCommandRunner,
) : CredentialKeychain {
    private val tool = SecretTool(secretTool, runner)
    private val label = "$serviceName credential"

    override fun read(key: String): String? {
        val result = tool.run("lookup", "--", *namespaceAttributes(), "key", key)
        return when {
            result.exitCode == 0 -> result.stdout
            result.isSecretToolMissingEntry -> null
            else -> throw tool.failure(result)
        }
    }

    override fun write(
        key: String,
        value: String,
    ) {
        tool.requireExecutable()
        require(value.toByteArray(Charsets.UTF_8).size < SecretTool.MAX_VALUE_BYTES) { "Linux credentials must be smaller than 8 KiB." }
        val result = tool.run("store", "--label=$label", "--", *namespaceAttributes(), "key", key, stdin = value)
        if (result.exitCode != 0) throw tool.failure(result)
    }

    override fun delete(key: String) {
        val result = tool.run("clear", "--", *namespaceAttributes(), "key", key)
        if (result.exitCode != 0 && !result.isSecretToolMissingEntry) throw tool.failure(result)
    }

    /** `secret-tool clear` removes every item matching the given attributes in one call. */
    override fun clear() {
        val result = tool.run("clear", "--", *namespaceAttributes())
        if (result.exitCode != 0 && !result.isSecretToolMissingEntry) throw tool.failure(result)
    }

    private fun namespaceAttributes() = arrayOf("library", LIBRARY_ATTRIBUTE, "service", serviceName, "account", accountName)

    private companion object {
        const val LIBRARY_ATTRIBUTE = "credential-keychain-kotlin"
    }
}

/** Runs `secret-tool`; backend diagnostics are never included in exceptions. */
internal class SecretTool(
    private val executable: File?,
    private val runner: CommandRunner,
) {
    fun requireExecutable(): File =
        executable ?: throw KeychainUnavailableException(Reason.Unsupported, "Linux secret-tool is not installed")

    fun run(
        vararg args: String,
        stdin: String? = null,
    ): CommandResult = runner.run(listOf(requireExecutable().absolutePath) + args, stdin)

    fun failure(result: CommandResult) = commandFailure("secret-tool exited with ${result.exitCode}")

    companion object {
        /** Commonly deployed `secret-tool` versions read at most this much stdin. */
        const val MAX_VALUE_BYTES = 8192
    }
}

/** `secret-tool` exits with 1 and no diagnostics when nothing matches. */
internal val CommandResult.isSecretToolMissingEntry: Boolean
    get() = exitCode == 1 && stderr.isBlank()
