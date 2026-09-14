package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason

/**
 * Backs [CredentialKeychain] with the Linux Secret Service (GNOME Keyring / KWallet) via
 * `secret-tool`. Items carry `library`, `service`, `account`, and `key` attributes; the
 * `library` marker keeps [clear] from matching other applications' items that happen to use
 * the same service/account attribute values.
 */
internal class LinuxKeyringStore(
    private val serviceName: String,
    private val accountName: String = serviceName,
    private val secretTool: java.io.File? = findExecutable("secret-tool"),
    private val runner: CommandRunner = systemCommandRunner,
) : CredentialKeychain {
    private val label = "$serviceName credential"

    override fun read(key: String): String? {
        val result = run("lookup", "--", *namespaceAttributes(), "key", key)
        return when {
            result.exitCode == 0 -> result.stdout
            result.isMissingEntry -> null
            else -> throw failure(result)
        }
    }

    override fun write(
        key: String,
        value: String,
    ) {
        requireTool()
        require(value.toByteArray(Charsets.UTF_8).size < MAX_VALUE_BYTES) { "Linux credentials must be smaller than 8 KiB." }
        val result = run("store", "--label=$label", "--", *namespaceAttributes(), "key", key, stdin = value)
        if (result.exitCode != 0) throw failure(result)
    }

    override fun delete(key: String) {
        val result = run("clear", "--", *namespaceAttributes(), "key", key)
        if (result.exitCode != 0 && !result.isMissingEntry) throw failure(result)
    }

    /** `secret-tool clear` removes every item matching the given attributes in one call. */
    override fun clear() {
        val result = run("clear", "--", *namespaceAttributes())
        if (result.exitCode != 0 && !result.isMissingEntry) throw failure(result)
    }

    private fun namespaceAttributes() = arrayOf("library", LIBRARY_ATTRIBUTE, "service", serviceName, "account", accountName)

    private fun requireTool(): java.io.File =
        secretTool ?: throw KeychainUnavailableException(Reason.Unsupported, "Linux secret-tool is not installed")

    private fun run(
        vararg args: String,
        stdin: String? = null,
    ): CommandResult = runner.run(listOf(requireTool().absolutePath) + args, stdin)

    /** `secret-tool` exits with 1 and no diagnostics when nothing matches. */
    private val CommandResult.isMissingEntry: Boolean
        get() = exitCode == 1 && stderr.isBlank()

    private fun failure(result: CommandResult) = commandFailure("secret-tool exited with ${result.exitCode}")

    private companion object {
        const val LIBRARY_ATTRIBUTE = "credential-keychain-kotlin"
        const val MAX_VALUE_BYTES = 8192
    }
}
