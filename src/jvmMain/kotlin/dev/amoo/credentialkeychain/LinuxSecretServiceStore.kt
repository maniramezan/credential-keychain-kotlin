package dev.amoo.credentialkeychain

/** Backs [CredentialKeychain] with the Linux Secret Service (GNOME Keyring / KWallet) via `secret-tool`. */
internal class LinuxSecretServiceStore(
    serviceName: String,
    private val accountName: String = serviceName,
    private val secretTool: java.io.File? = findExecutable("secret-tool"),
    private val runner: CommandRunner = systemCommandRunner,
) : CredentialKeychain {
    private val serviceName = serviceName
    private val secretLabel = "$serviceName credential"

    override fun read(key: String): String? {
        if (secretTool == null) throw KeychainUnavailableException("Linux (secret-tool is not installed)")
        val result = run("lookup", "--", "service", serviceName, "account", accountName, "key", key)
        return when (result.exitCode) {
            0 -> result.stdout
            1 -> if (result.stderr.isBlank()) null else throw failure(result)
            else -> throw failure(result)
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
        if (secretTool == null) throw KeychainUnavailableException("Linux (secret-tool is not installed)")
        require(value.toByteArray(Charsets.UTF_8).size < 8192) { "Linux credentials must be smaller than 8 KiB." }
        val result = run("store", "--label=$secretLabel", "--", "service", serviceName, "account", accountName, "key", key, stdin = value)
        if (result.exitCode != 0) throw failure(result)
    }

    override fun delete(key: String) {
        if (secretTool == null) throw KeychainUnavailableException("Linux (secret-tool is not installed)")
        val result = run("clear", "--", "service", serviceName, "account", accountName, "key", key)
        if (result.exitCode != 0 && !(result.exitCode == 1 && result.stderr.isBlank())) throw failure(result)
    }

    private fun run(
        vararg args: String,
        stdin: String? = null,
    ): CommandResult {
        val executable = checkNotNull(secretTool)
        return runner.run(listOf(executable.absolutePath) + args, stdin)
    }

    private fun failure(result: CommandResult): IllegalStateException =
        KeychainUnavailableException("secret-tool exited with ${result.exitCode}")
}
