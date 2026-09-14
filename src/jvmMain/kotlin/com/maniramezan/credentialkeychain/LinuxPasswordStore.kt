package com.maniramezan.credentialkeychain

import java.io.File

/**
 * Backs [PasswordStore] with the Linux Secret Service via `secret-tool`. Items carry `library`,
 * `service`, `account`, `server`, and `username` attributes. The `library` value differs from
 * [LinuxKeyringStore]'s, so clearing either store never removes the other's items.
 */
internal class LinuxPasswordStore(
    private val serviceName: String,
    private val accountName: String = serviceName,
    secretTool: File? = findExecutable("secret-tool"),
    runner: CommandRunner = systemCommandRunner,
) : PasswordStore {
    private val tool = SecretTool(secretTool, runner)

    override fun save(credential: PasswordCredential) {
        val result =
            tool.run(
                "store",
                "--label=${credential.username}@${credential.server}",
                "--",
                *attributes(credential.server, credential.username),
                stdin = credential.password,
            )
        if (result.exitCode != 0) throw tool.failure(result)
    }

    override fun find(
        server: String,
        username: String,
    ): PasswordCredential? {
        val result = tool.run("lookup", "--", *attributes(server, username))
        return when {
            result.exitCode == 0 -> PasswordCredential(server, username, result.stdout)
            result.isSecretToolMissingEntry -> null
            else -> throw tool.failure(result)
        }
    }

    /** Lists usernames with `search`, then reads each password with `lookup` for exact bytes. */
    override fun findAll(server: String): List<PasswordCredential> {
        val result = tool.run("search", "--all", "--", *attributes(server, username = null))
        if (result.exitCode != 0) throw tool.failure(result)
        return usernamesIn(result.stdout).distinct().mapNotNull { find(server, it) }
    }

    override fun delete(
        server: String,
        username: String,
    ) {
        val result = tool.run("clear", "--", *attributes(server, username))
        if (result.exitCode != 0 && !result.isSecretToolMissingEntry) throw tool.failure(result)
    }

    override fun clear() {
        val result = tool.run("clear", "--", *attributes(server = null, username = null))
        if (result.exitCode != 0 && !result.isSecretToolMissingEntry) throw tool.failure(result)
    }

    private fun attributes(
        server: String?,
        username: String?,
    ): Array<String> =
        buildList {
            addAll(listOf("library", LIBRARY_ATTRIBUTE, "service", serviceName, "account", accountName))
            if (server != null) addAll(listOf("server", server))
            if (username != null) addAll(listOf("username", username))
        }.toTypedArray()

    /**
     * `search` prints each item's secret before its `attribute.*` lines. Passwords saved through
     * this library cannot contain line breaks, so a secret cannot forge an attribute line.
     */
    internal fun usernamesIn(output: String): List<String> =
        output
            .lineSequence()
            .filter { it.startsWith(USERNAME_PREFIX) }
            .map { it.removePrefix(USERNAME_PREFIX) }
            .toList()

    private companion object {
        const val LIBRARY_ATTRIBUTE = "credential-keychain-kotlin-password"
        const val USERNAME_PREFIX = "attribute.username = "
    }
}
