package com.maniramezan.credentialkeychain

import java.io.File

/**
 * Backs [PasswordStore] with internet-password items in the macOS login keychain via
 * `/usr/bin/security`, using the same layout as the native Apple store: security domain is the
 * service/account namespace, server is the credential's server, account is its username.
 * [findAll] lists matching items from `security dump-keychain`, which prints attributes only.
 */
internal class MacOSPasswordStore(
    serviceName: String,
    accountName: String,
    securityTool: File = File(SecurityTool.DEFAULT_PATH),
    runner: CommandRunner = systemCommandRunner,
) : PasswordStore {
    private val tool = SecurityTool(securityTool, runner)
    private val namespace = credentialNamespace(serviceName, accountName)

    override fun save(credential: PasswordCredential) {
        // Only stdin carries the password; see MacOSKeychainStore.write.
        val q = SecurityTool::quote
        val command =
            "add-internet-password -s ${q(credential.server)} -a ${q(credential.username)} " +
                "-d ${q(namespace)} -w ${q(credential.password)} -U\n"
        val result = tool.run("-i", stdin = command)
        if (result.exitCode != 0) throw tool.failure(result.exitCode)
    }

    override fun find(
        server: String,
        username: String,
    ): PasswordCredential? {
        val result = tool.run("find-internet-password", "-s", server, "-a", username, "-d", namespace, "-g")
        return when {
            result.exitCode == 0 -> PasswordCredential(server, username, tool.decodePassword(result.stderr))
            result.isSecurityItemNotFound -> null
            else -> throw tool.failure(result.exitCode)
        }
    }

    override fun findAll(server: String): List<PasswordCredential> {
        val result = tool.run("dump-keychain")
        if (result.exitCode != 0) throw tool.failure(result.exitCode)
        return accountsIn(result.stdout, server).distinct().mapNotNull { find(server, it) }
    }

    override fun delete(
        server: String,
        username: String,
    ) {
        val result = tool.run("delete-internet-password", "-s", server, "-a", username, "-d", namespace)
        if (result.exitCode != 0 && !result.isSecurityItemNotFound) throw tool.failure(result.exitCode)
    }

    override fun clear() {
        // Each call deletes one matching item; repeat until the namespace is empty.
        repeat(MAX_CLEAR_ITERATIONS) {
            val result = tool.run("delete-internet-password", "-d", namespace)
            if (result.isSecurityItemNotFound) return
            if (result.exitCode != 0) throw tool.failure(result.exitCode)
        }
        throw commandFailure("macOS Keychain clear did not finish")
    }

    /** Returns the account of every `inet` item in [dump] whose security domain and server match. */
    internal fun accountsIn(
        dump: String,
        server: String,
    ): List<String> {
        val accounts = mutableListOf<String>()
        var itemClass: String? = null
        val attributes = mutableMapOf<String, String?>()

        fun finishItem() {
            val account = attributes["acct"]
            if (itemClass == "inet" && attributes["sdmn"] == namespace && attributes["srvr"] == server && account != null) {
                accounts += account
            }
            itemClass = null
            attributes.clear()
        }
        for (line in dump.lineSequence()) {
            when {
                line.startsWith("keychain: ") -> {
                    finishItem()
                }

                line.startsWith("class: ") -> {
                    itemClass = SecurityTool.decodeValue(line.removePrefix("class: ").trim())
                }

                else -> {
                    ATTRIBUTE.matchEntire(line.trim())?.let {
                        attributes[it.groupValues[1]] =
                            SecurityTool.decodeValue(it.groupValues[2])
                    }
                }
            }
        }
        finishItem()
        return accounts
    }

    private companion object {
        val ATTRIBUTE = Regex("\"(acct|sdmn|srvr)\"<blob>=(.*)")
    }
}
