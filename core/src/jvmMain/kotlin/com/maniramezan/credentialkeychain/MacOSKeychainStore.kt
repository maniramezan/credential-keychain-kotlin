package com.maniramezan.credentialkeychain

import java.io.File

/**
 * Backs [CredentialKeychain] with the macOS login keychain via the `/usr/bin/security` CLI.
 * Items use the service/account namespace as their service attribute and the entry key as
 * their account attribute, so [clear] can remove the whole namespace by service.
 */
internal class MacOSKeychainStore(
    serviceName: String,
    accountName: String,
    securityTool: File = File(SecurityTool.DEFAULT_PATH),
    runner: CommandRunner = systemCommandRunner,
) : CredentialKeychain {
    private val tool = SecurityTool(securityTool, runner)
    private val namespace = credentialNamespace(serviceName, accountName)

    override fun read(key: String): String? {
        val result = tool.run("find-generic-password", "-s", namespace, "-a", key, "-g")
        return when {
            result.exitCode == 0 -> tool.decodePassword(result.stderr)
            result.isSecurityItemNotFound -> null
            else -> throw tool.failure(result.exitCode)
        }
    }

    override fun write(
        key: String,
        value: String,
    ) {
        require("\n" !in value && "\r" !in value) { "Credential values must not contain line breaks." }
        // The secret is piped to `security -i` on stdin instead of being passed as a
        // process argument, where it would be visible to other local processes via `ps`.
        val q = SecurityTool::quote
        val result = tool.run("-i", stdin = "add-generic-password -s ${q(namespace)} -a ${q(key)} -w ${q(value)} -U\n")
        if (result.exitCode != 0) throw tool.failure(result.exitCode)
    }

    override fun delete(key: String) {
        val result = tool.run("delete-generic-password", "-s", namespace, "-a", key)
        if (result.exitCode != 0 && !result.isSecurityItemNotFound) throw tool.failure(result.exitCode)
    }

    override fun clear() {
        // Each call deletes one matching item; repeat until the namespace is empty.
        repeat(MAX_CLEAR_ITERATIONS) {
            val result = tool.run("delete-generic-password", "-s", namespace)
            if (result.isSecurityItemNotFound) return
            if (result.exitCode != 0) throw tool.failure(result.exitCode)
        }
        throw commandFailure("macOS Keychain clear did not finish")
    }
}
