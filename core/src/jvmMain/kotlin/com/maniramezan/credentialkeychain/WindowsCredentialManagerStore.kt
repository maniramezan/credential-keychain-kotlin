package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason

/**
 * Backs [PasswordStore] with Windows Credential Manager generic credentials for the current
 * user, through in-process `CredWriteW`, `CredReadW`, `CredEnumerateW`, and `CredDeleteW` calls.
 * Target names are `credential-keychain-kotlin:password:<namespace>:<server>:<username>` with
 * each component SHA-256 hashed; the username is stored in the credential's user-name field and
 * the password as a UTF-8 blob.
 */
internal class WindowsCredentialManagerStore(
    serviceName: String,
    accountName: String = serviceName,
    private val windowsApi: () -> WindowsApi = ::systemWindowsApi,
) : PasswordStore {
    private val prefix = "credential-keychain-kotlin:password:${digest(credentialNamespace(serviceName, accountName))}:"

    override fun save(credential: PasswordCredential) =
        credentials { api ->
            val secret = credential.password.toByteArray(Charsets.UTF_8)
            try {
                api.writeCredential(targetFor(credential.server, credential.username), credential.username, secret)
            } finally {
                secret.fill(0)
            }
        }

    override fun find(
        server: String,
        username: String,
    ): PasswordCredential? =
        credentials { api ->
            api.readCredential(targetFor(server, username))?.let { decode(it, server) }?.also {
                if (it.username != username) throw corrupted()
            }
        }

    override fun findAll(server: String): List<PasswordCredential> =
        credentials { api -> api.enumerateCredentials("$prefix${digest(server)}:*").map { decode(it, server) } }

    override fun delete(
        server: String,
        username: String,
    ) = credentials { it.deleteCredential(targetFor(server, username)) }

    override fun clear() = credentials { api -> api.enumerateCredentials("$prefix*").forEach { api.deleteCredential(it.target) } }

    internal fun targetFor(
        server: String,
        username: String,
    ): String = "$prefix${digest(server)}:${digest(username)}"

    /** The target must match the stored username, and the blob must be strict UTF-8. */
    private fun decode(
        credential: WindowsCredential,
        server: String,
    ): PasswordCredential {
        try {
            if (credential.target != targetFor(server, credential.userName)) throw corrupted()
            val password = credential.secret.decodeStrictUtf8() ?: throw corrupted()
            return PasswordCredential(server, credential.userName, password)
        } finally {
            credential.secret.fill(0)
        }
    }

    private fun corrupted() = KeychainUnavailableException(Reason.Corrupted, "Windows Credential Manager returned invalid data")

    private inline fun <T> credentials(block: (WindowsApi) -> T): T =
        windowsCall(windowsApi, "Windows Credential Manager operation failed", block)
}
