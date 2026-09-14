package com.maniramezan.credentialkeychain

import android.content.Context
import android.util.AtomicFile
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File

/**
 * Creates an app-private password store isolated by [serviceName] and [accountName], encrypted
 * with its own non-exportable Android Keystore AES-256-GCM key. Like the `CredentialKeychain`
 * overload, ciphertext lives under [Context.getNoBackupFilesDir] and is excluded from backup.
 *
 * `context` is retained only as [Context.getApplicationContext].
 *
 * ```kotlin
 * val passwords = PasswordStore.forCurrentPlatform(
 *     context = applicationContext,
 *     serviceName = "my-app",
 *     accountName = "user-123",
 * )
 * ```
 *
 * @param context any Android `Context`; only its application context is retained.
 * @param serviceName identifies the calling application or integration; must be nonblank
 *   and free of NUL/CR/LF.
 * @param accountName identifies the credential owner; defaults to [serviceName]. Same
 *   validity rules as [serviceName].
 * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or contains
 *   NUL, CR, or LF.
 */
@Throws(IllegalArgumentException::class)
public fun PasswordStore.Companion.forCurrentPlatform(
    context: Context,
    serviceName: String,
    accountName: String = serviceName,
): PasswordStore {
    validateIdentifier(serviceName, "serviceName")
    validateIdentifier(accountName, "accountName")
    return ValidatingPasswordStore(AndroidPasswordStore(context.applicationContext, serviceName, accountName))
}

internal actual fun platformPasswordStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): PasswordStore = UnsupportedPasswordStore("Android requires the Context-taking forCurrentPlatform overload")

/**
 * Ciphertext files at `<alias>/<sha256(server)>/<sha256(username)>.bin`. The plaintext is the
 * length-prefixed username and password; the associated data binds the namespace, server, and
 * file name, so a file moved to another server or username fails authentication.
 */
internal class AndroidPasswordStore(
    context: Context,
    service: String,
    account: String,
) : PasswordStore {
    private val namespace = credentialNamespace(service, account)
    private val files = AndroidEncryptedFiles(context, "com.maniramezan.credentialkeychain.password.${sha256Hex(namespace)}")

    override fun save(credential: PasswordCredential) =
        files.guarded {
            val name = sha256Hex(credential.username)
            val plaintext = credentialNamespace(credential.username, credential.password).toByteArray(Charsets.UTF_8)
            files.write(file(credential.server, name), associatedData(credential.server, name), plaintext)
        }

    override fun find(
        server: String,
        username: String,
    ): PasswordCredential? = files.guarded { decrypt(server, sha256Hex(username)) }

    override fun findAll(server: String): List<PasswordCredential> =
        files.guarded {
            // AtomicFile may leave only a ".bak" copy after an interrupted write; ".new" files are incomplete.
            serverDirectory(server)
                .listFiles()
                .orEmpty()
                .mapNotNull {
                    it.name
                        .removeSuffix(".bak")
                        .takeIf { name -> name.endsWith(".bin") }
                        ?.removeSuffix(".bin")
                }.distinct()
                .mapNotNull { decrypt(server, it) }
        }

    override fun delete(
        server: String,
        username: String,
    ) = files.guarded {
        files.delete(file(server, sha256Hex(username)))
        // Removes the server directory only once it is empty.
        serverDirectory(server).delete()
        Unit
    }

    override fun clear() = files.guarded { files.clear() }

    private fun decrypt(
        server: String,
        name: String,
    ): PasswordCredential? {
        val plaintext = files.read(file(server, name), associatedData(server, name)) ?: return null
        val parts = parseCredentialNamespace(plaintext.decodeToString(throwOnInvalidSequence = true))
        if (parts == null || parts.size != 2 || sha256Hex(parts[0]) != name) {
            throw KeychainUnavailableException(Reason.Corrupted, "Android password entry is malformed")
        }
        return PasswordCredential(server, parts[0], parts[1])
    }

    private fun serverDirectory(server: String) = File(files.directory, sha256Hex(server))

    private fun file(
        server: String,
        name: String,
    ) = AtomicFile(File(serverDirectory(server), "$name.bin"))

    private fun associatedData(
        server: String,
        name: String,
    ) = credentialNamespace(namespace, "password", server, name)
}
