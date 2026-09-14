package com.maniramezan.credentialkeychain

import android.content.Context
import android.util.AtomicFile
import java.io.File

/**
 * Creates app-private storage isolated by [serviceName] and [accountName], encrypted with
 * a non-exportable Android Keystore AES-256-GCM key. Ciphertext is written to a file under
 * [Context.getNoBackupFilesDir], so entries are excluded from Auto Backup — Keystore keys
 * are hardware/OS-bound and cannot be restored onto another device or after a factory reset.
 *
 * `context` is retained only as [Context.getApplicationContext], never the passed-in
 * instance, so it is safe to call this with an `Activity` context without leaking it.
 *
 * ```kotlin
 * val keychain = CredentialKeychain.forCurrentPlatform(
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
public fun CredentialKeychain.Companion.forCurrentPlatform(
    context: Context,
    serviceName: String,
    accountName: String = serviceName,
): CredentialKeychain {
    validateIdentifier(serviceName, "serviceName")
    validateIdentifier(accountName, "accountName")
    return ValidatingKeychain(AndroidKeychain(context.applicationContext, serviceName, accountName))
}

internal actual fun platformKeychain(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CredentialKeychain = UnsupportedKeychainStore("Android requires the Context-taking forCurrentPlatform overload")

/** Ciphertext files at `<alias>/<sha256(key)>.bin`, bound to the namespace and key as associated data. */
internal class AndroidKeychain(
    context: Context,
    service: String,
    account: String,
) : CredentialKeychain {
    private val namespace = credentialNamespace(service, account)
    private val files = AndroidEncryptedFiles(context, "com.maniramezan.credentialkeychain.${sha256Hex(namespace)}")

    override fun read(key: String): String? =
        files.guarded {
            files.read(file(key), credentialNamespace(namespace, key))?.decodeToString(throwOnInvalidSequence = true)
        }

    override fun write(
        key: String,
        value: String,
    ) = files.guarded {
        files.write(file(key), credentialNamespace(namespace, key), value.toByteArray(Charsets.UTF_8))
    }

    override fun delete(key: String) = files.guarded { files.delete(file(key)) }

    override fun clear() = files.guarded { files.clear() }

    private fun file(key: String) = AtomicFile(File(files.directory, "${sha256Hex(key)}.bin"))
}
