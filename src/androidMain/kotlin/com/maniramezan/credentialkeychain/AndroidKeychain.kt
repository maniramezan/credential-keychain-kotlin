package com.maniramezan.credentialkeychain

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.nio.charset.CharacterCodingException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

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

internal class AndroidKeychain(
    context: Context,
    service: String,
    account: String,
) : CredentialKeychain {
    private val namespace = credentialNamespace(service, account)
    private val alias = "com.maniramezan.credentialkeychain.${digest(namespace)}"

    // Keystore keys are not backed up; ciphertext must not be restored onto another device.
    private val directory = File(context.noBackupFilesDir, alias)

    override fun read(key: String): String? =
        guarded {
            val file = file(key)
            if (!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists()) return@guarded null
            val bytes = file.openRead().use { it.readBytes() }
            if (bytes.size < HEADER_BYTES + TAG_BITS / 8 || bytes[0] != FORMAT_VERSION) {
                throw KeychainUnavailableException(Reason.Corrupted, "Android ciphertext has an unknown format")
            }
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey(create = false), GCMParameterSpec(TAG_BITS, bytes.copyOfRange(1, HEADER_BYTES)))
            cipher.updateAAD(credentialNamespace(namespace, key).toByteArray(Charsets.UTF_8))
            cipher.doFinal(bytes.copyOfRange(HEADER_BYTES, bytes.size)).decodeToString(throwOnInvalidSequence = true)
        }

    override fun write(
        key: String,
        value: String,
    ) = guarded {
        check(directory.isDirectory || directory.mkdirs())
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey(create = true))
        check(cipher.iv.size == IV_BYTES)
        cipher.updateAAD(credentialNamespace(namespace, key).toByteArray(Charsets.UTF_8))
        val bytes = byteArrayOf(FORMAT_VERSION) + cipher.iv + cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        val file = file(key)
        val output = file.startWrite()
        try {
            output.write(bytes)
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        }
    }

    override fun delete(key: String) =
        guarded {
            val file = file(key)
            file.delete()
            check(
                !file.baseFile.exists() &&
                    !File(file.baseFile.path + ".bak").exists() &&
                    !File(file.baseFile.path + ".new").exists(),
            )
        }

    /** Removes all ciphertext first, then the namespace key, so a partial failure never strands ciphertext without its key. */
    override fun clear() =
        guarded {
            directory.listFiles()?.forEach { check(it.delete()) }
            check(!directory.exists() || directory.delete())
            val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            if (store.containsAlias(alias)) store.deleteEntry(alias)
        }

    private fun file(key: String) = AtomicFile(File(directory, "${digest(key)}.bin"))

    private fun secretKey(create: Boolean): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        // A lost key invalidates the whole namespace. Do not silently create a new key
        // while unreadable ciphertext remains; callers must explicitly delete or clear first.
        if (!create || directory.listFiles()?.isEmpty() != true) {
            throw KeychainUnavailableException(Reason.Corrupted, "Android Keystore key is missing; delete the entry or clear the store")
        }
        return KeyGenerator
            .getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            .apply {
                init(
                    KeyGenParameterSpec
                        .Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build(),
                )
            }.generateKey()
    }

    private fun <T> guarded(block: () -> T): T =
        synchronized(lock) {
            try {
                block()
            } catch (error: KeychainUnavailableException) {
                throw error
            } catch (error: Exception) {
                val reason =
                    when (error) {
                        is KeyPermanentlyInvalidatedException -> Reason.AuthenticationInvalidated
                        is AEADBadTagException, is CharacterCodingException -> Reason.Corrupted
                        else -> Reason.Failed
                    }
                // Keystore and file exceptions carry no plaintext; keep them as the cause for diagnosis.
                throw KeychainUnavailableException(reason, "Android Keystore operation failed", error)
            }
        }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val FORMAT_VERSION: Byte = 1
        const val IV_BYTES = 12
        const val HEADER_BYTES = 1 + IV_BYTES
        const val TAG_BITS = 128
        val lock = Any()

        fun digest(value: String): String =
            MessageDigest
                .getInstance("SHA-256")
                .digest(value.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
    }
}
