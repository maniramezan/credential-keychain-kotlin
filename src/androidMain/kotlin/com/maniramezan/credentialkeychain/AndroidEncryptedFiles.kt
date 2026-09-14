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
 * One non-exportable Android Keystore AES-256-GCM key plus a directory of authenticated
 * ciphertext files under `noBackupFilesDir`. Each file holds a format byte, a fresh 12-byte IV,
 * and the ciphertext with its 128-bit tag. Callers supply associated data that binds each file
 * to its namespace and location.
 */
internal class AndroidEncryptedFiles(
    context: Context,
    private val alias: String,
) {
    // Keystore keys are not backed up; ciphertext must not be restored onto another device.
    val directory: File = File(context.noBackupFilesDir, alias)

    /** Returns the decrypted contents of [file], or `null` if it does not exist. */
    fun read(
        file: AtomicFile,
        associatedData: String,
    ): ByteArray? {
        if (!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists()) return null
        val bytes = file.openRead().use { it.readBytes() }
        if (bytes.size < HEADER_BYTES + TAG_BITS / 8 || bytes[0] != FORMAT_VERSION) {
            throw KeychainUnavailableException(Reason.Corrupted, "Android ciphertext has an unknown format")
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey(create = false), GCMParameterSpec(TAG_BITS, bytes.copyOfRange(1, HEADER_BYTES)))
        cipher.updateAAD(associatedData.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(bytes.copyOfRange(HEADER_BYTES, bytes.size))
    }

    /** Atomically replaces [file] with [plaintext] encrypted under a fresh IV. */
    fun write(
        file: AtomicFile,
        associatedData: String,
        plaintext: ByteArray,
    ) {
        val parent = file.baseFile.parentFile
        check(parent != null && (parent.isDirectory || parent.mkdirs()))
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey(create = true))
        check(cipher.iv.size == IV_BYTES)
        cipher.updateAAD(associatedData.toByteArray(Charsets.UTF_8))
        val bytes = byteArrayOf(FORMAT_VERSION) + cipher.iv + cipher.doFinal(plaintext)
        val output = file.startWrite()
        try {
            output.write(bytes)
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        }
    }

    fun delete(file: AtomicFile) {
        file.delete()
        check(
            !file.baseFile.exists() &&
                !File(file.baseFile.path + ".bak").exists() &&
                !File(file.baseFile.path + ".new").exists(),
        )
    }

    /** Removes all ciphertext first, then the key, so a partial failure never strands ciphertext without its key. */
    fun clear() {
        check(!directory.exists() || directory.deleteRecursively())
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }

    /** Serializes access across every instance in the process and maps failures to [KeychainUnavailableException]. */
    fun <T> guarded(block: () -> T): T =
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

    private fun secretKey(create: Boolean): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        // A lost key invalidates the whole directory. Do not silently create a new key while
        // unreadable ciphertext remains; callers must explicitly delete or clear first.
        if (!create || directory.walkTopDown().any { it.isFile }) {
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

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val FORMAT_VERSION: Byte = 1
        const val IV_BYTES = 12
        const val HEADER_BYTES = 1 + IV_BYTES
        const val TAG_BITS = 128
        val lock = Any()
    }
}

internal fun sha256Hex(value: String): String =
    MessageDigest
        .getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
