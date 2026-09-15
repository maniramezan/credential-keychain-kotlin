package com.maniramezan.credentialkeychain.biometric

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.maniramezan.credentialkeychain.KeychainUnavailableException
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.cancellation.CancellationException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Creates biometric-protected storage isolated by [serviceName] and [accountName].
 *
 * Each namespace has one non-exportable Android Keystore RSA key whose private key can only be
 * used after a Class 3 biometric authentication and is invalidated when biometric enrollment
 * changes. Every entry is encrypted with a fresh AES-256-GCM key that the RSA public key wraps,
 * so [ProtectedKeychain.write] needs no prompt. Ciphertext lives under
 * [Context.getNoBackupFilesDir] and is never backed up.
 *
 * ```kotlin
 * val protected = ProtectedKeychain.forCurrentPlatform(
 *     context = applicationContext,
 *     activity = { currentActivity },
 *     serviceName = "my-app",
 *     accountName = "user-123",
 * )
 * ```
 *
 * @param context any Android `Context`; only its application context is retained.
 * @param activity returns the `FragmentActivity` that hosts the prompt, called on the main
 *   thread for each [ProtectedKeychain.read]. Return the currently resumed activity rather than
 *   capturing one, so the store does not leak it. A `null` result fails the read with
 *   [Reason.Failed].
 * @param serviceName identifies the calling application or integration; must be nonblank and
 *   free of NUL/CR/LF.
 * @param accountName identifies the credential owner. Same validity rules as [serviceName].
 * @throws IllegalArgumentException if [serviceName] or [accountName] is blank or contains NUL,
 *   CR, or LF.
 */
@Throws(IllegalArgumentException::class)
public fun ProtectedKeychain.Companion.forCurrentPlatform(
    context: Context,
    activity: () -> FragmentActivity?,
    serviceName: String,
    accountName: String,
): ProtectedKeychain {
    validateIdentifier(serviceName, "serviceName")
    validateIdentifier(accountName, "accountName")
    val appContext = context.applicationContext
    return ValidatingProtectedKeychain(
        AndroidProtectedKeychain(appContext, serviceName, accountName, SystemBiometricAuthenticator(activity)) {
            BiometricManager.from(appContext).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        },
    )
}

internal actual fun platformProtectedKeychain(
    serviceName: String,
    accountName: String,
): ProtectedKeychain = UnsupportedProtectedKeychain("Android requires the Context-taking forCurrentPlatform overload")

/** Unlocks a Keystore cipher through biometric authentication; tests replace the system prompt. */
internal fun interface BiometricAuthenticator {
    /** Shows the prompt and returns [cipher] once the user authenticates. */
    suspend fun authenticate(
        cipher: Cipher,
        prompt: AuthenticationPrompt,
    ): Cipher
}

/**
 * Ciphertext files at `<alias>/<sha256(key)>.bin`: a format byte, the wrapped AES key's length
 * (2 bytes) and bytes, a 12-byte IV, and the AES-GCM ciphertext bound to the namespace and key.
 */
internal class AndroidProtectedKeychain(
    context: Context,
    service: String,
    account: String,
    private val authenticator: BiometricAuthenticator,
    private val strongBiometricAvailable: () -> Boolean,
) : ProtectedKeychain {
    private val namespace = credentialNamespace(BIOMETRIC_NAMESPACE, service, account)
    private val alias = "com.maniramezan.credentialkeychain.biometric.${sha256Hex(namespace)}"
    private val directory = File(context.noBackupFilesDir, alias)

    override suspend fun read(
        key: String,
        prompt: AuthenticationPrompt,
    ): String? {
        val record = withContext(Dispatchers.IO) { guarded { readRecord(key) } } ?: return null
        val unwrap = withContext(Dispatchers.IO) { guarded { unwrapCipher() } }
        val authenticated = authenticator.authenticate(unwrap, prompt)
        return withContext(Dispatchers.IO) { guarded { open(record, authenticated, key) } }
    }

    override fun write(
        key: String,
        value: String,
    ) = guarded {
        if (!strongBiometricAvailable()) {
            throw KeychainUnavailableException(Reason.Unsupported, "no Class 3 biometric is enrolled")
        }
        val dataKey = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES).apply { init(AES_KEY_BITS) }.generateKey()
        val keyBytes = dataKey.encoded
        val wrapped =
            try {
                Cipher.getInstance(RSA_TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, publicKey(), OAEP) }.doFinal(keyBytes)
            } finally {
                keyBytes.fill(0)
            }
        val aes = Cipher.getInstance(AES_TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, dataKey) }
        check(aes.iv.size == IV_BYTES)
        aes.updateAAD(associatedData(key))
        val sealed = aes.doFinal(value.toByteArray(Charsets.UTF_8))
        val bytes =
            ByteBuffer
                .allocate(1 + 2 + wrapped.size + IV_BYTES + sealed.size)
                .put(FORMAT_VERSION)
                .putShort(wrapped.size.toShort())
                .put(wrapped)
                .put(aes.iv)
                .put(sealed)
                .array()
        check(directory.isDirectory || directory.mkdirs())
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
            check(!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists())
        }

    /** Removes all ciphertext first, then the key, so a partial failure never strands ciphertext without its key. */
    override fun clear() =
        guarded {
            check(!directory.exists() || directory.deleteRecursively())
            val store = keyStore()
            if (store.containsAlias(alias)) store.deleteEntry(alias)
        }

    private fun readRecord(key: String): Record? {
        val file = file(key)
        if (!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists()) return null
        val buffer = ByteBuffer.wrap(file.openRead().use { it.readBytes() })
        if (buffer.remaining() < 3 || buffer.get() != FORMAT_VERSION) throw corrupted()
        val wrappedSize = buffer.short.toInt() and 0xFFFF
        if (buffer.remaining() < wrappedSize + IV_BYTES + TAG_BITS / 8) throw corrupted()
        val wrapped = ByteArray(wrappedSize).also { buffer.get(it) }
        val iv = ByteArray(IV_BYTES).also { buffer.get(it) }
        val sealed = ByteArray(buffer.remaining()).also { buffer.get(it) }
        return Record(wrapped, iv, sealed)
    }

    private fun unwrapCipher(): Cipher {
        val privateKey =
            keyStore().getKey(alias, null) as? PrivateKey
                ?: throw KeychainUnavailableException(
                    Reason.Corrupted,
                    "Android Keystore key is missing; delete the entry or clear the store",
                )
        // Throws KeyPermanentlyInvalidatedException once biometric enrollment has changed.
        return Cipher.getInstance(RSA_TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, privateKey, OAEP) }
    }

    private fun open(
        record: Record,
        authenticated: Cipher,
        key: String,
    ): String {
        val keyBytes = authenticated.doFinal(record.wrappedKey)
        try {
            val aes = Cipher.getInstance(AES_TRANSFORMATION)
            aes.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, KeyProperties.KEY_ALGORITHM_AES), GCMParameterSpec(TAG_BITS, record.iv))
            aes.updateAAD(associatedData(key))
            val plaintext = aes.doFinal(record.sealed)
            return try {
                plaintext.decodeToString(throwOnInvalidSequence = true)
            } finally {
                plaintext.fill(0)
            }
        } finally {
            keyBytes.fill(0)
        }
    }

    /** The RSA public key as a software key: public-key encryption needs no authentication. */
    private fun publicKey(): PublicKey {
        val store = keyStore()
        val existing = store.getCertificate(alias)?.publicKey
        val keystoreKey =
            existing ?: run {
                // Never replace a lost key while ciphertext that needed it remains.
                if (directory.walkTopDown().any { it.isFile }) {
                    throw KeychainUnavailableException(
                        Reason.Corrupted,
                        "Android Keystore key is missing; delete the entry or clear the store",
                    )
                }
                generateKeyPair()
            }
        return KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA).generatePublic(X509EncodedKeySpec(keystoreKey.encoded))
    }

    private fun generateKeyPair(): PublicKey {
        val spec =
            KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(RSA_KEY_BITS)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setUserAuthenticationRequired(true)
                .apply {
                    // API 23 already invalidates per-use authentication keys when a biometric is enrolled.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) setInvalidatedByBiometricEnrollment(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    }
                }.build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE)
        try {
            generator.initialize(spec)
        } catch (error: InvalidAlgorithmParameterException) {
            // The spec is fixed, so this only happens without a secure lock screen or enrolled biometric.
            throw KeychainUnavailableException(Reason.Unsupported, "a secure lock screen and a Class 3 biometric are required", error)
        }
        return generator.generateKeyPair().public
    }

    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun file(key: String) = AtomicFile(File(directory, "${sha256Hex(key)}.bin"))

    private fun associatedData(key: String) = credentialNamespace(namespace, key).toByteArray(Charsets.UTF_8)

    private fun corrupted() = KeychainUnavailableException(Reason.Corrupted, "Android ciphertext has an unknown format")

    /** Serializes blocking work across instances and maps failures to [KeychainUnavailableException]. */
    private fun <T> guarded(block: () -> T): T =
        synchronized(lock) {
            try {
                block()
            } catch (error: KeychainUnavailableException) {
                throw error
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                val reason =
                    when (error) {
                        is KeyPermanentlyInvalidatedException -> Reason.AuthenticationInvalidated
                        is BadPaddingException, is CharacterCodingException -> Reason.Corrupted
                        else -> Reason.Failed
                    }
                // Keystore and file exceptions carry no plaintext; keep them as the cause for diagnosis.
                throw KeychainUnavailableException(reason, "Android Keystore operation failed", error)
            }
        }

    private class Record(
        val wrappedKey: ByteArray,
        val iv: ByteArray,
        val sealed: ByteArray,
    )

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
        const val FORMAT_VERSION: Byte = 1
        const val RSA_KEY_BITS = 2048
        const val AES_KEY_BITS = 256
        const val IV_BYTES = 12
        const val TAG_BITS = 128

        // Android Keystore only supports SHA-1 for the MGF1 digest on every API level.
        val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        val lock = Any()
    }
}

/** Hosts a [BiometricPrompt] on the main thread, requiring a Class 3 biometric. */
internal class SystemBiometricAuthenticator(
    private val activity: () -> FragmentActivity?,
) : BiometricAuthenticator {
    override suspend fun authenticate(
        cipher: Cipher,
        prompt: AuthenticationPrompt,
    ): Cipher =
        suspendCancellableCoroutine { continuation ->
            val main = Handler(Looper.getMainLooper())
            // Only touched on the main thread.
            var shown: BiometricPrompt? = null
            continuation.invokeOnCancellation { main.post { shown?.cancelAuthentication() } }
            main.post {
                if (!continuation.isActive) return@post
                val host =
                    activity() ?: run {
                        continuation.resumeWithException(
                            KeychainUnavailableException(Reason.Failed, "no FragmentActivity is available for the biometric prompt"),
                        )
                        return@post
                    }
                val callback =
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (!continuation.isActive) return
                            val unlocked = result.cryptoObject?.cipher
                            if (unlocked == null) {
                                continuation.resumeWithException(
                                    KeychainUnavailableException(Reason.Failed, "biometric prompt returned no cipher"),
                                )
                            } else {
                                continuation.resume(unlocked)
                            }
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence,
                        ) {
                            if (!continuation.isActive) return
                            continuation.resumeWithException(
                                KeychainUnavailableException(promptErrorReason(errorCode), "biometric prompt error $errorCode"),
                            )
                        }
                    }
                val info =
                    BiometricPrompt.PromptInfo
                        .Builder()
                        .setTitle(prompt.title)
                        .setSubtitle(prompt.subtitle)
                        .setNegativeButtonText(prompt.cancelLabel)
                        .setAllowedAuthenticators(BIOMETRIC_STRONG)
                        .build()
                shown =
                    BiometricPrompt(host, ContextCompat.getMainExecutor(host), callback).also {
                        it.authenticate(info, BiometricPrompt.CryptoObject(cipher))
                    }
            }
        }
}

/** Maps a [BiometricPrompt] error code to a failure reason. */
internal fun promptErrorReason(errorCode: Int): Reason =
    when (errorCode) {
        BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED -> Reason.Canceled

        BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> Reason.Locked

        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
        -> Reason.Unsupported

        else -> Reason.Failed
    }

internal fun sha256Hex(value: String): String =
    MessageDigest
        .getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
