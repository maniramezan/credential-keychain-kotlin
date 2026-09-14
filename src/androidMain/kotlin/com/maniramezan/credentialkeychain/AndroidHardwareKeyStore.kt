package com.maniramezan.credentialkeychain

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

internal actual fun platformHardwareKeyStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): HardwareKeyStore = AndroidHardwareKeyStore(serviceName, accountName)

/**
 * EC P-256 key pairs in Android Keystore under `<prefix><sha256(alias)>`, where the prefix hashes
 * the service/account namespace. Generation prefers StrongBox (API 28+) and falls back to the
 * trusted execution environment; software-only results are deleted unless explicitly allowed.
 */
internal class AndroidHardwareKeyStore(
    service: String,
    account: String,
) : HardwareKeyStore {
    private val prefix = "com.maniramezan.credentialkeychain.key.${sha256Hex(credentialNamespace(service, account))}."

    override fun generate(
        alias: String,
        spec: HardwareKeySpec,
    ): HardwareKeyInfo =
        guarded {
            val keyAlias = keyAlias(alias)
            val store = keyStore()
            if (store.containsAlias(keyAlias)) store.deleteEntry(keyAlias)
            if (!(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && generateKeyPair(keyAlias, strongBox = true))) {
                generateKeyPair(keyAlias, strongBox = false)
            }
            val info = read(store, alias) ?: throw KeychainUnavailableException(Reason.Failed, "Android Keystore did not store the key")
            if (info.securityLevel == SecurityLevel.Software && !spec.allowSoftwareKeys) {
                store.deleteEntry(keyAlias)
                throw KeychainUnavailableException(Reason.Unsupported, "Android secure hardware is not available")
            }
            info
        }

    override fun info(alias: String): HardwareKeyInfo? = guarded { read(keyStore(), alias) }

    override fun sign(
        alias: String,
        data: ByteArray,
    ): ByteArray? =
        guarded {
            val key = keyStore().getKey(keyAlias(alias), null) as? PrivateKey ?: return@guarded null
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initSign(key)
                update(data)
                sign()
            }
        }

    override fun delete(alias: String) =
        guarded {
            val store = keyStore()
            if (store.containsAlias(keyAlias(alias))) store.deleteEntry(keyAlias(alias))
        }

    override fun clear() =
        guarded {
            val store = keyStore()
            store
                .aliases()
                .toList()
                .filter { it.startsWith(prefix) }
                .forEach { store.deleteEntry(it) }
        }

    /** Returns `false` only when StrongBox was requested and is unavailable. */
    private fun generateKeyPair(
        keyAlias: String,
        strongBox: Boolean,
    ): Boolean {
        val builder =
            KeyGenParameterSpec
                .Builder(keyAlias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
        return try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
                initialize(builder.build())
                generateKeyPair()
            }
            true
        } catch (error: ProviderException) {
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                error is StrongBoxUnavailableException
            ) {
                false
            } else {
                throw error
            }
        }
    }

    private fun read(
        store: KeyStore,
        alias: String,
    ): HardwareKeyInfo? {
        val keyAlias = keyAlias(alias)
        val key = store.getKey(keyAlias, null) as? PrivateKey ?: return null
        val certificate =
            store.getCertificate(keyAlias) ?: throw KeychainUnavailableException(Reason.Corrupted, "Android key has no public key")
        return HardwareKeyInfo(alias, certificate.publicKey.encoded, securityLevel(key))
    }

    private fun securityLevel(key: PrivateKey): SecurityLevel {
        val info = KeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.StrongBox

                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE,
                -> SecurityLevel.TrustedEnvironment

                else -> SecurityLevel.Software
            }
        } else {
            // Before API 31 Keystore reports only whether the key is in secure hardware.
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) SecurityLevel.TrustedEnvironment else SecurityLevel.Software
        }
    }

    private fun keyAlias(alias: String) = prefix + sha256Hex(alias)

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun <T> guarded(block: () -> T): T =
        try {
            block()
        } catch (error: KeychainUnavailableException) {
            throw error
        } catch (error: Exception) {
            val reason =
                when (error) {
                    is KeyPermanentlyInvalidatedException -> Reason.AuthenticationInvalidated
                    is UserNotAuthenticatedException -> Reason.Locked
                    else -> Reason.Failed
                }
            // Keystore exceptions carry no key material; keep them as the cause for diagnosis.
            throw KeychainUnavailableException(reason, "Android Keystore key operation failed", error)
        }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }
}
