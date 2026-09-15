package com.maniramezan.credentialkeychain

import java.security.KeyFactory
import java.security.KeyStore
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import kotlin.test.*

class AndroidHardwareKeyStoreTest {
    @Test fun strictGenerationRequiresSecureHardwareAndLeavesNoSoftwareKey() =
        withStore { store, _ ->
            val result = runCatching { store.generate("signing") }
            result.exceptionOrNull()?.let {
                assertEquals(KeychainUnavailableException.Reason.Unsupported, assertIs<KeychainUnavailableException>(it).reason)
                assertNull(store.info("signing"))
            }
            result.getOrNull()?.let { assertNotEquals(SecurityLevel.Software, it.securityLevel) }
        }

    @Test fun keysSignVerifiablyAndAreReplacedAndIsolated() =
        withStore { store, service ->
            val allowSoftware = HardwareKeySpec(allowSoftwareKeys = true)
            val other = HardwareKeyStore.forCurrentPlatform(service, "second")
            try {
                assertNull(store.info("signing"))
                assertNull(store.sign("signing", byteArrayOf(1)))
                val key = store.generate("signing", allowSoftware)
                assertEquals(key, HardwareKeyStore.forCurrentPlatform(service, "first").info("signing"))

                val message = "challenge 秘密".toByteArray()
                val signature = assertNotNull(store.sign("signing", message))
                assertTrue(verify(key.publicKeyDer, message, signature))
                assertFalse(verify(key.publicKeyDer, "tampered".toByteArray(), signature))

                val replacement = store.generate("signing", allowSoftware)
                assertFalse(replacement.publicKeyDer.contentEquals(key.publicKeyDer))
                assertFalse(verify(replacement.publicKeyDer, message, signature))

                assertNull(other.info("signing"))
                other.generate("signing", allowSoftware)
                store.delete("missing")
                store.clear()
                assertNull(store.info("signing"))
                assertNotNull(other.info("signing"))
                val aliases =
                    KeyStore
                        .getInstance("AndroidKeyStore")
                        .apply { load(null) }
                        .aliases()
                        .toList()
                assertEquals(
                    1,
                    aliases.count {
                        it.startsWith("com.maniramezan.credentialkeychain.key.") &&
                            it.contains(sha256Hex(credentialNamespace(service, "second")))
                    },
                )
            } finally {
                other.clear()
            }
        }

    private fun verify(
        publicKeyDer: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeyDer))
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(message)
            verify(signature)
        }
    }

    private fun withStore(block: (HardwareKeyStore, String) -> Unit) {
        val service = "keychain-test-${UUID.randomUUID()}"
        val store = HardwareKeyStore.forCurrentPlatform(service, "first")
        try {
            block(store, service)
        } finally {
            store.clear()
        }
    }
}
