@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.maniramezan.credentialkeychain

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.NSUUID
import platform.Security.*
import kotlin.test.*

/**
 * Unsigned test binaries cannot use the Secure Enclave, so strict generation may fail with
 * `Unsupported`; the opt-in software path is exercised fully and its signatures are verified.
 */
class AppleHardwareKeyStoreTest {
    @Test fun strictGenerationUsesTheSecureEnclaveOrFailsWithoutLeavingAKey() {
        val store = HardwareKeyStore.forCurrentPlatform(uniqueService(), "first")
        try {
            val result = runCatching { store.generate("signing") }
            result.exceptionOrNull()?.let {
                assertEquals(KeychainUnavailableException.Reason.Unsupported, assertIs<KeychainUnavailableException>(it).reason)
                assertNull(store.info("signing"))
            }
            result.getOrNull()?.let { assertEquals(SecurityLevel.SecureEnclave, it.securityLevel) }
        } finally {
            store.clear()
        }
    }

    @Test fun softwareKeysSignVerifiablyAndAreReplacedAndIsolated() {
        val service = uniqueService()
        val allowSoftware = HardwareKeySpec(allowSoftwareKeys = true)
        val store = HardwareKeyStore.forCurrentPlatform(service, "first")
        val other = HardwareKeyStore.forCurrentPlatform(service, "second")
        try {
            assertNull(store.info("signing"))
            assertNull(store.sign("signing", byteArrayOf(1)))
            val key = store.generate("signing", allowSoftware)
            assertEquals(91, key.publicKeyDer.size)
            assertContentEquals(P256_PUBLIC_KEY_PREFIX, key.publicKeyDer.copyOfRange(0, 26))
            assertEquals(key, HardwareKeyStore.forCurrentPlatform(service, "first").info("signing"))

            val message = "challenge 秘密".encodeToByteArray()
            val signature = assertNotNull(store.sign("signing", message))
            assertEquals(0x30, signature[0].toInt())
            assertTrue(verify(key.publicKeyDer, message, signature))
            assertFalse(verify(key.publicKeyDer, "tampered".encodeToByteArray(), signature))
            assertTrue(verify(key.publicKeyDer, byteArrayOf(), assertNotNull(store.sign("signing", byteArrayOf()))))

            val replacement = store.generate("signing", allowSoftware)
            assertFalse(replacement.publicKeyDer.contentEquals(key.publicKeyDer))
            assertEquals(replacement, store.info("signing"))

            assertNull(other.info("signing"))
            other.generate("signing", allowSoftware)
            store.generate("second-key", allowSoftware)
            store.delete("second-key")
            assertNull(store.info("second-key"))
            store.delete("missing")
            store.clear()
            assertNull(store.info("signing"))
            assertNotNull(other.info("signing"))
        } finally {
            store.clear()
            other.clear()
        }
    }

    private fun verify(
        publicKeyDer: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean =
        withRetainingDictionary { attributes ->
            CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
            CFDictionarySetValue(attributes, kSecAttrKeyClass, kSecAttrKeyClassPublic)
            attributes.setInt(kSecAttrKeySizeInBits, 256)
            withAnyCFData(publicKeyDer.copyOfRange(26, publicKeyDer.size)) { point ->
                val publicKey = assertNotNull(SecKeyCreateWithData(point, attributes, null))
                try {
                    withAnyCFData(message) { data ->
                        withAnyCFData(signature) { signed ->
                            SecKeyVerifySignature(publicKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, data, signed, null)
                        }
                    }
                } finally {
                    CFRelease(publicKey)
                }
            }
        }

    private fun uniqueService() = "credential-keychain-test-${NSUUID().UUIDString}"
}
