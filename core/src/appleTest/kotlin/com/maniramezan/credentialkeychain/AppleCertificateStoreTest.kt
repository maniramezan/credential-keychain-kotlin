@file:OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class, kotlinx.cinterop.ExperimentalForeignApi::class)

package com.maniramezan.credentialkeychain

import platform.Foundation.NSUUID
import kotlin.io.encoding.Base64
import kotlin.test.*

/**
 * Runs as an unsigned test executable, so identities cannot reach the data-protection keychain
 * and must fail with `Unsupported` without leaving an entry. Certificates need no entitlements.
 * The iOS simulator harness covers identities end to end.
 */
class AppleCertificateStoreTest {
    private val passphrase = "android-test-passphrase"

    @Test fun certificatesRoundTripAndUnsignedIdentitiesFailCleanly() {
        val store = CertificateStore.forCurrentPlatform("credential-keychain-test-${NSUUID().UUIDString}", "first")
        try {
            val identity = runCatching { store.importPkcs12("client", EC_PKCS12, passphrase.toCharArray()) }
            identity.exceptionOrNull()?.let {
                assertEquals(KeychainUnavailableException.Reason.Unsupported, assertIs<KeychainUnavailableException>(it).reason)
                assertNull(store.info("client"))
            }
            identity.getOrNull()?.let {
                assertTrue(it.hasPrivateKey)
                assertContentEquals(LEAF_CERTIFICATE, it.certificateChainDer.first())
            }

            val pinned = store.importCertificate("pinned", LEAF_CERTIFICATE)
            assertFalse(pinned.hasPrivateKey)
            assertContentEquals(LEAF_CERTIFICATE, pinned.certificateChainDer.single())
            assertEquals(pinned, store.info("pinned"))
            assertTrue("pinned" in store.aliases())
            assertNull(store.secIdentity("pinned"))
            assertNull(store.secIdentity("missing"))

            store.delete("pinned")
            assertNull(store.info("pinned"))
            store.delete("missing")
        } finally {
            store.clear()
        }
    }

    @Test fun invalidInputIsRejectedBeforeAnythingIsStored() {
        val store = CertificateStore.forCurrentPlatform("credential-keychain-test-${NSUUID().UUIDString}", "first")
        try {
            assertFailsWith<IllegalArgumentException> { store.importPkcs12("client", EC_PKCS12, "wrong passphrase".toCharArray()) }
            assertFailsWith<IllegalArgumentException> { store.importPkcs12("client", byteArrayOf(1, 2, 3), passphrase.toCharArray()) }
            assertFailsWith<IllegalArgumentException> { store.importCertificate("pinned", byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)) }
            assertEquals(emptyList(), store.aliases())
        } finally {
            store.clear()
        }
    }

    private companion object {
        // Throwaway legacy-format EC PKCS#12 identity, shared with the Android tests and the simulator harness.
        val EC_PKCS12: ByteArray =
            Base64.decode(
                "MIIDhAIBAzCCAz0GCSqGSIb3DQEHAaCCAy4EggMqMIIDJjCB4wYJKoZIhvcNAQcBoIHVBIHSMIHPMIHMBgsqhkiG9w0BDAoBAqB3MHUwKQYKKoZIhvcNAQwBAzAbBBS2qlejDZje36xaTxA2v+aZ1GqBmgIDAMNQBEgZlxdOFZhMx+sEw9tjX0x3asslOVuFILB4l4xphECK8PE2JVwjLn9mXWMqpLjbEGljT2cwhW5l3SguD13AQzXjJnJsi4tWoUcxRDAfBgkqhkiG9w0BCRQxEh4QAGkAZABlAG4AdABpAHQAeTAhBgkqhkiG9w0BCRUxFAQSVGltZSAxNzg5NDIzNzA2MjI1MIICPAYJKoZIhvcNAQcGoIICLTCCAikCAQAwggIiBgkqhkiG9w0BBwEwKQYKKoZIhvcNAQwBBjAbBBQikssV2C9M4mcuSqSnd5PwVPOtZgIDAMNQgIIB6Gq6AumIFUhKpxo4/LKu3flUbGsY6ZXLZCxoT3YQwPF25H03Ob27Yv/rGjMPzpGffLYbV6o+ihZXjMgZh9JkpTF0FqIWT0rkP2vMbRjYwLBvowaAI5LY8teIfcmT+yAwYnTSJ16DQLeJoR0G/RvzVUNIbQeUWBCwq+oIElCr1Qqwz3SwcyJnlQPXCER9xADlp84hIEIUxMv2NPCaldkd2QS/7pWTsJbj7m4NVoL+hlzWEhftvVLYtcukJGA7o9GaDTb5v36kYPLFkbzZIZ9zBevmZ+f8ruCY8OpX/evvuyXT7FNEMKBEIZUcudCCNHmIcaMaehVuwLrBD1CvkU/YQzM9hG5Kv335g5fYFbrQMWArfIFv7AofsdqGL6b7PqhGszuvoC/SAQWXd0PUS60Tn13aur5LL3Quke5DOgA7z3V/S4ZzCsqMI24MF6G1KP5YymmDiLRC3DGgVjcig8/heA7XMBFcehrzK2tNKFws2PMFrXvIz6fJYBhI2VCIZr8oy8LajvmxGF1IHLX31qBB7qpaHRm1XmBj89pDmN/WV7MqlibYpBTi00dRERo+k0IKbqOd8FkvVC84T8Y2xvGpd2wj6pJi1Zqr7egRBy88Ky/5iB62+8YlM6rDLC80sI/gL77uAje6h5DrMD4wITAJBgUrDgMCGgUABBThyJV2drGDcOXfrbA6/eUOibb07gQUrY1Wnm2v4/Vozr+K2bD+NfVx0JgCAwGGoA==",
            )

        // DER leaf certificate of EC_PKCS12 (CN=credential-keychain-android-ec).
        val LEAF_CERTIFICATE: ByteArray =
            Base64.decode(
                "MIIBazCCARGgAwIBAgIIfISxZI6kX8owCgYIKoZIzj0EAwMwKTEnMCUGA1UEAxMeY3JlZGVudGlhbC1rZXljaGFpbi1hbmRyb2lkLWVjMCAXDTI2MDkxNDIyMDgyNloYDzIxMjYwODIxMjIwODI2WjApMScwJQYDVQQDEx5jcmVkZW50aWFsLWtleWNoYWluLWFuZHJvaWQtZWMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQuJYJa24mTBkJWHuIMompmeMA5/5SdavBRPbtQJjWFQ+2WyKVQbzDFUEXLKCbRntUTdhVxZAFA0rbtug00pWUgoyEwHzAdBgNVHQ4EFgQUpAZvia/g6flJH4EGV9DT4zlqsy4wCgYIKoZIzj0EAwMDSAAwRQIhAJNEqifjdMXrSLYXmcCuxWpaSYdZJndmQbchNFxid5BJAiAwWUXlnob30M4qtrtlBZTKaAKBgMkP5hXG20L34J1fsA==",
            )
    }
}
