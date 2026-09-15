package com.maniramezan.credentialkeychain

import android.util.Base64
import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import java.security.Signature
import java.util.UUID
import kotlin.test.*

class AndroidCertificateStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val passphrase = "android-test-passphrase".toCharArray()

    @Test fun importsEcAndRsaIdentitiesIntoAndroidKeystore() {
        val service = "keychain-test-${UUID.randomUUID()}"
        val first = CertificateStore.forCurrentPlatform(context, service, "first")
        val second = CertificateStore.forCurrentPlatform(context, service, "second")
        val secrets = CredentialKeychain.forCurrentPlatform(context, service, "first")
        try {
            assertEquals(emptyList(), first.aliases())
            val ec = first.importPkcs12("client", EC_PKCS12, passphrase)
            val rsa = first.importPkcs12("rsa", RSA_PKCS12, passphrase)
            val pinned = first.importCertificate("pinned", rsa.certificateChainDer.single())
            second.importPkcs12("client", EC_PKCS12, passphrase)
            secrets.write("client", "generic secret")

            assertTrue(ec.hasPrivateKey)
            assertFalse(pinned.hasPrivateKey)
            assertEquals(ec, CertificateStore.forCurrentPlatform(context, service, "first").info("client"))
            assertEquals(listOf("client", "pinned", "rsa"), first.aliases())

            val keyStore = keyStore()
            for ((alias, algorithm) in listOf("client" to "SHA256withECDSA", "rsa" to "SHA256withRSA")) {
                val entry = keyStore.getEntry(keyStoreAlias(service, "first", alias), null) as KeyStore.PrivateKeyEntry
                assertContentEquals(assertNotNull(first.info(alias)).certificateChainDer.single(), entry.certificate.encoded)
                val signature =
                    Signature.getInstance(algorithm).run {
                        initSign(entry.privateKey)
                        update(MESSAGE)
                        sign()
                    }
                val verified =
                    Signature.getInstance(algorithm).run {
                        initVerify(entry.certificate)
                        update(MESSAGE)
                        verify(signature)
                    }
                assertTrue(verified, alias)
            }
            assertFalse(keyStore.containsAlias(keyStoreAlias(service, "first", "pinned")))
            val handle = assertNotNull(first.privateKeyEntry("client"))
            val handleSignature =
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(handle.privateKey)
                    update(MESSAGE)
                    sign()
                }
            val handleVerified =
                Signature.getInstance("SHA256withECDSA").run {
                    initVerify(handle.certificate)
                    update(MESSAGE)
                    verify(handleSignature)
                }
            assertTrue(handleVerified)
            assertNull(first.privateKeyEntry("pinned"))
            assertNull(first.privateKeyEntry("missing"))

            first.delete("rsa")
            assertNull(first.info("rsa"))
            assertFalse(keyStore().containsAlias(keyStoreAlias(service, "first", "rsa")))
            first.clear()
            assertEquals(emptyList(), first.aliases())
            assertFalse(keyStore().containsAlias(keyStoreAlias(service, "first", "client")))
            assertEquals(listOf("client"), second.aliases())
            assertTrue(keyStore().containsAlias(keyStoreAlias(service, "second", "client")))
            assertEquals("generic secret", secrets.read("client"))
        } finally {
            first.clear()
            second.clear()
            secrets.clear()
        }
    }

    @Test fun invalidInputLeavesTheExistingIdentityInPlace() {
        val service = "keychain-test-${UUID.randomUUID()}"
        val store = CertificateStore.forCurrentPlatform(context, service, "first")
        try {
            val existing = store.importPkcs12("client", EC_PKCS12, passphrase)
            assertFailsWith<IllegalArgumentException> { store.importPkcs12("client", RSA_PKCS12, "wrong".toCharArray()) }
            assertFailsWith<IllegalArgumentException> { store.importPkcs12("client", byteArrayOf(1, 2, 3), passphrase) }
            assertFailsWith<IllegalArgumentException> { store.importCertificate("client", byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)) }
            assertEquals(existing, store.info("client"))
            assertTrue(keyStore().containsAlias(keyStoreAlias(service, "first", "client")))
        } finally {
            store.clear()
        }
    }

    @Test fun contextFreeFactoryIsUnsupported() {
        val store = CertificateStore.forCurrentPlatform("keychain-test", "account")
        assertEquals(
            KeychainUnavailableException.Reason.Unsupported,
            assertFailsWith<KeychainUnavailableException> { store.aliases() }.reason,
        )
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun keyStoreAlias(
        service: String,
        account: String,
        alias: String,
    ): String {
        val label = "credential-keychain-kotlin:${credentialNamespace(credentialNamespace(service, account), alias)}"
        return "com.maniramezan.credentialkeychain.certificate.${sha256Hex(label)}"
    }

    private companion object {
        val MESSAGE = "challenge".toByteArray()

        // Legacy-format (SHA-1 MAC, 3DES key bag) PKCS#12 test identities, readable on API 23.
        // Passphrase: android-test-passphrase. Throwaway keys generated with keytool.
        val EC_PKCS12: ByteArray =
            Base64.decode(
                "MIIDhAIBAzCCAz0GCSqGSIb3DQEHAaCCAy4EggMqMIIDJjCB4wYJKoZIhvcNAQcBoIHVBIHSMIHPMIHMBgsqhkiG9w0BDAoBAqB3MHUwKQYKKoZIhvcNAQwBAzAbBBS2qlejDZje36xaTxA2v+aZ1GqBmgIDAMNQBEgZlxdOFZhMx+sEw9tjX0x3asslOVuFILB4l4xphECK8PE2JVwjLn9mXWMqpLjbEGljT2cwhW5l3SguD13AQzXjJnJsi4tWoUcxRDAfBgkqhkiG9w0BCRQxEh4QAGkAZABlAG4AdABpAHQAeTAhBgkqhkiG9w0BCRUxFAQSVGltZSAxNzg5NDIzNzA2MjI1MIICPAYJKoZIhvcNAQcGoIICLTCCAikCAQAwggIiBgkqhkiG9w0BBwEwKQYKKoZIhvcNAQwBBjAbBBQikssV2C9M4mcuSqSnd5PwVPOtZgIDAMNQgIIB6Gq6AumIFUhKpxo4/LKu3flUbGsY6ZXLZCxoT3YQwPF25H03Ob27Yv/rGjMPzpGffLYbV6o+ihZXjMgZh9JkpTF0FqIWT0rkP2vMbRjYwLBvowaAI5LY8teIfcmT+yAwYnTSJ16DQLeJoR0G/RvzVUNIbQeUWBCwq+oIElCr1Qqwz3SwcyJnlQPXCER9xADlp84hIEIUxMv2NPCaldkd2QS/7pWTsJbj7m4NVoL+hlzWEhftvVLYtcukJGA7o9GaDTb5v36kYPLFkbzZIZ9zBevmZ+f8ruCY8OpX/evvuyXT7FNEMKBEIZUcudCCNHmIcaMaehVuwLrBD1CvkU/YQzM9hG5Kv335g5fYFbrQMWArfIFv7AofsdqGL6b7PqhGszuvoC/SAQWXd0PUS60Tn13aur5LL3Quke5DOgA7z3V/S4ZzCsqMI24MF6G1KP5YymmDiLRC3DGgVjcig8/heA7XMBFcehrzK2tNKFws2PMFrXvIz6fJYBhI2VCIZr8oy8LajvmxGF1IHLX31qBB7qpaHRm1XmBj89pDmN/WV7MqlibYpBTi00dRERo+k0IKbqOd8FkvVC84T8Y2xvGpd2wj6pJi1Zqr7egRBy88Ky/5iB62+8YlM6rDLC80sI/gL77uAje6h5DrMD4wITAJBgUrDgMCGgUABBThyJV2drGDcOXfrbA6/eUOibb07gQUrY1Wnm2v4/Vozr+K2bD+NfVx0JgCAwGGoA==",
                Base64.NO_WRAP,
            )
        val RSA_PKCS12: ByteArray =
            Base64.decode(
                "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",
                Base64.NO_WRAP,
            )
    }
}
