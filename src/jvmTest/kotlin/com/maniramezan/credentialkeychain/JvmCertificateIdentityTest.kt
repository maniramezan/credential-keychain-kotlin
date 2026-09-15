package com.maniramezan.credentialkeychain

import java.security.Signature
import kotlin.test.*

class JvmCertificateIdentityTest {
    @Test fun linuxIdentitiesReturnAPrivateKeyEntryThatSigns() {
        val keychain = MapKeychain()
        val store = ValidatingCertificateStore(KeychainCertificateStore("ns", keychain, LinuxCertificateBackend(keychain)))
        for ((alias, algorithm, signature) in listOf(Triple("ec", "EC", "SHA256withECDSA"), Triple("rsa", "RSA", "SHA256withRSA"))) {
            val info = store.importPkcs12(alias, TestCertificates.pkcs12(algorithm), TestCertificates.PASSPHRASE.toCharArray())
            val entry = assertNotNull(store.privateKeyEntry(alias))
            assertContentEquals(info.certificateChainDer.single(), entry.certificate.encoded)
            val message = "challenge".toByteArray()
            val signed =
                Signature.getInstance(signature).run {
                    initSign(entry.privateKey)
                    update(message)
                    sign()
                }
            val verified =
                Signature.getInstance(signature).run {
                    initVerify(entry.certificate)
                    update(message)
                    verify(signed)
                }
            assertTrue(verified, alias)
        }
        store.importCertificate("pinned", assertNotNull(store.info("ec")).certificateChainDer.single())
        assertNull(store.privateKeyEntry("pinned"))
        assertNull(store.privateKeyEntry("missing"))
        store.delete("ec")
        assertNull(store.privateKeyEntry("ec"))
    }

    @Test fun macOSKeychainStoreReadFailuresAreSanitized() {
        val keychain = MapKeychain()
        val backend = MacOSCertificateBackend { throw IllegalStateException("sensitive certificate detail") }
        val store = ValidatingCertificateStore(KeychainCertificateStore("ns", keychain, backend))
        // Record an identity directly: the failing provider cannot store one.
        keychain.values["certificate:client"] = credentialNamespace("1", "identity", "AQ==")
        val error = assertFailsWith<KeychainUnavailableException> { store.privateKeyEntry("client") }
        assertEquals(KeychainUnavailableException.Reason.Failed, error.reason)
        assertFalse(error.toString().contains("sensitive"))
    }

    private class MapKeychain : CredentialKeychain {
        val values = mutableMapOf<String, String>()

        override fun read(key: String): String? = values[key]

        override fun write(
            key: String,
            value: String,
        ) {
            values[key] = value
        }

        override fun delete(key: String) {
            values.remove(key)
        }

        override fun clear() {
            values.clear()
        }
    }
}
