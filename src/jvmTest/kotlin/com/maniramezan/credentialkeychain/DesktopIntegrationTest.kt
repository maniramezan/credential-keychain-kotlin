package com.maniramezan.credentialkeychain

import org.junit.jupiter.api.Assumptions.assumeTrue
import java.util.UUID
import kotlin.test.*

class DesktopIntegrationTest {
    @Test fun realStoreRoundTrip() {
        assumeTrue(System.getenv("CREDENTIAL_KEYCHAIN_INTEGRATION") == "1")
        val service = "keychain-test-${UUID.randomUUID()}"
        val first = CredentialKeychain.forCurrentPlatform(service, "first")
        val second = CredentialKeychain.forCurrentPlatform(service, "second")
        try {
            assertNull(first.read("key"))
            first.write("key", "secret ' \" \\ 秘密")
            assertEquals("secret ' \" \\ 秘密", CredentialKeychain.forCurrentPlatform(service, "first").read("key"))
            assertNull(second.read("key"))
            second.write("key", "other")
            for (value in listOf("616263", "e7a798e5af86", "  spaced  ", "a\tb", "秘密", "0x616263")) {
                first.write("key", value)
                assertEquals(value, first.read("key"))
            }
            first.write("key", "updated")
            assertEquals("updated", first.read("key"))
            assertEquals("other", second.read("key"))
            first.delete("key")
            assertNull(first.read("key"))
            first.delete("missing")
        } finally {
            first.clear()
            second.clear()
        }
    }

    @Test fun realPasswordStoreRoundTripAndIsolation() {
        assumeTrue(System.getenv("CREDENTIAL_KEYCHAIN_INTEGRATION") == "1")
        val service = "keychain-test-${UUID.randomUUID()}"
        val server = "api.example.com"
        val first = PasswordStore.forCurrentPlatform(service, "first")
        val second = PasswordStore.forCurrentPlatform(service, "second")
        val secrets = CredentialKeychain.forCurrentPlatform(service, "first")
        try {
            assertNull(first.find(server, "alice"))
            assertEquals(emptyList(), first.findAll(server))
            first.save(PasswordCredential(server, "alice", "secret ' \" \\ 秘密"))
            first.save(PasswordCredential(server, "bob", "  spaced  "))
            first.save(PasswordCredential("other.example.com", "carol", "other server"))
            second.save(PasswordCredential(server, "alice", "second account"))
            secrets.write("alice", "generic secret")
            assertEquals(PasswordCredential(server, "alice", "secret ' \" \\ 秘密"), first.find(server, "alice"))
            assertEquals(
                listOf(PasswordCredential(server, "alice", "secret ' \" \\ 秘密"), PasswordCredential(server, "bob", "  spaced  ")),
                first.findAll(server),
            )
            first.save(PasswordCredential(server, "alice", "updated"))
            assertEquals("updated", first.find(server, "alice")?.password)
            first.delete(server, "bob")
            assertNull(first.find(server, "bob"))
            first.delete(server, "missing")
            first.clear()
            assertEquals(emptyList(), first.findAll(server))
            assertNull(first.find("other.example.com", "carol"))
            assertEquals("second account", second.find(server, "alice")?.password)
            assertEquals("generic secret", secrets.read("alice"))
            secrets.clear()
            assertEquals("second account", second.find(server, "alice")?.password)
        } finally {
            first.clear()
            second.clear()
            secrets.clear()
        }
    }

    @Test fun realCertificateStoreRoundTripAndIsolation() {
        assumeTrue(System.getenv("CREDENTIAL_KEYCHAIN_INTEGRATION") == "1")
        val service = "keychain-test-${UUID.randomUUID()}"
        val passphrase = TestCertificates.PASSPHRASE.toCharArray()
        val first = CertificateStore.forCurrentPlatform(service, "first")
        val second = CertificateStore.forCurrentPlatform(service, "second")
        val secrets = CredentialKeychain.forCurrentPlatform(service, "first")
        try {
            assertEquals(emptyList(), first.aliases())
            assertNull(first.info("client"))
            val ec = first.importPkcs12("client", TestCertificates.pkcs12("EC"), passphrase)
            assertTrue(ec.hasPrivateKey)
            val rsa = first.importPkcs12("rsa", TestCertificates.pkcs12("RSA"), passphrase)
            val pinned = first.importCertificate("pinned", rsa.certificateChainDer.single())
            second.importPkcs12("client", TestCertificates.pkcs12("EC"), passphrase)
            secrets.write("client", "generic secret")

            assertEquals(ec, CertificateStore.forCurrentPlatform(service, "first").info("client"))
            assertEquals(pinned, first.info("pinned"))
            assertEquals(listOf("client", "pinned", "rsa"), first.aliases())
            for ((alias, algorithm) in listOf("client" to "SHA256withECDSA", "rsa" to "SHA256withRSA")) {
                val entry = assertNotNull(first.privateKeyEntry(alias), alias)
                val message = "challenge".toByteArray()
                val signature =
                    java.security.Signature.getInstance(algorithm).run {
                        initSign(entry.privateKey)
                        update(message)
                        sign()
                    }
                val verified =
                    java.security.Signature.getInstance(algorithm).run {
                        initVerify(entry.certificate)
                        update(message)
                        verify(signature)
                    }
                assertTrue(verified, alias)
            }
            assertNull(first.privateKeyEntry("pinned"))

            val replacement = first.importPkcs12("client", TestCertificates.pkcs12("EC"), passphrase)
            assertNotEquals(ec, replacement)
            assertEquals(replacement, first.info("client"))
            first.delete("rsa")
            assertNull(first.info("rsa"))
            first.delete("missing")

            first.clear()
            assertEquals(emptyList(), first.aliases())
            assertNull(first.info("client"))
            assertEquals(listOf("client"), second.aliases())
            assertEquals("generic secret", secrets.read("client"))
            secrets.clear()
            assertNotNull(second.info("client"))
        } finally {
            first.clear()
            second.clear()
            secrets.clear()
        }
    }

    @Test fun realStoreClearRemovesOnlyItsNamespace() {
        assumeTrue(System.getenv("CREDENTIAL_KEYCHAIN_INTEGRATION") == "1")
        val service = "keychain-test-${UUID.randomUUID()}"
        val first = CredentialKeychain.forCurrentPlatform(service, "first")
        val second = CredentialKeychain.forCurrentPlatform(service, "second")
        try {
            first.write("a", "1")
            first.write("b", "2")
            second.write("a", "3")
            first.clear()
            assertNull(first.read("a"))
            assertNull(first.read("b"))
            assertEquals("3", second.read("a"))
            first.clear()
        } finally {
            first.clear()
            second.clear()
        }
    }
}
