package com.maniramezan.credentialkeychain

import kotlin.test.*

class CertificateIdentityTargetTest {
    private val passphrase = "pass".toCharArray()

    @Test fun onlyEntriesWithPrivateKeysResolveToTheirBackendAndLabel() {
        val backend = Backend()
        val inner = KeychainCertificateStore(credentialNamespace("service", "account"), MapKeychain(), backend)
        val store = ValidatingCertificateStore(inner)
        store.importPkcs12("client", byteArrayOf(1), passphrase)
        store.importCertificate("pinned", byteArrayOf(2))

        val target = assertNotNull(store.identityTarget("client"))
        assertSame(backend, target.first)
        assertEquals(inner.label("client"), target.second)
        assertSame(backend, assertNotNull(inner.identityTarget("client")).first)
        assertNull(store.identityTarget("pinned"))
        assertNull(store.identityTarget("missing"))
    }

    @Test fun invalidAliasesUnsupportedPlatformsAndForeignStoresAreRejected() {
        val store = ValidatingCertificateStore(KeychainCertificateStore("ns", MapKeychain(), Backend()))
        assertEquals("alias must not be blank.", assertFailsWith<IllegalArgumentException> { store.identityTarget(" ") }.message)
        val unsupported = ValidatingCertificateStore(UnsupportedCertificateStore("BeOS"))
        assertEquals(
            KeychainUnavailableException.Reason.Unsupported,
            assertFailsWith<KeychainUnavailableException> {
                unsupported.identityTarget("a")
            }.reason,
        )
        assertEquals(
            "store must be created by CertificateStore.forCurrentPlatform.",
            assertFailsWith<IllegalArgumentException> { Foreign().identityTarget("a") }.message,
        )
        assertFailsWith<IllegalArgumentException> { ValidatingCertificateStore(Foreign()).identityTarget("a") }
    }

    private class Backend : CertificateBackend {
        override fun parsePkcs12(
            pkcs12: ByteArray,
            passphrase: CharArray,
        ): List<ByteArray> = listOf(pkcs12)

        override fun parseCertificate(der: ByteArray): ByteArray = der

        override fun storeIdentity(
            label: String,
            pkcs12: ByteArray,
            passphrase: CharArray,
        ) = Unit

        override fun deleteIdentity(label: String) = Unit
    }

    private class MapKeychain : CredentialKeychain {
        private val values = mutableMapOf<String, String>()

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

    private class Foreign : CertificateStore {
        override fun importPkcs12(
            alias: String,
            pkcs12: ByteArray,
            passphrase: CharArray,
        ): CertificateInfo = error("unused")

        override fun importCertificate(
            alias: String,
            certificateDer: ByteArray,
        ): CertificateInfo = error("unused")

        override fun info(alias: String): CertificateInfo? = null

        override fun aliases(): List<String> = emptyList()

        override fun delete(alias: String) = Unit

        override fun clear() = Unit
    }
}
