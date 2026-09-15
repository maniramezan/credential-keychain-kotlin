package com.maniramezan.credentialkeychain

import kotlin.test.*

class CertificateStoreTest {
    private val passphrase = "pass".toCharArray()

    @Test fun factoriesValidateTheNamespace() {
        assertNotNull(CertificateStore.forCurrentPlatform("certificate-test"))
        assertNotNull(CertificateStore.forCurrentPlatform("certificate-test", "account", KeychainOptions()))
        assertEquals(
            "serviceName must not be blank.",
            assertFailsWith<IllegalArgumentException> {
                CertificateStore.forCurrentPlatform(" ")
            }.message,
        )
        assertFailsWith<IllegalArgumentException> { CertificateStore.forCurrentPlatform("service", "a\nb") }
    }

    @Test fun importsReadReplaceAndDeleteEntries() {
        val backend = FakeBackend()
        val store = store(backend)
        assertNull(store.info("client"))
        assertEquals(emptyList(), store.aliases())

        val identity = store.importPkcs12("client", byteArrayOf(1, 2), passphrase)
        assertEquals(CertificateInfo("client", listOf(byteArrayOf(1, 2), byteArrayOf(9)), hasPrivateKey = true), identity)
        assertEquals(identity, store.info("client"))
        assertContentEquals(byteArrayOf(1, 2), backend.identities[store.label("client")])

        val certificate = store.importCertificate("client", byteArrayOf(7))
        assertEquals(CertificateInfo("client", listOf(byteArrayOf(7)), hasPrivateKey = false), certificate)
        assertEquals(certificate, store.info("client"))
        assertEquals(emptyMap(), backend.identities)
        assertEquals(listOf("client"), store.aliases())

        store.delete("client")
        assertNull(store.info("client"))
        assertEquals(emptyList(), store.aliases())
        store.delete("missing")
    }

    @Test fun aliasesAreSortedAndClearRemovesIdentities() {
        val backend = FakeBackend()
        val keychain = InMemoryKeychain()
        val store = store(backend, keychain)
        store.importPkcs12("zeta", byteArrayOf(3), passphrase)
        store.importCertificate("alpha", byteArrayOf(4))
        store.importPkcs12("mid", byteArrayOf(5), passphrase)
        assertEquals(listOf("alpha", "mid", "zeta"), store.aliases())
        store.clear()
        assertEquals(emptyList(), store.aliases())
        assertEquals(emptyMap(), backend.identities)
        assertEquals(emptyMap(), keychain.values)
    }

    @Test fun invalidImportsLeaveTheExistingEntryUntouched() {
        val backend = FakeBackend()
        val store = store(backend)
        val existing = store.importPkcs12("client", byteArrayOf(1), passphrase)
        assertFailsWith<IllegalArgumentException> { store.importPkcs12("client", byteArrayOf(2), "wrong".toCharArray()) }
        assertFailsWith<IllegalArgumentException> { store.importCertificate("client", byteArrayOf(0)) }
        assertEquals(existing, store.info("client"))
        assertContentEquals(byteArrayOf(1), backend.identities[store.label("client")])
    }

    @Test fun oversizedMetadataRollsBackTheIdentityAndIsUnsupported() {
        val backend = FakeBackend()
        val store = store(backend, InMemoryKeychain(maxValueLength = 40))
        val error = assertFailsWith<KeychainUnavailableException> { store.importPkcs12("client", ByteArray(64), passphrase) }
        assertEquals(KeychainUnavailableException.Reason.Unsupported, error.reason)
        assertNull(store.info("client"))
        assertEquals(emptyMap(), backend.identities)
        assertEquals(emptyList(), store.aliases())
    }

    @Test fun malformedMetadataIsCorrupted() {
        val keychain = InMemoryKeychain()
        val store = store(FakeBackend(), keychain)
        for (value in listOf(
            "garbage",
            credentialNamespace("2", "identity", "AQ=="),
            credentialNamespace("1", "other", "AQ=="),
            credentialNamespace("1", "identity"),
            credentialNamespace("1", "identity", "!!"),
        )) {
            keychain.values["certificate:client"] = value
            assertEquals(
                KeychainUnavailableException.Reason.Corrupted,
                assertFailsWith<KeychainUnavailableException> {
                    store.info("client")
                }.reason,
                value,
            )
        }
        keychain.values["index"] = "garbage"
        assertEquals(
            KeychainUnavailableException.Reason.Corrupted,
            assertFailsWith<KeychainUnavailableException> { store.aliases() }.reason,
        )
    }

    @Test fun labelsAreNamespacedAndCollisionResistant() {
        assertNotEquals(
            KeychainCertificateStore(credentialNamespace("a", "b"), InMemoryKeychain(), FakeBackend()).label("c"),
            KeychainCertificateStore(credentialNamespace("a", "b:c"), InMemoryKeychain(), FakeBackend()).label(""),
        )
    }

    @Test fun invalidArgumentsNeverReachTheBackend() {
        val calls = mutableListOf<String>()
        val store = ValidatingCertificateStore(RecordingCertificateStore(calls))
        assertEquals("alias must not be blank.", assertFailsWith<IllegalArgumentException> { store.info("") }.message)
        assertFailsWith<IllegalArgumentException> { store.delete("a\rb") }
        assertEquals(
            "pkcs12 must not be empty.",
            assertFailsWith<IllegalArgumentException> {
                store.importPkcs12("a", byteArrayOf(), passphrase)
            }.message,
        )
        assertEquals(
            "certificateDer must be at most 1048576 bytes.",
            assertFailsWith<IllegalArgumentException> { store.importCertificate("a", ByteArray(MAX_CERTIFICATE_INPUT_BYTES + 1)) }.message,
        )
        assertEquals(emptyList(), calls)
        store.importPkcs12("a", byteArrayOf(1), passphrase)
        store.importCertificate("a", ByteArray(MAX_CERTIFICATE_INPUT_BYTES))
        store.info("a")
        store.aliases()
        store.delete("a")
        store.clear()
        assertEquals(listOf("importPkcs12:a", "importCertificate:a", "info:a", "aliases", "delete:a", "clear"), calls)
    }

    @Test fun certificateInfoIsImmutableAndComparesByValue() {
        val der = byteArrayOf(1, 2)
        val info = CertificateInfo("client", listOf(der), hasPrivateKey = true)
        der[0] = 9
        info.certificateChainDer[0][0] = 9
        assertContentEquals(byteArrayOf(1, 2), info.certificateChainDer.single())
        assertEquals(CertificateInfo("client", listOf(byteArrayOf(1, 2)), true).hashCode(), info.hashCode())
        assertNotEquals(CertificateInfo("client", listOf(byteArrayOf(1, 2)), false), info)
        assertNotEquals(CertificateInfo("client", listOf(byteArrayOf(1, 2), byteArrayOf(3)), true), info)
        assertNotEquals(CertificateInfo("client", listOf(byteArrayOf(1, 3)), true), info)
        assertEquals("CertificateInfo(alias=client, hasPrivateKey=true, certificates=1)", info.toString())
    }

    @Test fun unsupportedStoreFailsEveryOperation() {
        val store = UnsupportedCertificateStore("BeOS")
        val failures =
            listOf(
                assertFailsWith<KeychainUnavailableException> { store.importPkcs12("a", byteArrayOf(1), passphrase) },
                assertFailsWith<KeychainUnavailableException> { store.importCertificate("a", byteArrayOf(1)) },
                assertFailsWith<KeychainUnavailableException> { store.info("a") },
                assertFailsWith<KeychainUnavailableException> { store.aliases() },
                assertFailsWith<KeychainUnavailableException> { store.delete("a") },
                assertFailsWith<KeychainUnavailableException> { store.clear() },
            )
        failures.forEach { assertEquals(KeychainUnavailableException.Reason.Unsupported, it.reason) }
    }

    private fun store(
        backend: FakeBackend,
        keychain: InMemoryKeychain = InMemoryKeychain(),
    ) = KeychainCertificateStore(credentialNamespace("service", "account"), keychain, backend)

    private class FakeBackend : CertificateBackend {
        val identities = mutableMapOf<String, ByteArray>()

        override fun parsePkcs12(
            pkcs12: ByteArray,
            passphrase: CharArray,
        ): List<ByteArray> {
            require(passphrase.concatToString() == "pass") { "bad passphrase" }
            return listOf(pkcs12, byteArrayOf(9))
        }

        override fun parseCertificate(der: ByteArray): ByteArray {
            require(der.first() != 0.toByte()) { "bad certificate" }
            return der
        }

        override fun storeIdentity(
            label: String,
            pkcs12: ByteArray,
            passphrase: CharArray,
        ) {
            identities[label] = pkcs12
        }

        override fun deleteIdentity(label: String) {
            identities.remove(label)
        }
    }

    private class InMemoryKeychain(
        private val maxValueLength: Int = Int.MAX_VALUE,
    ) : CredentialKeychain {
        val values = mutableMapOf<String, String>()

        override fun read(key: String): String? = values[key]

        override fun write(
            key: String,
            value: String,
        ) {
            require(value.length <= maxValueLength) { "too large" }
            values[key] = value
        }

        override fun delete(key: String) {
            values.remove(key)
        }

        override fun clear() {
            values.clear()
        }
    }

    private class RecordingCertificateStore(
        private val calls: MutableList<String>,
    ) : CertificateStore {
        override fun importPkcs12(
            alias: String,
            pkcs12: ByteArray,
            passphrase: CharArray,
        ): CertificateInfo {
            calls += "importPkcs12:$alias"
            return CertificateInfo(alias, listOf(pkcs12), true)
        }

        override fun importCertificate(
            alias: String,
            certificateDer: ByteArray,
        ): CertificateInfo {
            calls += "importCertificate:$alias"
            return CertificateInfo(alias, listOf(certificateDer), false)
        }

        override fun info(alias: String): CertificateInfo? {
            calls += "info:$alias"
            return null
        }

        override fun aliases(): List<String> {
            calls += "aliases"
            return emptyList()
        }

        override fun delete(alias: String) {
            calls += "delete:$alias"
        }

        override fun clear() {
            calls += "clear"
        }
    }
}
