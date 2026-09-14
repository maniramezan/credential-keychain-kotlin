package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.util.Base64
import kotlin.test.*

class CertificateBackendTest {
    private val parser =
        object : JvmCertificateBackend() {
            override fun storeIdentity(
                label: String,
                pkcs12: ByteArray,
                passphrase: CharArray,
            ) = Unit

            override fun deleteIdentity(label: String) = Unit
        }

    @Test fun parsesEcAndRsaIdentitiesAndTheirCertificates() {
        for (algorithm in listOf("EC", "RSA")) {
            val pkcs12 = TestCertificates.pkcs12(algorithm)
            val chain = parser.parsePkcs12(pkcs12, TestCertificates.PASSPHRASE.toCharArray())
            assertEquals(1, chain.size, algorithm)
            assertContentEquals(chain.single(), parser.parseCertificate(chain.single()))
            assertEquals(algorithm, loadPkcs12Identity(pkcs12, TestCertificates.PASSPHRASE.toCharArray()).privateKey.algorithm)
        }
    }

    @Test fun rejectsBadPkcs12AndCertificateInput() {
        val pkcs12 = TestCertificates.pkcs12("EC")
        val invalid =
            listOf(
                { parser.parsePkcs12(pkcs12, "wrong".toCharArray()) },
                { parser.parsePkcs12(byteArrayOf(1, 2, 3), TestCertificates.PASSPHRASE.toCharArray()) },
                {
                    parser.parsePkcs12(
                        TestCertificates.pkcs12("EC", aliases = listOf("one", "two")),
                        TestCertificates.PASSPHRASE.toCharArray(),
                    )
                },
                { parser.parseCertificate(byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)) },
                { parser.parseCertificate(pkcs12) },
            )
        for (call in invalid) {
            val error = assertFailsWith<IllegalArgumentException> { call() }
            assertFalse(error.message.orEmpty().contains(TestCertificates.PASSPHRASE))
        }
    }

    @Test fun storeRecordsRealChainsThroughTheSharedMetadataLogic() {
        val keychain = MapKeychain()
        val linux = LinuxCertificateBackend(keychain)
        val store = KeychainCertificateStore(credentialNamespace("service", "account"), keychain, linux)
        val pkcs12 = TestCertificates.pkcs12("EC")
        val identity = store.importPkcs12("client", pkcs12, TestCertificates.PASSPHRASE.toCharArray())
        val leaf = identity.certificateChainDer.single()
        assertEquals(identity, store.info("client"))
        val stored = assertNotNull(linux.readIdentity(store.label("client")))
        assertEquals("EC", stored.privateKey.algorithm)
        assertContentEquals(leaf, stored.chain.single().encoded)

        val pinned = store.importCertificate("pinned", leaf)
        assertEquals(listOf("client", "pinned"), store.aliases())
        assertFalse(pinned.hasPrivateKey)
        store.delete("client")
        assertNull(linux.readIdentity(store.label("client")))
        store.clear()
        assertEquals(emptyMap(), keychain.values)
    }

    @Test fun linuxRejectsBundlesThatSecretToolCannotStore() {
        val backend = LinuxCertificateBackend(MapKeychain(maxValueBytes = 512))
        val error =
            assertFailsWith<KeychainUnavailableException> {
                backend.storeIdentity("label", TestCertificates.pkcs12("RSA"), TestCertificates.PASSPHRASE.toCharArray())
            }
        assertEquals(Reason.Unsupported, error.reason)
        val corrupt = MapKeychain().apply { values["identity:label"] = Base64.getEncoder().encodeToString(byteArrayOf(1, 2)) }
        assertEquals(
            Reason.Corrupted,
            assertFailsWith<KeychainUnavailableException> {
                LinuxCertificateBackend(corrupt).readIdentity("label")
            }.reason,
        )
    }

    @Test fun windowsSendsBundlesAndPassphrasesOnlyThroughStdin() {
        val pkcs12 = TestCertificates.pkcs12("EC")
        val encodedBundle = Base64.getEncoder().encodeToString(pkcs12)
        val encodedPassphrase = Base64.getEncoder().encodeToString(TestCertificates.PASSPHRASE.toByteArray())
        val scripts = mutableListOf<String>()
        val backend =
            WindowsCertificateBackend(
                PowerShell(
                    File("powershell.exe"),
                    CommandRunner { args, stdin ->
                        val commandLine = args.joinToString(" ")
                        assertFalse(commandLine.contains(encodedBundle))
                        assertFalse(commandLine.contains(encodedPassphrase))
                        assertFalse(commandLine.contains(TestCertificates.PASSPHRASE))
                        scripts += checkNotNull(stdin)
                        CommandResult(0, "", "")
                    },
                ),
            )
        backend.storeIdentity("credential-keychain-kotlin:it's", pkcs12, TestCertificates.PASSPHRASE.toCharArray())
        backend.deleteIdentity("credential-keychain-kotlin:it's")
        val (store, delete) = scripts
        assertTrue(store.contains(encodedBundle))
        assertTrue(store.contains(encodedPassphrase))
        assertTrue(store.contains("X509KeyStorageFlags]'PersistKeySet,UserKeySet'"))
        assertTrue(store.contains("FriendlyName = 'credential-keychain-kotlin:it''s'"))
        assertTrue(store.contains("[System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')"))
        assertTrue(store.indexOf("Remove-CkkCertificates 'credential") < store.indexOf("\$store.Add"))
        assertTrue(delete.contains("Remove-CkkCertificates 'credential-keychain-kotlin:it''s'"))
        assertTrue(delete.contains("Key.Delete()"))
    }

    @Test fun windowsFailuresAreSanitizedAndMissingPowerShellIsUnsupported() {
        val broken =
            WindowsCertificateBackend(
                PowerShell(
                    File("powershell.exe"),
                    CommandRunner {
                        _,
                        _,
                        ->
                        CommandResult(1, "", "sensitive")
                    },
                ),
            )
        val error = assertFailsWith<KeychainUnavailableException> { broken.deleteIdentity("label") }
        assertEquals(Reason.Failed, error.reason)
        assertFalse(error.toString().contains("sensitive"))
        val missing = WindowsCertificateBackend(PowerShell(null, CommandRunner { _, _ -> error("must not launch") }))
        assertEquals(Reason.Unsupported, assertFailsWith<KeychainUnavailableException> { missing.deleteIdentity("label") }.reason)
    }

    @Test fun macOSKeychainStoreFailuresAreSanitized() {
        val backend = MacOSCertificateBackend { throw IllegalStateException("sensitive certificate detail") }
        val error = assertFailsWith<KeychainUnavailableException> { backend.deleteIdentity("label") }
        assertEquals(Reason.Failed, error.reason)
        assertFalse(error.toString().contains("sensitive"))
        assertFailsWith<IllegalArgumentException> { backend.storeIdentity("label", byteArrayOf(1), "x".toCharArray()) }
        val inMemory = KeyStore.getInstance("PKCS12")
        MacOSCertificateBackend { inMemory }.deleteIdentity("missing")
    }

    private class MapKeychain(
        private val maxValueBytes: Int = Int.MAX_VALUE,
    ) : CredentialKeychain {
        val values = mutableMapOf<String, String>()

        override fun read(key: String): String? = values[key]

        override fun write(
            key: String,
            value: String,
        ) {
            require(value.toByteArray().size <= maxValueBytes) { "too large" }
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

/** Generates throwaway PKCS#12 identities with the JDK's keytool. */
internal object TestCertificates {
    const val PASSPHRASE = "test-passphrase"

    fun pkcs12(
        keyAlgorithm: String,
        aliases: List<String> = listOf("identity"),
    ): ByteArray {
        val keytool =
            File(
                System.getProperty("java.home"),
                "bin/keytool" + if (System.getProperty("os.name").startsWith("Windows")) ".exe" else "",
            )
        val directory = Files.createTempDirectory("credential-keychain-p12").toFile()
        try {
            val file = File(directory, "identity.p12")
            for (alias in aliases) {
                val command =
                    mutableListOf(
                        keytool.path,
                        "-genkeypair",
                        "-keyalg",
                        keyAlgorithm,
                        "-alias",
                        alias,
                        "-dname",
                        "CN=credential-keychain-test-$alias",
                        "-validity",
                        "2",
                        "-storetype",
                        "PKCS12",
                        "-keystore",
                        file.path,
                        "-storepass",
                        PASSPHRASE,
                        "-keypass",
                        PASSPHRASE,
                    )
                command += if (keyAlgorithm == "EC") listOf("-groupname", "secp256r1") else listOf("-keysize", "2048")
                val process = ProcessBuilder(command).redirectErrorStream(true).start()
                process.inputStream.readBytes()
                check(process.waitFor() == 0) { "keytool failed" }
            }
            return file.readBytes()
        } finally {
            directory.deleteRecursively()
        }
    }
}
