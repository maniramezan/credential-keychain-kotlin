package com.maniramezan.credentialkeychain

import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.ptr.PointerByReference
import com.sun.jna.win32.StdCallLibrary
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.security.KeyStore
import java.util.Base64
import java.util.UUID
import kotlin.test.*

/**
 * Calls [JnaWindowsApi] against the real current-user stores, covering what the store-level
 * round trips in [DesktopIntegrationTest] cannot observe: key-container cleanup, Win32 error
 * paths, and compatibility with data written by the earlier PowerShell backends.
 */
class WindowsNativeIntegrationTest {
    private val api by lazy { JnaWindowsApi() }
    private val name = "credential-keychain-kotlin:test:${UUID.randomUUID()}"

    @BeforeEach fun requireWindows() {
        assumeTrue(desktopOs() == DesktopOs.Windows && System.getenv("CREDENTIAL_KEYCHAIN_INTEGRATION") == "1")
    }

    @Test fun dpapiRoundTripsAndRejectsInvalidCiphertext() {
        for (plaintext in listOf(ByteArray(0), "秘密".toByteArray(), ByteArray(64 * 1024) { it.toByte() })) {
            val ciphertext = api.protect(plaintext)
            assertFalse(ciphertext.contentEquals(plaintext))
            assertContentEquals(plaintext, api.unprotect(ciphertext))
        }
        val tampered = api.protect("secret".toByteArray()).apply { this[size - 1] = (this[size - 1] + 1).toByte() }
        assertFailsWith<IllegalStateException> { api.unprotect(tampered) }
        assertFailsWith<IllegalStateException> { api.unprotect(byteArrayOf(1, 2, 3)) }
    }

    @Test fun credentialsRoundTripFilterAndReportWin32Errors() {
        try {
            assertNull(api.readCredential("$name:a"))
            assertEquals(emptyList(), api.enumerateCredentials("$name:*"))
            api.deleteCredential("$name:a")

            api.writeCredential("$name:a", "alice", "first".toByteArray())
            api.writeCredential("$name:a", "alice", "秘密".toByteArray())
            api.writeCredential("$name:b", "", ByteArray(0))
            api.writeCredential("$name-other:a", "carol", "other".toByteArray())
            val a = assertNotNull(api.readCredential("$name:a"))
            assertEquals("$name:a" to "alice", a.target to a.userName)
            assertContentEquals("秘密".toByteArray(), a.secret)
            val b = assertNotNull(api.readCredential("$name:b"))
            assertEquals("", b.userName)
            assertContentEquals(ByteArray(0), b.secret)
            assertEquals(setOf("$name:a", "$name:b"), api.enumerateCredentials("$name:*").map { it.target }.toSet())

            // CRED_MAX_CREDENTIAL_BLOB_SIZE is 2560 bytes; Windows rejects anything larger.
            assertFailsWith<IllegalStateException> { api.writeCredential("$name:c", "dave", ByteArray(2561)) }
            assertNull(api.readCredential("$name:c"))
        } finally {
            (api.enumerateCredentials("$name:*") + api.enumerateCredentials("$name-other:*")).forEach { api.deleteCredential(it.target) }
        }
    }

    @Test fun importingAndDeletingIdentitiesManagesTheirKeyContainers() {
        try {
            for (algorithm in listOf("EC", "RSA")) {
                api.importIdentity(name, TestCertificates.pkcs12(algorithm), TestCertificates.PASSPHRASE.toCharArray())
                val key = api.keyLocations(name).single()
                // EC keys cannot live in a CryptoAPI provider, so this always exercises CNG deletion.
                if (algorithm == "EC") assertEquals(0, key.providerType)
                assertTrue(WindowsKeys.exists(key), algorithm)

                api.deleteIdentities(name)
                assertEquals(emptyList(), api.keyLocations(name))
                assertFalse(WindowsKeys.exists(key), algorithm)
                api.deleteIdentities(name)
            }
        } finally {
            api.deleteIdentities(name)
        }
    }

    @Test fun reimportingReplacesTheIdentityAndDeletesTheOldKey() {
        try {
            api.importIdentity(name, TestCertificates.pkcs12("EC"), TestCertificates.PASSPHRASE.toCharArray())
            val old = api.keyLocations(name).single()
            api.importIdentity(name, TestCertificates.pkcs12("EC"), TestCertificates.PASSPHRASE.toCharArray())
            val new = api.keyLocations(name).single()
            assertNotEquals(old.container, new.container)
            assertFalse(WindowsKeys.exists(old))
            assertTrue(WindowsKeys.exists(new))
        } finally {
            api.deleteIdentities(name)
        }
    }

    @Test fun failedImportsLeaveNoCertificateOrKey() {
        try {
            var saved: JnaWindowsApi.KeyLocation? = null
            val failing =
                JnaWindowsApi { key ->
                    assertTrue(WindowsKeys.exists(key))
                    saved = key
                    throw IllegalStateException("injected")
                }
            assertFailsWith<IllegalStateException> {
                failing.importIdentity(name, TestCertificates.pkcs12("EC"), TestCertificates.PASSPHRASE.toCharArray())
            }
            assertFalse(WindowsKeys.exists(assertNotNull(saved)))
            assertEquals(emptyList(), api.keyLocations(name))

            assertFailsWith<IllegalStateException> { api.importIdentity(name, TestCertificates.pkcs12("EC"), "wrong".toCharArray()) }
            assertFailsWith<IllegalStateException> { api.importIdentity(name, byteArrayOf(1, 2, 3), CharArray(0)) }
            assertEquals(emptyList(), api.keyLocations(name))
        } finally {
            api.deleteIdentities(name)
        }
    }

    @Test fun importsBundlesWithAnEmptyPassphrase() {
        val identity = loadPkcs12Identity(TestCertificates.pkcs12("EC"), TestCertificates.PASSPHRASE.toCharArray())
        val bundle =
            KeyStore.getInstance("PKCS12").run {
                load(null, null)
                setKeyEntry("identity", identity.privateKey, CharArray(0), identity.chain.toTypedArray())
                ByteArrayOutputStream().also { store(it, CharArray(0)) }.toByteArray()
            }
        try {
            api.importIdentity(name, bundle, CharArray(0))
            assertTrue(WindowsKeys.exists(api.keyLocations(name).single()))
        } finally {
            api.deleteIdentities(name)
        }
    }

    @Test fun dpapiCiphertextIsCompatibleWithThePowerShellBackend() {
        val directory = Files.createTempDirectory("keychain-legacy").toFile()
        try {
            val store = WindowsDpapiStore("test", storageDir = directory)
            val secret = "legacy ' \" 秘密\r\n"
            val file = store.fileFor("old")
            powerShell(
                "${'$'}p = [System.Security.Cryptography.ProtectedData]::Protect(${bytes(secret.toByteArray())}, ${'$'}null, " +
                    "[System.Security.Cryptography.DataProtectionScope]::CurrentUser); " +
                    "[System.IO.File]::WriteAllBytes(${literal(file.absolutePath)}, ${'$'}p)",
            )
            assertEquals(secret, store.read("old"))

            store.write("new", secret)
            val decrypted =
                powerShell(
                    "[Console]::Out.Write([Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Unprotect(" +
                        "${bytes(store.fileFor("new").readBytes())}, ${'$'}null, " +
                        "[System.Security.Cryptography.DataProtectionScope]::CurrentUser)))",
                )
            assertEquals(secret, String(Base64.getDecoder().decode(decrypted.trim()), Charsets.UTF_8))
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun identitiesImportedByThePowerShellBackendAreDeletedWithTheirKeys() {
        try {
            powerShell(
                "${'$'}c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(" +
                    "${bytes(TestCertificates.pkcs12("EC"))}, ${literal(TestCertificates.PASSPHRASE)}, " +
                    "[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'PersistKeySet,UserKeySet'); " +
                    "${'$'}c.FriendlyName = ${literal(name)}; " +
                    "${'$'}s = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser'); " +
                    "${'$'}s.Open('ReadWrite'); ${'$'}s.Add(${'$'}c); ${'$'}s.Close()",
            )
            val key = api.keyLocations(name).single()
            assertTrue(WindowsKeys.exists(key))
            api.deleteIdentities(name)
            assertEquals(emptyList(), api.keyLocations(name))
            assertFalse(WindowsKeys.exists(key))
        } finally {
            api.deleteIdentities(name)
        }
    }

    /** Runs a one-line Windows PowerShell script; test data only, so it may appear in arguments. */
    private fun powerShell(script: String): String {
        val executable = findExecutable("powershell.exe")
        assumeTrue(executable != null, "Windows PowerShell is required for compatibility checks")
        val result =
            runCommand(
                checkNotNull(executable).path,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "\$ErrorActionPreference = 'Stop'; Add-Type -AssemblyName System.Security; $script",
            )
        assertEquals(0, result.exitCode, result.stderr)
        return result.stdout
    }

    private fun bytes(value: ByteArray) = "[Convert]::FromBase64String('${Base64.getEncoder().encodeToString(value)}')"

    private fun literal(value: String) = "'" + value.replace("'", "''") + "'"
}

/** Opens key containers independently of [JnaWindowsApi], to observe whether they still exist. */
internal object WindowsKeys {
    private val ncrypt = Native.load("ncrypt", JnaWindowsApi.NCrypt::class.java)
    private val advapi32 = Native.load("advapi32", Advapi32::class.java)

    fun exists(key: JnaWindowsApi.KeyLocation): Boolean {
        val machine = key.flags and CRYPT_MACHINE_KEYSET
        val handle = PointerByReference()
        if (key.providerType != 0) {
            val opened =
                advapi32.CryptAcquireContextW(
                    handle,
                    WString(key.container),
                    key.provider?.let(::WString),
                    key.providerType,
                    machine or SILENT,
                )
            if (opened) advapi32.CryptReleaseContext(handle.value, 0)
            return opened
        }
        val provider = PointerByReference()
        check(ncrypt.NCryptOpenStorageProvider(provider, key.provider?.let(::WString), 0) == 0) { "NCryptOpenStorageProvider failed" }
        try {
            val opened = ncrypt.NCryptOpenKey(provider.value, handle, WString(key.container), 0, machine or SILENT) == 0
            if (opened) ncrypt.NCryptFreeObject(handle.value)
            return opened
        } finally {
            ncrypt.NCryptFreeObject(provider.value)
        }
    }

    @Suppress("FunctionName", "ktlint:standard:function-naming")
    interface Advapi32 : StdCallLibrary {
        fun CryptAcquireContextW(
            provider: PointerByReference,
            container: WString,
            providerName: WString?,
            providerType: Int,
            flags: Int,
        ): Boolean

        fun CryptReleaseContext(
            provider: Pointer,
            flags: Int,
        ): Boolean
    }

    const val CRYPT_MACHINE_KEYSET = 0x20

    // CRYPT_SILENT and NCRYPT_SILENT_FLAG share this value.
    const val SILENT = 0x40
}
