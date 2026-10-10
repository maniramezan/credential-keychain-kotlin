package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

/** Current-user DPAPI ciphertext files, encrypted and decrypted in-process; plaintext never touches disk. */
internal class WindowsDpapiStore(
    serviceName: String,
    accountName: String = serviceName,
    private val storageDir: File =
        File(
            System.getenv("LOCALAPPDATA") ?: System.getenv("APPDATA") ?: System.getProperty("user.home"),
            "credential-keychain/${digest(credentialNamespace(serviceName, accountName))}",
        ),
    private val windowsApi: () -> WindowsApi = ::systemWindowsApi,
) : CredentialKeychain {
    override fun read(key: String): String? =
        dpapi { dpapi ->
            val file = fileFor(key)
            if (!file.exists()) return@dpapi null
            val plaintext = dpapi.unprotect(file.readBytes())
            try {
                plaintext.decodeStrictUtf8() ?: throw KeychainUnavailableException(Reason.Corrupted, "Windows DPAPI returned invalid data")
            } finally {
                plaintext.fill(0)
            }
        }

    override fun write(
        key: String,
        value: String,
    ): Unit =
        dpapi { dpapi ->
            if (!storageDir.isDirectory &&
                !storageDir.mkdirs()
            ) {
                throw commandFailure("Windows ciphertext directory cannot be created")
            }
            val plaintext = value.toByteArray(Charsets.UTF_8)
            val ciphertext =
                try {
                    dpapi.protect(plaintext)
                } finally {
                    plaintext.fill(0)
                }
            // Replace atomically within the directory; never truncate the previous ciphertext on failure.
            val file = fileFor(key)
            val temp = File(storageDir, "${file.name}.${UUID.randomUUID().toString().replace("-", "")}.tmp")
            try {
                temp.writeBytes(ciphertext)
                Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } finally {
                temp.delete()
            }
        }

    override fun delete(key: String) =
        dpapi {
            val file = fileFor(key)
            if (file.exists() && !file.delete()) throw commandFailure("Windows ciphertext cannot be deleted")
        }

    override fun clear() =
        dpapi {
            storageDir.listFiles()?.forEach { if (!it.delete()) throw commandFailure("Windows ciphertext cannot be deleted") }
            if (storageDir.exists() && !storageDir.delete()) throw commandFailure("Windows ciphertext directory cannot be deleted")
        }

    internal fun fileFor(key: String): File = File(storageDir, "${digest(key)}.bin")

    /** Every operation needs the native layer, so a host without it is unsupported even for missing keys. */
    private inline fun <T> dpapi(block: (WindowsApi) -> T): T = windowsCall(windowsApi, "Windows DPAPI operation failed", block)
}
