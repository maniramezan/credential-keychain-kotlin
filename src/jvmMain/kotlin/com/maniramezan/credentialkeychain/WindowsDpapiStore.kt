package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.util.Base64

/** Current-user DPAPI ciphertext; secrets and scripts travel only through stdin. */
internal class WindowsDpapiStore(
    serviceName: String,
    accountName: String = serviceName,
    powershell: File? = findExecutable("powershell.exe"),
    private val storageDir: File =
        File(
            System.getenv("LOCALAPPDATA") ?: System.getenv("APPDATA") ?: System.getProperty("user.home"),
            "credential-keychain/${digest(credentialNamespace(serviceName, accountName))}",
        ),
    runner: CommandRunner = systemCommandRunner,
) : CredentialKeychain {
    private val shell = PowerShell(powershell, runner)

    override fun read(key: String): String? {
        shell.requireExecutable()
        val file = fileFor(key)
        if (!file.exists()) return null
        val result =
            run(
                """
                ${'$'}bytes = [System.IO.File]::ReadAllBytes(${PowerShell.literal(file.absolutePath)})
                ${'$'}plain = [System.Security.Cryptography.ProtectedData]::Unprotect(${'$'}bytes, ${'$'}null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                [Console]::Out.Write([System.Convert]::ToBase64String(${'$'}plain))
                """.trimIndent(),
            )
        return try {
            String(Base64.getDecoder().decode(result.stdout.trim()), Charsets.UTF_8)
        } catch (
            _: IllegalArgumentException,
        ) {
            throw KeychainUnavailableException(Reason.Corrupted, "Windows DPAPI returned invalid data")
        }
    }

    override fun write(
        key: String,
        value: String,
    ) {
        shell.requireExecutable()
        if (!storageDir.isDirectory &&
            !storageDir.mkdirs()
        ) {
            throw commandFailure("Windows ciphertext directory cannot be created")
        }
        val file = fileFor(key)
        val encoded = Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))
        // Use an atomic same-directory replacement; never truncate the previous ciphertext on
        // failure. File.Replace's backup argument uses NullString.Value rather than $null:
        // Windows PowerShell 5.1 coerces $null to an empty string for a String parameter, and
        // File.Replace rejects "" as an illegal backup path.
        run(
            """
            ${'$'}bytes = [System.Convert]::FromBase64String('$encoded')
            ${'$'}protected = [System.Security.Cryptography.ProtectedData]::Protect(${'$'}bytes, ${'$'}null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            ${'$'}path = ${PowerShell.literal(file.absolutePath)}
            ${'$'}temp = ${'$'}path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
            try {
                [System.IO.File]::WriteAllBytes(${'$'}temp, ${'$'}protected)
                if ([System.IO.File]::Exists(${'$'}path)) {
                    [System.IO.File]::Replace(${'$'}temp, ${'$'}path, [System.Management.Automation.Language.NullString]::Value)
                } else {
                    [System.IO.File]::Move(${'$'}temp, ${'$'}path)
                }
            } finally {
                if ([System.IO.File]::Exists(${'$'}temp)) { [System.IO.File]::Delete(${'$'}temp) }
            }
            """.trimIndent(),
        )
    }

    override fun delete(key: String) {
        shell.requireExecutable()
        val file = fileFor(key)
        if (file.exists() && !file.delete()) throw commandFailure("Windows ciphertext cannot be deleted")
    }

    override fun clear() {
        shell.requireExecutable()
        storageDir.listFiles()?.forEach { if (!it.delete()) throw commandFailure("Windows ciphertext cannot be deleted") }
        if (storageDir.exists() && !storageDir.delete()) throw commandFailure("Windows ciphertext directory cannot be deleted")
    }

    internal fun fileFor(key: String): File = File(storageDir, "${digest(key)}.bin")

    private fun run(script: String): CommandResult = shell.run(script, "Windows DPAPI operation failed")
}
