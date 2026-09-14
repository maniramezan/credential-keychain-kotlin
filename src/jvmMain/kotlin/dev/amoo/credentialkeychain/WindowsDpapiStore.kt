package dev.amoo.credentialkeychain

import java.io.File
import java.util.Base64

/** Current-user DPAPI ciphertext; secrets and scripts travel only through stdin. */
internal class WindowsDpapiStore(
    serviceName: String,
    accountName: String = serviceName,
    private val powershell: File? = findExecutable("powershell.exe"),
    private val storageDir: File = File(
        System.getenv("APPDATA") ?: System.getProperty("user.home"),
        "credential-keychain/${digest(credentialNamespace(serviceName, accountName))}",
    ),
    private val runner: CommandRunner = systemCommandRunner,
) : CredentialKeychain {
    override fun read(key: String): String? {
        requirePowerShell()
        val file = fileFor(key)
        if (!file.exists()) return null
        val result = run("""
            ${'$'}bytes = [System.IO.File]::ReadAllBytes('${file.absolutePath.escaped()}')
            ${'$'}plain = [System.Security.Cryptography.ProtectedData]::Unprotect(${'$'}bytes, ${'$'}null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            [Console]::Out.Write([System.Convert]::ToBase64String(${'$'}plain))
        """.trimIndent())
        return try { String(Base64.getDecoder().decode(result.stdout.trim()), Charsets.UTF_8) }
        catch (_: IllegalArgumentException) { throw KeychainUnavailableException("Windows DPAPI returned invalid data") }
    }

    override fun write(key: String, value: String) {
        if (value.isBlank()) { delete(key); return }
        requirePowerShell()
        if (!storageDir.isDirectory && !storageDir.mkdirs()) throw KeychainUnavailableException("Windows ciphertext directory cannot be created")
        val file = fileFor(key)
        val encoded = Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))
        // Use an atomic same-directory replacement; never truncate the previous ciphertext on failure.
        run("""
            ${'$'}bytes = [System.Convert]::FromBase64String('$encoded')
            ${'$'}protected = [System.Security.Cryptography.ProtectedData]::Protect(${'$'}bytes, ${'$'}null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            ${'$'}path = '${file.absolutePath.escaped()}'
            ${'$'}temp = ${'$'}path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
            try {
                [System.IO.File]::WriteAllBytes(${'$'}temp, ${'$'}protected)
                if ([System.IO.File]::Exists(${'$'}path)) {
                    [System.IO.File]::Replace(${'$'}temp, ${'$'}path, ${'$'}null)
                } else {
                    [System.IO.File]::Move(${'$'}temp, ${'$'}path)
                }
            } finally {
                if ([System.IO.File]::Exists(${'$'}temp)) { [System.IO.File]::Delete(${'$'}temp) }
            }
        """.trimIndent())
    }

    override fun delete(key: String) {
        requirePowerShell()
        val file = fileFor(key)
        if (file.exists() && !file.delete()) throw KeychainUnavailableException("Windows ciphertext cannot be deleted")
    }

    internal fun fileFor(key: String): File = File(storageDir, "${digest(key)}.bin")

    private fun requirePowerShell(): File = powershell
        ?: throw KeychainUnavailableException("Windows PowerShell is not available")

    private fun run(script: String): CommandResult {
        val input = """
            ${'$'}ErrorActionPreference = 'Stop'
            try {
                Add-Type -AssemblyName System.Security
                $script
                exit 0
            } catch {
                [Console]::Error.WriteLine(${'$'}_.Exception.Message)
                exit 1
            }

        """.trimIndent() + "\n"
        // The PowerShell exception message is a generic .NET system error (e.g. a missing
        // user profile or unsupported DPAPI scope), never the secret value or script source.
        // It still never becomes part of the thrown exception: KeychainUnavailableException
        // can propagate into a consuming app's crash reports, and the strict contract for
        // every backend in this library is that command output never reaches there.
        // Diagnostics are opt-in (CREDENTIAL_KEYCHAIN_DIAGNOSTICS=1) and go straight to this
        // process's own stderr instead, which is already visible in a CI log without that risk.
        val bootstrap = "try { \$reader = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), [System.Text.UTF8Encoding]::new(\$false)); & ([ScriptBlock]::Create(\$reader.ReadToEnd())) } catch { [Console]::Error.WriteLine(\$_.Exception.Message); exit 1 }"
        val result = runner.run(listOf(requirePowerShell().absolutePath, "-NoProfile", "-NonInteractive", "-Command", bootstrap), input)
        if (result.exitCode != 0) {
            if (diagnosticsEnabled) System.err.println("credential-keychain: Windows DPAPI diagnostic: ${result.stderr.trim()}")
            throw KeychainUnavailableException("Windows DPAPI operation failed")
        }
        return result
    }

    private fun String.escaped(): String = replace("'", "''")

    private companion object {
        /** Opt-in diagnostics; see the comment above [run]. Unset by default. */
        val diagnosticsEnabled = System.getenv("CREDENTIAL_KEYCHAIN_DIAGNOSTICS") == "1"
    }
}
