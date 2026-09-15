package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File

/** Runs Windows PowerShell scripts that are supplied only through stdin, never as process arguments. */
internal class PowerShell(
    private val executable: File?,
    private val runner: CommandRunner,
) {
    fun requireExecutable(): File =
        executable ?: throw KeychainUnavailableException(Reason.Unsupported, "Windows PowerShell is not available")

    /** Runs [script] with `$ErrorActionPreference = 'Stop'`; any failure throws with [failureMessage]. */
    fun run(
        script: String,
        failureMessage: String,
    ): CommandResult {
        val input =
            """
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
        // Never forward backend diagnostics: parser failures can include script source and secrets.
        val bootstrap =
            "try { \$reader = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), " +
                "[System.Text.UTF8Encoding]::new(\$false)); & ([ScriptBlock]::Create(\$reader.ReadToEnd())) } " +
                "catch { exit 1 }"
        val result = runner.run(listOf(requireExecutable().absolutePath, "-NoProfile", "-NonInteractive", "-Command", bootstrap), input)
        if (result.exitCode != 0) throw commandFailure(failureMessage)
        return result
    }

    companion object {
        /** A single-quoted PowerShell string literal; nothing inside it is interpolated. */
        fun literal(value: String): String = "'" + value.replace("'", "''") + "'"
    }
}
