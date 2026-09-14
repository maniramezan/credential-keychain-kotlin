package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

internal fun findExecutable(name: String): java.io.File? =
    System
        .getenv("PATH")
        ?.split(java.io.File.pathSeparatorChar)
        ?.asSequence()
        ?.map { java.io.File(it, name) }
        ?.firstOrNull { it.isFile && it.canExecute() }

internal data class CommandResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
)

internal fun commandFailure(message: String): KeychainUnavailableException = KeychainUnavailableException(Reason.Failed, message)

/** Drains both streams concurrently and closes stdin even when no input is supplied. */
internal fun runCommand(
    vararg command: String,
    stdin: String? = null,
    timeout: Duration = DEFAULT_COMMAND_TIMEOUT,
): CommandResult {
    val executor =
        java.util.concurrent.Executors.newFixedThreadPool(3) { runnable ->
            Thread(runnable, "credential-keychain-process").apply { isDaemon = true }
        }
    var process: Process? = null
    try {
        val child = ProcessBuilder(command.toList()).start()
        process = child
        val stdout = executor.submit<String> { child.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() } }
        val stderr = executor.submit<String> { child.errorStream.bufferedReader(Charsets.UTF_8).use { it.readText() } }
        val writer =
            executor.submit {
                child.outputStream.bufferedWriter(Charsets.UTF_8).use { if (stdin != null) it.write(stdin) }
            }
        val deadline = System.nanoTime() + timeout.inWholeNanoseconds
        if (!child.waitFor(timeout.inWholeNanoseconds, TimeUnit.NANOSECONDS)) {
            throw commandFailure("secure storage command timed out")
        }

        fun remaining() = (deadline - System.nanoTime()).coerceAtLeast(1)
        val exitCode = child.exitValue()
        val inputDelivered =
            try {
                writer.get(remaining(), TimeUnit.NANOSECONDS)
                true
            } catch (_: ExecutionException) {
                false
            } catch (_: TimeoutException) {
                false
            }
        // A tool that fails early may close stdin unread; its exit code is then the meaningful
        // result. A successful exit without the complete input is never trusted.
        if (!inputDelivered && exitCode == 0) throw commandFailure("secure storage command did not accept its input")
        return CommandResult(
            exitCode,
            stdout.get(remaining(), TimeUnit.NANOSECONDS),
            stderr.get(remaining(), TimeUnit.NANOSECONDS),
        )
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        throw commandFailure("secure storage command interrupted")
    } catch (error: KeychainUnavailableException) {
        throw error
    } catch (_: Exception) {
        // Child output and command arguments can contain secrets; never attach them to errors.
        throw commandFailure("secure storage command failed")
    } finally {
        process?.let { child ->
            if (child.isAlive) child.destroyForcibly()
            runCatching { child.outputStream.close() }
            runCatching { child.inputStream.close() }
            runCatching { child.errorStream.close() }
        }
        executor.shutdownNow()
    }
}

internal fun digest(value: String): String =
    java.security.MessageDigest
        .getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

internal fun interface CommandRunner {
    fun run(
        arguments: List<String>,
        stdin: String?,
    ): CommandResult
}

internal val DEFAULT_COMMAND_TIMEOUT: Duration = 30.seconds

internal fun commandRunner(timeout: Duration): CommandRunner =
    CommandRunner { arguments, stdin ->
        runCommand(*arguments.toTypedArray(), stdin = stdin, timeout = timeout)
    }

internal val systemCommandRunner: CommandRunner = commandRunner(DEFAULT_COMMAND_TIMEOUT)
