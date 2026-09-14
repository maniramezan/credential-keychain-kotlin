package dev.amoo.credentialkeychain

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

/** Drains both streams concurrently and closes stdin even when no input is supplied. */
internal fun runCommand(
    vararg command: String,
    stdin: String? = null,
    timeoutSeconds: Long = 30,
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
        val deadline =
            System.nanoTime() +
                java.util.concurrent.TimeUnit.SECONDS
                    .toNanos(timeoutSeconds)
        if (!child.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS)) {
            throw KeychainUnavailableException("secure storage command timed out")
        }

        fun remaining() = (deadline - System.nanoTime()).coerceAtLeast(1)
        writer.get(remaining(), java.util.concurrent.TimeUnit.NANOSECONDS)
        return CommandResult(
            child.exitValue(),
            stdout.get(remaining(), java.util.concurrent.TimeUnit.NANOSECONDS),
            stderr.get(remaining(), java.util.concurrent.TimeUnit.NANOSECONDS),
        )
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        throw KeychainUnavailableException("secure storage command interrupted")
    } catch (error: KeychainUnavailableException) {
        throw error
    } catch (_: Exception) {
        // Child output and command arguments can contain secrets; never attach them to errors.
        throw KeychainUnavailableException("secure storage command failed")
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

internal val systemCommandRunner =
    CommandRunner { arguments, stdin ->
        runCommand(*arguments.toTypedArray(), stdin = stdin)
    }
