package com.maniramezan.credentialkeychain

/** In-memory [WindowsApi]; "ciphertext" is the plaintext reversed behind a marker. */
internal class FakeWindowsApi : WindowsApi {
    val credentials = linkedMapOf<String, WindowsCredential>()
    val identities = linkedMapOf<String, ByteArray>()
    val calls = mutableListOf<String>()

    /** Thrown by every call when set. */
    var failure: Exception? = null

    override fun protect(plaintext: ByteArray): ByteArray = call("protect") { MARKER + plaintext.reversedArray() }

    override fun unprotect(ciphertext: ByteArray): ByteArray =
        call("unprotect") {
            check(ciphertext.take(MARKER.size) == MARKER.toList()) { "sensitive ciphertext detail" }
            ciphertext.copyOfRange(MARKER.size, ciphertext.size).reversedArray()
        }

    override fun writeCredential(
        target: String,
        userName: String,
        secret: ByteArray,
    ) = call("writeCredential") { credentials[target] = WindowsCredential(target, userName, secret.copyOf()) }

    override fun readCredential(target: String): WindowsCredential? = call("readCredential") { credentials[target]?.copy() }

    /** Matches like `CredEnumerateW`: a trailing `*` matches any suffix. */
    override fun enumerateCredentials(filter: String): List<WindowsCredential> =
        call("enumerateCredentials") {
            val prefix = filter.removeSuffix("*")
            credentials.values.filter { if (prefix == filter) it.target == filter else it.target.startsWith(prefix) }.map { it.copy() }
        }

    override fun deleteCredential(target: String) {
        call("deleteCredential") { credentials.remove(target) }
    }

    override fun importIdentity(
        friendlyName: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ) = call("importIdentity") { identities[friendlyName] = pkcs12.copyOf() + String(passphrase).toByteArray() }

    override fun deleteIdentities(friendlyName: String) {
        call("deleteIdentities") { identities.remove(friendlyName) }
    }

    private fun WindowsCredential.copy() = WindowsCredential(target, userName, secret.copyOf())

    private fun <T> call(
        name: String,
        block: () -> T,
    ): T {
        calls += name
        failure?.let { throw it }
        return block()
    }

    companion object {
        val MARKER = "dpapi:".toByteArray()
    }
}
