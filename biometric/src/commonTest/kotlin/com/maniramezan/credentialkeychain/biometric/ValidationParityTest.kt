package com.maniramezan.credentialkeychain.biometric

import com.maniramezan.credentialkeychain.CredentialKeychain
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** The biometric module copies core's internal validators; core's public factories validate the same way. */
class ValidationParityTest {
    private val nul = Char(0)

    @Test fun identifierMessagesMatchCore() {
        val invalidNames =
            listOf(
                " " to "account",
                "service" to "",
                "ser${nul}vice" to "account",
                "service" to "acc\nount",
                "service" to "acc\rount",
            )
        for ((service, account) in invalidNames) {
            val core = assertFailsWith<IllegalArgumentException> { CredentialKeychain.forCurrentPlatform(service, account) }
            val biometric = assertFailsWith<IllegalArgumentException> { ProtectedKeychain.forCurrentPlatform(service, account) }
            assertEquals(core.message, biometric.message)
        }
    }

    @Test fun secretValueMessagesMatchCore() {
        // Both validating wrappers reject these before any backend call.
        val core = CredentialKeychain.forCurrentPlatform("validation-parity", "validation-parity")
        val biometric = ValidatingProtectedKeychain(UnsupportedProtectedKeychain("test"))
        for (value in listOf("", "  ", "a${nul}b")) {
            assertEquals(
                assertFailsWith<IllegalArgumentException> { core.write("key", value) }.message,
                assertFailsWith<IllegalArgumentException> { biometric.write("key", value) }.message,
            )
        }
    }
}
