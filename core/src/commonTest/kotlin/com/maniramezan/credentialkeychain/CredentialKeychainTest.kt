package com.maniramezan.credentialkeychain

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

class CredentialKeychainTest {
    @Test
    fun forCurrentPlatformReturnsANonNullStore() {
        assertNotNull(CredentialKeychain.forCurrentPlatform("credential-keychain-test"))
        assertNotNull(CredentialKeychain.forCurrentPlatform("credential-keychain-test", "account", KeychainOptions()))
    }

    @Test
    fun unsupportedStorageFailsEveryOperation() {
        val store = UnsupportedKeychainStore("BeOS")
        val failures =
            listOf(
                assertFailsWith<KeychainUnavailableException> { store.read("key") },
                assertFailsWith<KeychainUnavailableException> { store.write("key", "secret") },
                assertFailsWith<KeychainUnavailableException> { store.delete("key") },
                assertFailsWith<KeychainUnavailableException> { store.clear() },
            )
        failures.forEach { assertEquals(KeychainUnavailableException.Reason.Unsupported, it.reason) }
    }

    @Test
    fun optionsDefaultToTheMostRestrictiveAccessibilityAndRejectInvalidTimeouts() {
        val defaults = KeychainOptions()
        assertEquals(AppleAccessibility.WhenUnlocked, defaults.appleAccessibility)
        assertEquals(30.seconds, defaults.desktopCommandTimeout)
        assertFailsWith<IllegalArgumentException> { KeychainOptions(desktopCommandTimeout = Duration.ZERO) }
        assertFailsWith<IllegalArgumentException> { KeychainOptions(desktopCommandTimeout = -1.seconds) }
        assertFailsWith<IllegalArgumentException> { KeychainOptions(desktopCommandTimeout = Duration.INFINITE) }
    }

    @Test
    fun exceptionsExposeReasonAndCause() {
        val cause = RuntimeException("backend")
        val error = KeychainUnavailableException(KeychainUnavailableException.Reason.Locked, "device locked", cause)
        assertEquals(KeychainUnavailableException.Reason.Locked, error.reason)
        assertSame(cause, error.cause)
        assertEquals("Secure credential storage is not available (Locked): device locked.", error.message)
    }
}
