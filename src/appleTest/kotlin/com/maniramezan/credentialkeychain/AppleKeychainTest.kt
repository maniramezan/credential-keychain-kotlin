package com.maniramezan.credentialkeychain

import platform.Foundation.NSUUID
import kotlin.test.*

/** Uses a unique service and deletes every test entry, including on assertion failure. */
class AppleKeychainTest {
    @Test fun nativeKeychainRoundTripAndIsolation() {
        val service = uniqueService()
        val first = CredentialKeychain.forCurrentPlatform(service, "first")
        val second = CredentialKeychain.forCurrentPlatform(service, "second")
        try {
            assertNull(first.read("key"))
            first.write("key", "  秘密\nsecond line\n")
            assertEquals("  秘密\nsecond line\n", CredentialKeychain.forCurrentPlatform(service, "first").read("key"))
            assertNull(second.read("key"))
            second.write("key", "other")
            first.write("key", "updated")
            assertEquals("updated", first.read("key"))
            assertEquals("other", second.read("key"))
            first.delete("key")
            assertNull(first.read("key"))
            first.delete("missing")
        } finally {
            first.clear()
            second.clear()
        }
    }

    @Test fun ambiguousServiceAndKeyPairsRemainIsolated() {
        val service = uniqueService()
        val first = CredentialKeychain.forCurrentPlatform("$service.part", "account")
        val second = CredentialKeychain.forCurrentPlatform(service, "account")
        try {
            first.write("key", "first")
            second.write("part.key", "second")
            assertEquals("first", first.read("key"))
            assertEquals("second", second.read("part.key"))
        } finally {
            first.clear()
            second.clear()
        }
    }

    @Test fun clearRemovesOnlyItsOwnNamespace() {
        val service = uniqueService()
        val first = CredentialKeychain.forCurrentPlatform(service, "first")
        val second = CredentialKeychain.forCurrentPlatform(service, "second")
        val other = CredentialKeychain.forCurrentPlatform("$service-other", "first")
        try {
            first.write("a", "1")
            first.write("b", "2")
            second.write("a", "3")
            other.write("a", "4")
            first.clear()
            assertNull(first.read("a"))
            assertNull(first.read("b"))
            assertEquals("3", second.read("a"))
            assertEquals("4", other.read("a"))
            first.clear()
        } finally {
            first.clear()
            second.clear()
            other.clear()
        }
    }

    @Test fun accessibilityOptionAppliesToNewAndExistingEntries() {
        val service = uniqueService()
        val background = CredentialKeychain.forCurrentPlatform(service, "account", KeychainOptions(AppleAccessibility.AfterFirstUnlock))
        val foreground = CredentialKeychain.forCurrentPlatform(service, "account")
        try {
            background.write("key", "first")
            foreground.write("key", "second")
            assertEquals("second", background.read("key"))
            background.write("key", "third")
            assertEquals("third", foreground.read("key"))
        } finally {
            foreground.clear()
        }
    }

    private fun uniqueService() = "credential-keychain-test-${NSUUID().UUIDString}"
}
