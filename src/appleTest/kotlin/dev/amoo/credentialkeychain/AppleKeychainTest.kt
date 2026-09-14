package dev.amoo.credentialkeychain

import platform.Foundation.NSUUID
import kotlin.test.*

/** Uses a unique service and deletes every test entry, including on assertion failure. */
class AppleKeychainTest {
    @Test fun nativeKeychainRoundTripAndIsolation() {
        val service = "credential-keychain-test-${NSUUID().UUIDString}"
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
            first.write("key", " ")
            assertNull(first.read("key"))
            first.delete("missing")
        } finally {
            first.delete("key")
            second.delete("key")
        }
    }

    @Test fun ambiguousServiceAndKeyPairsRemainIsolated() {
        val service = "credential-keychain-test-${NSUUID().UUIDString}"
        val first = CredentialKeychain.forCurrentPlatform("$service.part", "account")
        val second = CredentialKeychain.forCurrentPlatform(service, "account")
        try {
            first.write("key", "first")
            second.write("part.key", "second")
            assertEquals("first", first.read("key"))
            assertEquals("second", second.read("part.key"))
        } finally {
            first.delete("key")
            second.delete("part.key")
        }
    }
}
