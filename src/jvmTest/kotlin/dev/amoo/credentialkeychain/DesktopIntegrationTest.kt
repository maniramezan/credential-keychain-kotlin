package dev.amoo.credentialkeychain

import org.junit.jupiter.api.Assumptions.assumeTrue
import java.util.UUID
import kotlin.test.*

class DesktopIntegrationTest {
    @Test fun realStoreRoundTrip() {
        assumeTrue(System.getenv("CREDENTIAL_KEYCHAIN_INTEGRATION") == "1")
        val service = "keychain-test-${UUID.randomUUID()}"
        val first = CredentialKeychain.forCurrentPlatform(service, "first")
        val second = CredentialKeychain.forCurrentPlatform(service, "second")
        try {
            assertNull(first.read("key"))
            first.write("key", "secret ' \" \\ 秘密")
            assertEquals("secret ' \" \\ 秘密", CredentialKeychain.forCurrentPlatform(service, "first").read("key"))
            assertNull(second.read("key"))
            second.write("key", "other")
            for (value in listOf("616263", "e7a798e5af86", "  spaced  ", "a\tb", "秘密", "0x616263")) {
                first.write("key", value)
                assertEquals(value, first.read("key"))
            }
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
}
