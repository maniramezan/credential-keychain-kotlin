package dev.amoo.credentialkeychain

import kotlin.test.Test
import kotlin.test.assertFailsWith

class WebUnavailableTest {
    @Test fun factoryNeverProvidesFallbackStorage() {
        val keychain = CredentialKeychain.forCurrentPlatform("web-test", "account")
        assertFailsWith<KeychainUnavailableException> { keychain.read("key") }
        assertFailsWith<KeychainUnavailableException> { keychain.write("key", "secret") }
        assertFailsWith<KeychainUnavailableException> { keychain.write("key", " ") }
        assertFailsWith<KeychainUnavailableException> { keychain.delete("key") }
    }
}
