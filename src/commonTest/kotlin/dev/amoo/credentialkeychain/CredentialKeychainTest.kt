package dev.amoo.credentialkeychain

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

class CredentialKeychainTest {

    @Test
    fun `forCurrentPlatform returns a non-null store`() {
        assertNotNull(CredentialKeychain.forCurrentPlatform("credential-keychain-test"))
    }

    @Test
    fun `unsupported storage fails every operation`() {
        val store = UnsupportedKeychainStore("BeOS")
        assertFailsWith<KeychainUnavailableException> { store.read("key") }
        assertFailsWith<KeychainUnavailableException> { store.write("key", "secret") }
        assertFailsWith<KeychainUnavailableException> { store.write("key", "") }
        assertFailsWith<KeychainUnavailableException> { store.delete("key") }
    }

}
