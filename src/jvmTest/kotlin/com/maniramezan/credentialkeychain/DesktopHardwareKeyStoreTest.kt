package com.maniramezan.credentialkeychain

import kotlin.test.*

class DesktopHardwareKeyStoreTest {
    @Test fun desktopJvmNeverCreatesKeysEvenWhenSoftwareKeysAreAllowed() {
        val store = HardwareKeyStore.forCurrentPlatform("hardware-key-test", "account")
        val failures =
            listOf(
                assertFailsWith<KeychainUnavailableException> { store.generate("key") },
                assertFailsWith<KeychainUnavailableException> { store.generate("key", HardwareKeySpec(allowSoftwareKeys = true)) },
                assertFailsWith<KeychainUnavailableException> { store.info("key") },
                assertFailsWith<KeychainUnavailableException> { store.sign("key", byteArrayOf(1)) },
                assertFailsWith<KeychainUnavailableException> { store.delete("key") },
                assertFailsWith<KeychainUnavailableException> { store.clear() },
            )
        failures.forEach { assertEquals(KeychainUnavailableException.Reason.Unsupported, it.reason) }
    }
}
