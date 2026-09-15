package com.maniramezan.credentialkeychain

import kotlin.test.*

class HardwareKeyStoreTest {
    @Test fun factoriesValidateTheNamespace() {
        assertNotNull(HardwareKeyStore.forCurrentPlatform("hardware-key-test"))
        assertNotNull(HardwareKeyStore.forCurrentPlatform("hardware-key-test", "account", KeychainOptions()))
        assertEquals(
            "serviceName must not be blank.",
            assertFailsWith<IllegalArgumentException> {
                HardwareKeyStore.forCurrentPlatform("")
            }.message,
        )
        assertFailsWith<IllegalArgumentException> { HardwareKeyStore.forCurrentPlatform("service", "a\rb") }
    }

    @Test fun invalidAliasesNeverReachTheBackend() {
        val backend = RecordingHardwareKeyStore()
        val store = ValidatingHardwareKeyStore(backend)
        for (invalid in listOf("", " ", "a\nb", "a\u0000b")) {
            assertFailsWith<IllegalArgumentException> { store.generate(invalid) }
            assertFailsWith<IllegalArgumentException> { store.info(invalid) }
            assertFailsWith<IllegalArgumentException> { store.sign(invalid, byteArrayOf(1)) }
            assertFailsWith<IllegalArgumentException> { store.delete(invalid) }
        }
        assertEquals("alias must not be blank.", assertFailsWith<IllegalArgumentException> { store.info(" ") }.message)
        assertEquals(emptyList(), backend.calls)
        store.generate("signing", HardwareKeySpec(allowSoftwareKeys = true))
        store.info("signing")
        store.sign("signing", byteArrayOf())
        store.delete("signing")
        store.clear()
        assertEquals(listOf("generate:signing:true", "info:signing", "sign:signing:0", "delete:signing", "clear"), backend.calls)
    }

    @Test fun unsupportedStoreFailsEveryOperation() {
        val store = UnsupportedHardwareKeyStore("BeOS")
        val failures =
            listOf(
                assertFailsWith<KeychainUnavailableException> { store.generate("key") },
                assertFailsWith<KeychainUnavailableException> { store.info("key") },
                assertFailsWith<KeychainUnavailableException> { store.sign("key", byteArrayOf(1)) },
                assertFailsWith<KeychainUnavailableException> { store.delete("key") },
                assertFailsWith<KeychainUnavailableException> { store.clear() },
            )
        failures.forEach { assertEquals(KeychainUnavailableException.Reason.Unsupported, it.reason) }
    }

    @Test fun keyInfoIsImmutableAndComparesByValue() {
        val source = byteArrayOf(1, 2, 3)
        val info = HardwareKeyInfo("signing", source, SecurityLevel.StrongBox)
        source[0] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), info.publicKeyDer)
        info.publicKeyDer[0] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), info.publicKeyDer)
        assertEquals(HardwareKeyInfo("signing", byteArrayOf(1, 2, 3), SecurityLevel.StrongBox), info)
        assertEquals(HardwareKeyInfo("signing", byteArrayOf(1, 2, 3), SecurityLevel.StrongBox).hashCode(), info.hashCode())
        assertNotEquals(HardwareKeyInfo("signing", byteArrayOf(1, 2, 4), SecurityLevel.StrongBox), info)
        assertNotEquals(HardwareKeyInfo("signing", byteArrayOf(1, 2, 3), SecurityLevel.Software), info)
        assertNotEquals(HardwareKeyInfo("other", byteArrayOf(1, 2, 3), SecurityLevel.StrongBox), info)
        assertEquals("HardwareKeyInfo(alias=signing, securityLevel=StrongBox, publicKeyDer=3 bytes)", info.toString())
        assertEquals(HardwareKeySpec(), HardwareKeySpec(allowSoftwareKeys = false))
        assertNotEquals(HardwareKeySpec(), HardwareKeySpec(allowSoftwareKeys = true))
        assertEquals(HardwareKeySpec(true).hashCode(), HardwareKeySpec(true).hashCode())
        assertEquals("HardwareKeySpec(allowSoftwareKeys=true)", HardwareKeySpec(true).toString())
    }

    @Test fun uncompressedP256PointsAreWrappedAsSubjectPublicKeyInfo() {
        val point = ByteArray(65) { if (it == 0) 0x04 else it.toByte() }
        val der = assertNotNull(p256SubjectPublicKeyInfo(point))
        assertEquals(91, der.size)
        assertContentEquals(P256_PUBLIC_KEY_PREFIX, der.copyOfRange(0, 26))
        assertContentEquals(point, der.copyOfRange(26, 91))
        assertNull(p256SubjectPublicKeyInfo(point.copyOf(64)))
        assertNull(p256SubjectPublicKeyInfo(point.copyOf().apply { this[0] = 0x02 }))
    }

    private class RecordingHardwareKeyStore : HardwareKeyStore {
        val calls = mutableListOf<String>()

        override fun generate(
            alias: String,
            spec: HardwareKeySpec,
        ): HardwareKeyInfo {
            calls += "generate:$alias:${spec.allowSoftwareKeys}"
            return HardwareKeyInfo(alias, byteArrayOf(1), SecurityLevel.Software)
        }

        override fun info(alias: String): HardwareKeyInfo? {
            calls += "info:$alias"
            return null
        }

        override fun sign(
            alias: String,
            data: ByteArray,
        ): ByteArray? {
            calls += "sign:$alias:${data.size}"
            return null
        }

        override fun delete(alias: String) {
            calls += "delete:$alias"
        }

        override fun clear() {
            calls += "clear"
        }
    }
}
