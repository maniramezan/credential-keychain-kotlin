package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import com.sun.jna.Memory
import com.sun.jna.Native
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.*

class JnaWindowsApiTest {
    /** Pointers and 32-bit fields align the same on every 64-bit ABI, so this also checks Win64. */
    @Test fun structuresMatchTheWin64Layouts() {
        assumeTrue(Native.POINTER_SIZE == 8)
        assertEquals(16, JnaWindowsApi.DataBlob().size())
        assertEquals(80, JnaWindowsApi.Credential().size())
        assertEquals(48, JnaWindowsApi.KeyProviderInfo(Memory(48)).size())
    }

    @Test fun dataBlobsOwnAndWipeACopy() {
        val bytes = byteArrayOf(1, 2, 3)
        val blob = JnaWindowsApi.DataBlob(bytes)
        bytes.fill(0)
        assertEquals(3, blob.cbData)
        assertContentEquals(byteArrayOf(1, 2, 3), assertNotNull(blob.pbData).getByteArray(0, 3))
        blob.wipe()
        assertContentEquals(byteArrayOf(0, 0, 0), assertNotNull(blob.pbData).getByteArray(0, 3))
        assertEquals(0, JnaWindowsApi.DataBlob(ByteArray(0)).cbData)
    }

    @Test fun hostsWithoutWin32AreUnsupported() {
        assumeFalse(desktopOs() == DesktopOs.Windows)
        val failures =
            listOf(
                assertFailsWith<KeychainUnavailableException> { WindowsDpapiStore("test").read("key") },
                assertFailsWith<KeychainUnavailableException> { WindowsCredentialManagerStore("test").findAll("api") },
                assertFailsWith<KeychainUnavailableException> { WindowsCertificateBackend().deleteIdentity("label") },
            )
        failures.forEach { assertEquals(Reason.Unsupported, it.reason) }
    }
}
