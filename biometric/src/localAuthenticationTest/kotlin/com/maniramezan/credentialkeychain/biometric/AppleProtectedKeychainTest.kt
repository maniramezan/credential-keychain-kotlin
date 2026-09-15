@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.maniramezan.credentialkeychain.biometric

import com.maniramezan.credentialkeychain.KeychainUnavailableException
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlinx.coroutines.test.runTest
import platform.LocalAuthentication.LAErrorBiometryLockout
import platform.LocalAuthentication.LAErrorBiometryNotAvailable
import platform.LocalAuthentication.LAErrorBiometryNotEnrolled
import platform.LocalAuthentication.LAErrorPasscodeNotSet
import platform.Security.errSecAuthFailed
import platform.Security.errSecInteractionNotAllowed
import platform.Security.errSecMissingEntitlement
import platform.Security.errSecNotAvailable
import platform.Security.errSecUserCanceled
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class AppleProtectedKeychainTest {
    @Test fun securityStatusesMapToReasons() {
        assertEquals(Reason.Canceled, statusFailure(errSecUserCanceled).reason)
        assertEquals(Reason.Locked, statusFailure(errSecAuthFailed).reason)
        assertEquals(Reason.Locked, statusFailure(errSecInteractionNotAllowed).reason)
        assertEquals(Reason.Unsupported, statusFailure(errSecMissingEntitlement).reason)
        assertEquals(Reason.Unsupported, statusFailure(errSecNotAvailable).reason)
        assertEquals(Reason.Failed, statusFailure(-1).reason)
    }

    @Test fun biometryErrorsMapToReasons() {
        assertNull(biometryFailure(null, reading = true))
        assertEquals(Reason.Locked, biometryFailure(LAErrorBiometryLockout, reading = true)?.reason)
        assertEquals(Reason.AuthenticationInvalidated, biometryFailure(LAErrorBiometryNotEnrolled, reading = true)?.reason)
        assertEquals(Reason.AuthenticationInvalidated, biometryFailure(LAErrorPasscodeNotSet, reading = true)?.reason)
        assertEquals(Reason.Unsupported, biometryFailure(LAErrorBiometryNotEnrolled, reading = false)?.reason)
        assertEquals(Reason.Unsupported, biometryFailure(LAErrorBiometryNotAvailable, reading = false)?.reason)
    }

    /**
     * Test executables have no keychain entitlements or enrolled biometrics, so the real store
     * must report Unsupported rather than storing anything. The simulator app harness covers
     * the entitled round trip.
     */
    @Test fun unentitledProcessesGetUnsupported() =
        runTest {
            val store = ProtectedKeychain.forCurrentPlatform("credential-keychain-biometric-tests-${Random.nextLong()}", "tests")
            val prompt = AuthenticationPrompt("Unlock", cancelLabel = "Cancel")
            val write = runCatching { store.write("key", "value") }.exceptionOrNull() as? KeychainUnavailableException
            assertEquals(Reason.Unsupported, write?.reason)
            val read = runCatching { store.read("key", prompt) }
            read.exceptionOrNull()?.let { assertEquals(Reason.Unsupported, (it as KeychainUnavailableException).reason) }
            if (read.isSuccess) assertNull(read.getOrNull())
            runCatching { store.clear() }.exceptionOrNull()?.let {
                assertEquals(
                    Reason.Unsupported,
                    (it as KeychainUnavailableException).reason,
                )
            }
        }
}
