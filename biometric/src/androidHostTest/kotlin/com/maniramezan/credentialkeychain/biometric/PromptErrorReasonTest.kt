package com.maniramezan.credentialkeychain.biometric

import androidx.biometric.BiometricPrompt
import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import kotlin.test.Test
import kotlin.test.assertEquals

class PromptErrorReasonTest {
    @Test fun promptErrorsMapToReasons() {
        for (code in listOf(BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED)) {
            assertEquals(Reason.Canceled, promptErrorReason(code))
        }
        for (code in listOf(BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT)) {
            assertEquals(Reason.Locked, promptErrorReason(code))
        }
        val unsupported =
            listOf(
                BiometricPrompt.ERROR_HW_UNAVAILABLE,
                BiometricPrompt.ERROR_HW_NOT_PRESENT,
                BiometricPrompt.ERROR_NO_BIOMETRICS,
                BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
            )
        for (code in unsupported) assertEquals(Reason.Unsupported, promptErrorReason(code))
        assertEquals(Reason.Failed, promptErrorReason(BiometricPrompt.ERROR_TIMEOUT))
        assertEquals(Reason.Failed, promptErrorReason(BiometricPrompt.ERROR_VENDOR))
    }
}
