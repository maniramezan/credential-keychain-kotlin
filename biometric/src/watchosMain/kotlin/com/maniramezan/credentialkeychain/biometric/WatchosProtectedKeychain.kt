package com.maniramezan.credentialkeychain.biometric

/** Apple Watch has no Face ID or Touch ID for keychain items. */
internal actual fun platformProtectedKeychain(
    serviceName: String,
    accountName: String,
): ProtectedKeychain = UnsupportedProtectedKeychain("watchOS has no biometric authentication")
