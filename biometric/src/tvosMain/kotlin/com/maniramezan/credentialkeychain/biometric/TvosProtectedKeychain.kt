package com.maniramezan.credentialkeychain.biometric

/** Apple TV has no biometric sensor. */
internal actual fun platformProtectedKeychain(
    serviceName: String,
    accountName: String,
): ProtectedKeychain = UnsupportedProtectedKeychain("tvOS has no biometric authentication")
