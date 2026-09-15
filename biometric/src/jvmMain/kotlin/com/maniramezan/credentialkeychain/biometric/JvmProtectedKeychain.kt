package com.maniramezan.credentialkeychain.biometric

/** Desktop JVM has no supported path to biometric-gated secret storage. */
internal actual fun platformProtectedKeychain(
    serviceName: String,
    accountName: String,
): ProtectedKeychain = UnsupportedProtectedKeychain("desktop JVM has no biometric-protected storage")
