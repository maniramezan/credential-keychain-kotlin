package dev.amoo.credentialkeychain

internal actual fun platformKeychain(
    serviceName: String,
    accountName: String,
): CredentialKeychain = UnsupportedKeychainStore("JavaScript has no OS keychain backend")
