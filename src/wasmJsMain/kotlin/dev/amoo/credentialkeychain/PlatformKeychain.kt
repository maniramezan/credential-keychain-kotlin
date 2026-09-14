package dev.amoo.credentialkeychain

internal actual fun platformKeychain(serviceName: String, accountName: String): CredentialKeychain =
    UnsupportedKeychainStore("WebAssembly has no OS keychain backend")
