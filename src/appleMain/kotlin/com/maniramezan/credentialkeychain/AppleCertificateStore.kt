package com.maniramezan.credentialkeychain

// The Apple Keychain identity backend follows in its own change.
internal actual fun platformCertificateStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CertificateStore = UnsupportedCertificateStore("Apple certificate storage is not available yet")
