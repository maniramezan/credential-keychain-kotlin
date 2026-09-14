package com.maniramezan.credentialkeychain

// The Android Keystore certificate backend follows in its own change.
internal actual fun platformCertificateStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CertificateStore = UnsupportedCertificateStore("Android certificate storage is not available yet")
