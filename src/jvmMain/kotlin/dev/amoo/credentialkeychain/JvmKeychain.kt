package dev.amoo.credentialkeychain

internal actual fun platformKeychain(serviceName: String, accountName: String): CredentialKeychain {
    val osName = System.getProperty("os.name").orEmpty()
    return when {
        osName.contains("Mac", ignoreCase = true) -> MacOSKeychainStore(serviceName, accountName)
        osName.contains("Linux", ignoreCase = true) -> LinuxSecretServiceStore(serviceName, accountName)
        osName.contains("Windows", ignoreCase = true) -> WindowsDpapiStore(serviceName, accountName)
        else -> UnsupportedKeychainStore(osName)
    }
}
