package com.maniramezan.credentialkeychain

internal actual fun platformKeychain(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CredentialKeychain {
    val osName = System.getProperty("os.name").orEmpty()
    val runner = commandRunner(options.desktopCommandTimeout)
    return when {
        osName.contains("Mac", ignoreCase = true) -> MacOSKeychainStore(serviceName, accountName, runner = runner)
        osName.contains("Linux", ignoreCase = true) -> LinuxKeyringStore(serviceName, accountName, runner = runner)
        osName.contains("Windows", ignoreCase = true) -> WindowsDpapiStore(serviceName, accountName, runner = runner)
        else -> UnsupportedKeychainStore(osName.ifEmpty { "unknown operating system" })
    }
}
