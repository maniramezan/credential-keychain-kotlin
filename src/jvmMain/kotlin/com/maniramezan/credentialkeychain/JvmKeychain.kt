package com.maniramezan.credentialkeychain

internal actual fun platformKeychain(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CredentialKeychain {
    val runner = commandRunner(options.desktopCommandTimeout)
    return when (desktopOs()) {
        DesktopOs.MacOS -> MacOSKeychainStore(serviceName, accountName, runner = runner)
        DesktopOs.Linux -> LinuxKeyringStore(serviceName, accountName, runner = runner)
        DesktopOs.Windows -> WindowsDpapiStore(serviceName, accountName, runner = runner)
        DesktopOs.Other -> UnsupportedKeychainStore(unsupportedOsName())
    }
}

internal actual fun platformPasswordStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): PasswordStore {
    val runner = commandRunner(options.desktopCommandTimeout)
    return when (desktopOs()) {
        DesktopOs.MacOS -> MacOSPasswordStore(serviceName, accountName, runner = runner)
        DesktopOs.Linux -> LinuxPasswordStore(serviceName, accountName, runner = runner)
        DesktopOs.Windows -> WindowsCredentialManagerStore(serviceName, accountName, runner = runner)
        DesktopOs.Other -> UnsupportedPasswordStore(unsupportedOsName())
    }
}

internal enum class DesktopOs { MacOS, Linux, Windows, Other }

internal fun desktopOs(osName: String = System.getProperty("os.name").orEmpty()): DesktopOs =
    when {
        osName.contains("Mac", ignoreCase = true) -> DesktopOs.MacOS
        osName.contains("Linux", ignoreCase = true) -> DesktopOs.Linux
        osName.contains("Windows", ignoreCase = true) -> DesktopOs.Windows
        else -> DesktopOs.Other
    }

private fun unsupportedOsName(): String = System.getProperty("os.name").orEmpty().ifEmpty { "unknown operating system" }
