pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}
rootProject.name = "credential-keychain-kotlin"

// Published as io.github.maniramezan:credential-keychain-kotlin.
include(":core")

// Published as io.github.maniramezan:credential-keychain-kotlin-biometric.
include(":biometric")
