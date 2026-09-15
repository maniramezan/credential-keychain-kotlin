pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}
rootProject.name = "credential-keychain-kotlin"

// Published as com.maniramezan:credential-keychain-kotlin.
include(":core")

// Published as com.maniramezan:credential-keychain-kotlin-biometric.
include(":biometric")
