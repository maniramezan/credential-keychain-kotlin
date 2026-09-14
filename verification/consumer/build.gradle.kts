import java.util.Properties

plugins {
    kotlin("multiplatform") version "2.4.20"
    id("com.android.kotlin.multiplatform.library") version "9.4.0"
}
val releaseProperties =
    Properties().apply {
        rootDir.resolve("../../gradle.properties").inputStream().use { load(it) }
    }
val keychainDependency = "com.maniramezan:credential-keychain-kotlin:${releaseProperties.getProperty("VERSION_NAME")}"
repositories {
    exclusiveContent {
        forRepository {
            maven { url = uri(providers.gradleProperty("verificationRepository").get()) }
        }
        filter { includeGroup("com.maniramezan") }
    }
    google()
    mavenCentral()
}
kotlin {
    jvmToolchain(21)
    jvm()
    android {
        namespace = "com.maniramezan.keychain.consumer"
        compileSdk = 36
        minSdk = 23
    }
    iosArm64()
    iosSimulatorArm64 {
        // Hosted in a simulator app by scripts/apple-simulator-tests.sh.
        binaries.framework {
            baseName = "KeychainConsumer"
            export(keychainDependency)
        }
    }
    macosArm64 {
        binaries.framework {
            baseName = "KeychainConsumer"
            export(keychainDependency)
        }
    }
    tvosArm64()
    tvosSimulatorArm64()
    watchosArm64()
    watchosDeviceArm64()
    watchosSimulatorArm64()
    sourceSets.commonMain.dependencies {
        api(keychainDependency)
    }
}
