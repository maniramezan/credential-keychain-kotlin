import java.util.Properties

plugins {
    kotlin("multiplatform") version "2.4.20"
    id("com.android.kotlin.multiplatform.library") version "9.4.1"
}
val releaseProperties =
    Properties().apply {
        rootDir.resolve("../../gradle.properties").inputStream().use { load(it) }
    }
val keychainDependency = "com.maniramezan:credential-keychain-kotlin:${releaseProperties.getProperty("VERSION_NAME")}"
val biometricDependency = "com.maniramezan:credential-keychain-kotlin-biometric:${releaseProperties.getProperty("VERSION_NAME")}"
repositories {
    exclusiveContent {
        forRepository {
            // Defaults to the repository publishAllPublicationsToVerificationRepository writes at the root.
            val verificationRepository =
                providers
                    .gradleProperty("verificationRepository")
                    .orElse(rootDir.resolve("../../build/verification-repository").canonicalPath)
            maven { url = uri(verificationRepository.get()) }
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
            export(biometricDependency)
        }
    }
    macosArm64 {
        binaries.framework {
            baseName = "KeychainConsumer"
            export(keychainDependency)
            export(biometricDependency)
        }
    }
    tvosArm64()
    tvosSimulatorArm64()
    watchosArm64()
    watchosDeviceArm64()
    watchosSimulatorArm64()
    sourceSets.commonMain.dependencies {
        api(keychainDependency)
        api(biometricDependency)
    }
}
