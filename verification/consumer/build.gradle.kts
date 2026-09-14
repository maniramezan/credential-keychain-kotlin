import java.util.Properties

plugins {
    kotlin("multiplatform") version "2.4.20"
    id("com.android.kotlin.multiplatform.library") version "9.4.0"
}
val releaseProperties = Properties().apply {
    rootDir.resolve("../../gradle.properties").inputStream().use { load(it) }
}
repositories {
    exclusiveContent {
        forRepository {
            maven { url = uri(providers.gradleProperty("verificationRepository").get()) }
        }
        filter { includeGroup("dev.amoo") }
    }
    google()
    mavenCentral()
}
kotlin {
    jvmToolchain(21)
    jvm()
    android { namespace = "dev.amoo.keychain.consumer"; compileSdk = 36; minSdk = 23 }
    iosArm64(); iosSimulatorArm64(); iosX64()
    macosArm64(); macosX64()
    tvosArm64(); tvosSimulatorArm64(); tvosX64()
    watchosArm64(); watchosDeviceArm64(); watchosSimulatorArm64(); watchosX64()
    js(IR) { nodejs() }
    wasmJs { nodejs() }
    sourceSets.commonMain.dependencies {
        implementation("dev.amoo:credential-keychain-kotlin:${releaseProperties.getProperty("VERSION_NAME")}")
    }
}
