plugins {
    id("credentialkeychain.library")
}

// The Gradle project is :biometric, but Kotlin module and klib names keep the artifact's name.
kotlinModuleName("credential-keychain-kotlin-biometric")

kotlin {
    // LocalAuthentication exists on iOS and macOS only; tvOS and watchOS get Unsupported stores.
    @OptIn(org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common {
            group("apple") {
                group("localAuthentication") {
                    withIos()
                    withMacos()
                }
            }
        }
    }
    android {
        namespace = "com.maniramezan.credentialkeychain.biometric"
    }
    sourceSets {
        commonMain.dependencies {
            // KeychainUnavailableException and its reasons are part of this module's API.
            api(project(":core"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
        }
        androidMain.dependencies {
            // FragmentActivity appears in the Android factory's signature.
            api("androidx.fragment:fragment:1.8.9")
            implementation("androidx.biometric:biometric:1.1.0")
        }
        commonTest.dependencies {
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
        }
    }
}

mavenPublishing {
    coordinates(artifactId = "credential-keychain-kotlin-biometric")
    pom {
        name.set("Credential Keychain Kotlin Biometric")
        description.set("Kotlin Multiplatform secrets that require biometric authentication to read")
    }
}

dokka {
    moduleName.set("credential-keychain-kotlin-biometric")
}
