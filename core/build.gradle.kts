plugins {
    id("credentialkeychain.library")
}

// The Gradle project is :core, but Kotlin module and klib names keep the artifact's name.
kotlinModuleName("credential-keychain-kotlin")

kotlin {
    android {
        namespace = "com.maniramezan.credentialkeychain"
    }
}

mavenPublishing {
    coordinates(artifactId = "credential-keychain-kotlin")
    pom {
        name.set("Credential Keychain Kotlin")
        description.set("Kotlin Multiplatform credentials backed by platform secure storage")
    }
}

dokka {
    moduleName.set("credential-keychain-kotlin")
}
