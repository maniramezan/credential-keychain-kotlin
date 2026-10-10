import org.gradle.testing.jacoco.tasks.JacocoReportBase

plugins {
    id("credentialkeychain.library")
}

// The Gradle project is :core, but Kotlin module and klib names keep the artifact's name.
kotlinModuleName("credential-keychain-kotlin")

kotlin {
    android {
        namespace = "com.maniramezan.credentialkeychain"
    }
    sourceSets {
        // Windows backends call DPAPI, Credential Manager, and CryptoAPI in-process.
        jvmMain.dependencies { implementation("net.java.dev.jna:jna:5.19.1") }
    }
}

// The JNA bindings only run on Windows, where the real-store tests cover them.
if (!System.getProperty("os.name").startsWith("Windows")) {
    tasks.withType<JacocoReportBase>().configureEach {
        val classes = classDirectories.files
        classDirectories.setFrom(files(classes).asFileTree.matching { exclude("**/JnaWindowsApi*") })
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
