// Root project: lints Gradle scripts outside the library modules and aggregates API docs.
plugins {
    id("org.jetbrains.dokka")
    id("org.jlleitschuh.gradle.ktlint")
}

// ktlint and the Dokka aggregate resolve their tools from these.
repositories {
    google()
    mavenCentral()
}

ktlint {
    version.set(BuildVersions.KTLINT)
    kotlinScriptAdditionalPaths {
        include(fileTree("verification") { include("**/*.kts") })
        include(fileTree("build-logic") { include("**/*.kts") })
    }
    filter {
        exclude("**/build/**", "**/.gradle/**", "**/.kotlin/**")
    }
}

dokka {
    moduleName.set("Credential Keychain Kotlin")
    dokkaPublications.html {
        failOnWarning.set(true)
    }
}
