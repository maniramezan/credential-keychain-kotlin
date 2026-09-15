import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinMultiplatform
import org.gradle.testing.jacoco.tasks.JacocoCoverageVerification
import org.gradle.testing.jacoco.tasks.JacocoReport
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation

// Shared by every published module. Each module sets its artifactId, Kotlin module name,
// Android namespace, POM name and description, and Dokka module name.
plugins {
    id("org.jetbrains.kotlin.multiplatform")
    id("com.android.kotlin.multiplatform.library")
    id("org.jetbrains.dokka")
    id("com.vanniktech.maven.publish")
    id("org.jlleitschuh.gradle.ktlint")
    jacoco
}

group = "com.maniramezan"
version = providers.gradleProperty("VERSION_NAME").get()
repositories {
    google()
    mavenCentral()
}

ktlint {
    version.set(BuildVersions.KTLINT)
    filter {
        exclude("**/build/**", "**/.gradle/**", "**/.kotlin/**")
    }
}

kotlin {
    explicitApi()
    @OptIn(ExperimentalAbiValidation::class)
    abiValidation()
    jvmToolchain(21)
    jvm {
        // Built with JDK 21, but published bytecode and JDK API usage target Java 17 consumers.
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
            freeCompilerArgs.add("-Xjdk-release=17")
        }
        testRuns["test"].executionTask.configure { useJUnitPlatform() }
    }
    android {
        compileSdk = 36
        minSdk = 23
        compilerOptions.jvmTarget.set(JvmTarget.JVM_11)
        withHostTestBuilder {}
        withDeviceTestBuilder { sourceSetTreeName = "test" }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }
    iosArm64()
    iosSimulatorArm64()
    macosArm64()
    tvosArm64()
    tvosSimulatorArm64()
    watchosArm64()
    watchosDeviceArm64()
    watchosSimulatorArm64()
    sourceSets {
        commonTest.dependencies { implementation(kotlin("test")) }
        getByName("androidDeviceTest").dependencies {
            implementation("androidx.test:runner:1.7.0")
            implementation("androidx.test.ext:junit:1.3.0")
        }
        jvmTest.dependencies {
            implementation(kotlin("test-junit5"))
            runtimeOnly("org.junit.platform:junit-platform-launcher")
        }
    }
}

mavenPublishing {
    configure(KotlinMultiplatform(javadocJar = JavadocJar.Dokka("dokkaGeneratePublicationHtml")))
    publishToMavenCentral(automaticRelease = false)
    if (providers.gradleProperty("releaseSigning").orNull == "true") {
        signAllPublications()
    }
    pom {
        url.set("https://github.com/maniramezan/credential-keychain-kotlin")
        inceptionYear.set("2026")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("maniramezan")
                name.set("Mani Ramezan")
                url.set("https://github.com/maniramezan")
            }
        }
        scm {
            url.set("https://github.com/maniramezan/credential-keychain-kotlin")
            connection.set("scm:git:https://github.com/maniramezan/credential-keychain-kotlin.git")
            developerConnection.set("scm:git:ssh://git@github.com/maniramezan/credential-keychain-kotlin.git")
        }
    }
}

dokka {
    dokkaPublications.html {
        failOnWarning.set(true)
        suppressInheritedMembers.set(true)
    }
    dokkaSourceSets.configureEach {
        reportUndocumented.set(true)
        includes.from("module.md")
        sourceLink {
            localDirectory.set(file("src"))
            val modulePath = projectDir.relativeTo(rootDir).invariantSeparatorsPath
            remoteUrl.set(uri("https://github.com/maniramezan/credential-keychain-kotlin/tree/main/$modulePath/src"))
            remoteLineSuffix.set("#L")
        }
    }
}

jacoco { toolVersion = BuildVersions.JACOCO }
val jvmTests = tasks.named<Test>("jvmTest")
val jvmClasses =
    kotlin.targets
        .getByName("jvm")
        .compilations
        .getByName("main")
        .output.classesDirs

// This report covers commonMain as compiled for JVM and jvmMain. It makes no
// claim about Android or native Apple execution coverage.
val jvmCoverageReport =
    tasks.register<JacocoReport>("jvmCoverageReport") {
        group = "verification"
        description = "HTML and XML coverage for common/JVM production code."
        dependsOn(jvmTests)
        executionData(jvmTests.get())
        classDirectories.setFrom(jvmClasses)
        sourceDirectories.setFrom(files("src/commonMain/kotlin", "src/jvmMain/kotlin"))
        reports {
            html.required.set(true)
            xml.required.set(true)
        }
    }
val jvmCoverageVerification =
    tasks.register<JacocoCoverageVerification>("jvmCoverageVerification") {
        group = "verification"
        dependsOn(jvmCoverageReport)
        executionData(jvmTests.get())
        classDirectories.setFrom(jvmClasses)
        sourceDirectories.setFrom(files("src/commonMain/kotlin", "src/jvmMain/kotlin"))
        violationRules {
            rule {
                limit {
                    counter = "LINE"
                    minimum = "0.85".toBigDecimal()
                }
                limit {
                    counter = "BRANCH"
                    minimum = "0.70".toBigDecimal()
                }
            }
        }
    }
tasks.named("check") { dependsOn(jvmCoverageVerification) }

// One filesystem repository at the root for artifact and consumer checks, without credentials.
publishing.repositories {
    maven {
        name = "Verification"
        url = rootDir.resolve("build/verification-repository").toURI()
    }
}
