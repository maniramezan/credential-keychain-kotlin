plugins {
    `kotlin-dsl`
}

// Plugin versions for every module. The convention plugins apply them without versions.
dependencies {
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.20")
    implementation("com.android.tools.build:gradle:9.4.0")
    implementation("org.jetbrains.dokka:dokka-gradle-plugin:2.2.0")
    implementation("com.vanniktech:gradle-maven-publish-plugin:0.37.0")
    implementation("org.jlleitschuh.gradle:ktlint-gradle:14.2.0")
}
