plugins {
    id("credentialkeychain.root")
}

// build/dokka/html holds one site for every published module.
dependencies {
    dokka(project(":core"))
    dokka(project(":biometric"))
}
