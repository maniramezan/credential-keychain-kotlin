# credential-keychain-kotlin

Kotlin Multiplatform storage for API keys, tokens, and passwords, backed by platform
secure storage. There is no plaintext persistence fallback.

## Platform support

| Platform | Kotlin targets | Backend |
|---|---|---|
| Android 6.0+ (API 23+) | `android` | Android Keystore AES-256-GCM; ciphertext in app-private, non-backed-up files |
| iOS | `iosArm64`, `iosSimulatorArm64`, `iosX64` | Native Apple Security framework |
| macOS | `macosArm64`, `macosX64` | Native Apple Security framework |
| tvOS | `tvosArm64`, `tvosSimulatorArm64`, `tvosX64` | Native Apple Security framework |
| watchOS | `watchosArm64`, `watchosDeviceArm64`, `watchosSimulatorArm64`, `watchosX64` | Native Apple Security framework |
| macOS desktop JVM | `jvm` | Keychain through `/usr/bin/security` |
| Linux desktop JVM | `jvm` | Secret Service through `secret-tool` |
| Windows desktop JVM | `jvm` | Current-user DPAPI through Windows PowerShell |
| Browser / Node.js | `js`, `wasmJs` | API compiles; all storage operations throw `KeychainUnavailableException` |

Windows and Linux support requires a JVM; this package does not yet publish `mingwX64`,
`linuxX64`, or `linuxArm64` native backends. Web targets provide dependency compatibility,
not secure browser persistence. They do not use localStorage, IndexedDB, or an in-memory
substitute. Android uses the Android JVM target, not Android/Native.

## Usage from shared code

```kotlin
import dev.amoo.credentialkeychain.CredentialKeychain

// Apple native or desktop JVM:
val keychain = CredentialKeychain.forCurrentPlatform(
    serviceName = "my-app",
    accountName = "user-123", // defaults to serviceName
)
keychain.write("api-key", "secret-token")
val token: String? = keychain.read("api-key")
keychain.delete("api-key")
```

Both service and account namespace entries. Inject a `CredentialKeychain` into shared
application code so Android can supply its Context-based implementation:

```kotlin
// In androidMain:
import dev.amoo.credentialkeychain.CredentialKeychain
import dev.amoo.credentialkeychain.forCurrentPlatform

val keychain = CredentialKeychain.forCurrentPlatform(
    context = applicationContext,
    serviceName = "my-app",
    accountName = "user-123",
)
```

The Context-free factory on Android returns an unavailable store. This avoids retaining
an Activity or requiring global initialization.

## Contract and requirements

- Operations are synchronous and may block or prompt for access. Use a worker thread.
- Reads return `null` for absent entries. Unavailable backends and operational failures
  throw `KeychainUnavailableException`; do not interpret them as missing credentials.
- Deleting an absent entry succeeds when the backend is available.
- Blank writes delete the entry. Other values retain whitespace. Identifiers must be
  nonblank and cannot contain NUL, CR, or LF; values cannot contain NUL.
- macOS JVM's interactive `security` backend additionally rejects CR/LF in values.
  Native Apple and Android backends accept multiline secrets.
- Apple native entries use `WhenUnlockedThisDeviceOnly` and disable synchronization.
  Apps need valid signing/Keychain access for their deployment environment.
- Android keys stay in Android Keystore; hardware backing depends on the device. Files
  contain authenticated ciphertext with the namespace and key bound as associated data.
  Ciphertext is excluded from backup because Keystore keys cannot be restored with it.
  Access is serialized within the process; sharing a store across Android processes is
  not supported. Deleting an entry retains the namespace's encryption key.
- Linux requires `secret-tool` and an accessible Secret Service session (for example,
  GNOME Keyring). Headless sessions may not have one. Credentials should stay below
  8 KiB, the input limit of commonly deployed `secret-tool` versions.
- Windows requires Windows PowerShell (`powershell.exe`) and a loaded user profile.
  Ciphertext lives under `%APPDATA%/credential-keychain/` in hashed service/account and
  key paths. DPAPI binds decryption to the Windows user, not to a particular application.
- Desktop subprocesses have a 30-second timeout. Secrets are supplied through stdin,
  and backend error output is not included in exceptions.

## Documentation and release status

The [API reference](https://maniramezan.github.io/credential-keychain-kotlin/) is the
configured GitHub Pages destination. It becomes available after repository setup and
its first successful Documentation workflow. The [release guide](docs/releasing.md)
covers verification, coverage, API baselines, Pages setup, and Maven Central staging.
Release Please maintains a release PR from conventional commits on `main`. Merging it
creates a version tag and GitHub release, then starts verification and Central staging.
Final Maven Central publication remains manual.

This checkout has not established a successful release or live deployment. After a
version is published, consume it from `mavenCentral()` with
`dev.amoo:credential-keychain-kotlin:<published-version>` in `commonMain`.

## Build and consume locally

Use JDK 21, Android SDK 36, and the Gradle wrapper. JVM artifacts require Java 21.
A macOS host with compatible Xcode is required to build all Apple artifacts.

```sh
./gradlew jvmTest
./gradlew assemble macosArm64Test jsNodeTest wasmJsNodeTest
./gradlew publishToMavenLocal
```

After local publication, a consuming KMP project can use:

```kotlin
repositories {
    mavenLocal()
    google()
    mavenCentral()
}
kotlin {
    sourceSets.commonMain.dependencies {
        implementation("dev.amoo:credential-keychain-kotlin:0.1.0") // x-release-please-version
    }
}
```

The build creates the KMP metadata publication and platform publications. Publish the
complete set when distributing the library. CI validates all 17 publications and compiles
a separate consumer against their Gradle metadata.

## Verification

```sh
./gradlew jvmCoverageVerification
./gradlew checkKotlinAbi dokkaGeneratePublicationHtml
./gradlew connectedAndroidDeviceTest
```

The common/JVM coverage gate is 85% lines and 70% branches; reports are under
`build/reports/jacoco/`. These numbers do not measure native Apple, Android, or web
execution. The [release guide](docs/releasing.md) explains the scope and platform checks.

CI configures real-store tests on Windows, macOS, and Linux, Android emulator tests on
API 23 and 35, native macOS Keychain tests, Apple/web compilation, JS/Wasm Node tests,
API compatibility, documentation, and publication-consumer checks. Reports are retained
as workflow artifacts even on failure.

Android tests include ciphertext tampering/substitution, lost keys, fresh IVs, concurrent
instances, atomic-backup recovery, and account isolation. A missing Android encryption
key causes writes to fail while old ciphertext remains; delete affected entries explicitly
before creating a replacement key.

Run desktop integration tests against a disposable namespace using:

```sh
CREDENTIAL_KEYCHAIN_INTEGRATION=1 ./gradlew jvmTest --rerun-tasks
```

Native Apple device signing, access prompts, and locked-store behavior require platform
validation before release; compilation alone does not verify them.
