# credential-keychain-kotlin

Kotlin Multiplatform storage for API keys, tokens, and passwords, backed by platform
secure storage. There is no plaintext persistence fallback: every supported platform
routes through its native secure-storage facility (Android Keystore, Apple Keychain,
macOS Keychain, Linux Secret Service, or Windows DPAPI), or the call throws.

This exists for apps and libraries that need one `CredentialKeychain` interface for
things like storing an OAuth refresh token, a scoped API key, or a user's saved
password/PAT across Android, iOS, macOS, tvOS, watchOS, and desktop JVM — without
writing a platform-specific secure-storage adapter for each target.

## Why this exists / what it does

- **One API, native storage everywhere.** `write`/`read`/`delete` behave the same
  from `commonMain`; each platform target resolves to its own OS-backed secure store.
- **No silent fallback.** If a platform can't provide secure storage (web targets,
  a missing Linux Secret Service session, an Android call without a `Context`), the
  library throws `KeychainUnavailableException` instead of writing plaintext or an
  in-memory stand-in you might mistake for durable storage.
- **Namespaced by service + account.** Multiple apps, environments, or user accounts
  sharing a device don't collide, because both `serviceName` and `accountName` are
  bound into the storage key (and into the Android Keystore AAD / Apple Keychain
  attributes) rather than just a bare key string.
- **Small, dependency-light surface.** Three methods (`read`, `write`, `delete`) and
  one exception type — see [Contract and requirements](#contract-and-requirements)
  for exact semantics before you integrate.

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

## Installation

Add the dependency to `commonMain` once it's published (see
[Documentation and release status](#documentation-and-release-status) — this package
has not published a version to Maven Central yet, so for now see
[Build and consume locally](#build-and-consume-locally)):

```kotlin
// build.gradle.kts
kotlin {
    sourceSets.commonMain.dependencies {
        implementation("dev.amoo:credential-keychain-kotlin:<published-version>")
    }
}
```

No extra platform dependency, manifest entry, or entitlement is required to link the
library. Apple targets do need Keychain access configured for your app's signing
identity at runtime (see the [Apple](#apple-ios-macos-tvos-watchos) notes below), and
desktop JVM targets shell out to an OS binary (`security`, `secret-tool`,
`powershell.exe`) that must be present on the machine — see
[Contract and requirements](#contract-and-requirements).

## Usage from shared code

The `CredentialKeychain` interface is the same on every platform: `write`, `read`,
`delete`. In `commonMain` you obtain an instance through
`CredentialKeychain.forCurrentPlatform(...)`, which resolves to the right backend for
the target actually compiling.

```kotlin
import dev.amoo.credentialkeychain.CredentialKeychain
import dev.amoo.credentialkeychain.KeychainUnavailableException

// Apple native or desktop JVM:
val keychain = CredentialKeychain.forCurrentPlatform(
    serviceName = "my-app",
    accountName = "user-123", // defaults to serviceName
)

keychain.write("api-key", "secret-token")
val token: String? = keychain.read("api-key") // null only if absent
keychain.delete("api-key")
```

Call from a worker thread/coroutine dispatcher — every operation is synchronous and a
native backend may block or prompt the user. Wrap calls that could hit an unavailable
backend (see the [platform table](#platform-support)) so a missing secure-storage
session degrades instead of crashing:

```kotlin
suspend fun readApiKey(keychain: CredentialKeychain): String? = withContext(Dispatchers.IO) {
    try {
        keychain.read("api-key")
    } catch (e: KeychainUnavailableException) {
        logger.warn("Secure storage unavailable, prompting user to re-enter credentials", e)
        null
    }
}
```

Inject a single `CredentialKeychain` into shared application code (a repository, a
`ViewModel`, DI graph) rather than calling `forCurrentPlatform` at every call site — this
is also what lets Android supply its `Context`-based implementation without `commonMain`
needing to know about `Context` at all:

```kotlin
// In androidMain:
import dev.amoo.credentialkeychain.CredentialKeychain
import dev.amoo.credentialkeychain.forCurrentPlatform

val keychain: CredentialKeychain = CredentialKeychain.forCurrentPlatform(
    context = applicationContext,
    serviceName = "my-app",
    accountName = "user-123",
)
```

The Context-free factory on Android returns an unavailable store — every call throws
`KeychainUnavailableException` — rather than silently working without one. This avoids
retaining an Activity or requiring global/`ContentProvider`-based initialization just so
`commonMain` can call a zero-arg factory.

### Example: storing an OAuth token per user account

Namespacing by `accountName` lets a multi-account app keep one secure entry per signed-in
user without you having to encode the user id into the key string yourself:

```kotlin
fun keychainFor(userId: String): CredentialKeychain =
    CredentialKeychain.forCurrentPlatform(serviceName = "com.example.myapp", accountName = userId)

fun saveTokens(userId: String, accessToken: String, refreshToken: String) {
    val keychain = keychainFor(userId)
    keychain.write("access-token", accessToken)
    keychain.write("refresh-token", refreshToken)
}

fun signOut(userId: String) {
    val keychain = keychainFor(userId)
    keychain.delete("access-token")
    keychain.delete("refresh-token")
}
```

### Example: Compose Multiplatform (shared UI, platform-supplied instance)

```kotlin
// commonMain
@Composable
fun ApiKeyScreen(keychain: CredentialKeychain) {
    var apiKey by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        apiKey = withContext(Dispatchers.Default) { keychain.read("api-key") }
    }
    // render apiKey / a form that calls keychain.write("api-key", input) on submit
}

// androidMain composition root
val keychain = CredentialKeychain.forCurrentPlatform(LocalContext.current.applicationContext, "my-app")
ApiKeyScreen(keychain)

// iosMain / appleMain-facing Swift or Kotlin entry point
val keychain = CredentialKeychain.forCurrentPlatform(serviceName = "my-app")
ApiKeyScreen(keychain)
```

### Apple (iOS, macOS, tvOS, watchOS)

Consumed from Swift, the same shared `CredentialKeychain` instance created in Kotlin
(or exposed through your KMP module's generated interop) works unchanged:

```swift
let keychain = try CredentialKeychainCompanion.shared.forCurrentPlatform(serviceName: "my-app", accountName: "user-123")
try keychain.write(key: "api-key", value: "secret-token")
let token = try keychain.read(key: "api-key")
```

Export this dependency from your consuming Kotlin framework before importing it in
Swift; this package publishes KLIBs, not a standalone Swift framework. Generated names
can vary with your framework configuration. Public operations declare `@Throws` for
availability and validation errors so Swift callers can handle them with `do`/`catch`.

Entries are stored with `WhenUnlockedThisDeviceOnly` accessibility and are not
iCloud-synchronized. Your app needs valid code signing and Keychain access for its
deployment environment (a Keychain Sharing entitlement is not required for an app to
access its own entries, but simulator/device signing must be in place) or writes and
reads will fail.

### Desktop JVM (macOS, Linux, Windows)

The same `forCurrentPlatform(serviceName, accountName)` call is used; which native
binary it shells out to depends on the OS the JVM is running on (see the
[platform table](#platform-support)). Nothing else in your code changes:

```kotlin
// jvmMain — works unmodified on macOS, Linux, or Windows
val keychain = CredentialKeychain.forCurrentPlatform("my-cli-tool")
keychain.write("github-token", token)
```

Make sure the required OS binary is present before shipping a desktop build — see the
per-OS requirements in [Contract and requirements](#contract-and-requirements).

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

See the [architecture and verification matrix](docs/architecture.md) for source-set
responsibilities, every non-Web target gap, runtime evidence, and release limitations.


```sh
./gradlew ktlintCheck jvmCoverageVerification
./gradlew checkKotlinAbi dokkaGeneratePublicationHtml
./gradlew connectedAndroidDeviceTest
```

The common/JVM coverage gate is 85% lines and 70% branches; reports are under
`build/reports/jacoco/`. These numbers do not measure native Apple, Android, or web
execution. The [release guide](docs/releasing.md) explains the scope and platform checks.

CI configures real-store tests on Windows, macOS, and Linux, Android emulator tests on
API 23 and 35, native ARM/Intel macOS Keychain tests, Kotlin lint, Apple/web compilation, JS/Wasm Node tests,
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
