# credential-keychain-kotlin

Kotlin Multiplatform storage for API keys, tokens, and passwords, backed by platform
secure storage. There is no plaintext persistence fallback: every supported platform
routes through its native secure-storage facility (Android Keystore, Apple Keychain,
macOS Keychain, Linux Secret Service, or Windows DPAPI), or the call throws.

This exists for apps and libraries that need one interface for things like storing an
OAuth refresh token, a scoped API key, or a user's saved username and password across
Android, iOS, macOS, tvOS, watchOS, and desktop JVM — without writing a platform-specific
secure-storage adapter for each target. `CredentialKeychain` stores secrets by key, and
`PasswordStore` stores username/password credentials per server.

## Why this exists / what it does

- **One API, native storage everywhere.** `read`/`write`/`delete`/`clear` behave the same
  from `commonMain`; each platform target resolves to its own OS-backed secure store.
- **No silent fallback.** If a platform can't provide secure storage (a missing Linux
  Secret Service session, an Android call without a `Context`), the
  library throws `KeychainUnavailableException` instead of writing plaintext or an
  in-memory stand-in you might mistake for durable storage.
- **Actionable failures.** Every failure carries a `reason` — `Unsupported`, `Locked`,
  `Canceled`, `AuthenticationInvalidated`, `Corrupted`, or `Failed` — so you can retry
  later, re-prompt, or reset the store.
- **Namespaced by service + account.** Multiple apps, environments, or user accounts
  sharing a device don't collide, because both `serviceName` and `accountName` are
  bound into the storage key rather than just a bare key string.
- **Small, dependency-free surface.** Two store interfaces, one options class, and one
  exception type — see [Contract and requirements](#contract-and-requirements) for exact semantics.

## Platform support

| Platform | Kotlin targets | Backend |
|---|---|---|
| Android 6.0+ (API 23+) | `android` | Android Keystore AES-256-GCM; ciphertext in app-private, non-backed-up files |
| iOS | `iosArm64`, `iosSimulatorArm64` | Apple Keychain, device-only, configurable accessibility |
| tvOS | `tvosArm64`, `tvosSimulatorArm64` | Apple Keychain, device-only, configurable accessibility |
| watchOS | `watchosArm64`, `watchosDeviceArm64`, `watchosSimulatorArm64` | Apple Keychain, device-only, configurable accessibility |
| macOS | `macosArm64` | File-based login keychain through the Security framework |
| macOS desktop JVM | `jvm` | Login keychain through `/usr/bin/security` |
| Linux desktop JVM | `jvm` | Secret Service through `secret-tool` |
| Windows desktop JVM | `jvm` | Current-user DPAPI (secrets) and Credential Manager (passwords) through Windows PowerShell |

JVM artifacts target Java 17. Intel Apple targets (`iosX64`, `macosX64`, `tvosX64`,
`watchosX64`) are not published; Intel Macs are supported through the JVM target. Windows
and Linux support requires a JVM — there are no `mingwX64`, `linuxX64`, or `linuxArm64`
native backends, and no web (`js`, `wasmJs`) targets.

## Installation

```kotlin
// build.gradle.kts
kotlin {
    sourceSets.commonMain.dependencies {
        implementation("com.maniramezan:credential-keychain-kotlin:0.1.0") // x-release-please-version
    }
}
```

No extra platform dependency, manifest entry, or entitlement is required to link the
library. Desktop JVM targets shell out to an OS tool (`security`, `secret-tool`,
`powershell.exe`) that must be present on the machine — see
[Contract and requirements](#contract-and-requirements).

## Usage from shared code

In `commonMain`, obtain an instance through `CredentialKeychain.forCurrentPlatform(...)`,
which resolves to the right backend for the target being compiled.

```kotlin
import com.maniramezan.credentialkeychain.CredentialKeychain

// Apple native or desktop JVM:
val keychain = CredentialKeychain.forCurrentPlatform(
    serviceName = "my-app",
    accountName = "user-123", // defaults to serviceName
)

keychain.write("api-key", "secret-token")
val token: String? = keychain.read("api-key") // null only if absent
keychain.delete("api-key")
keychain.clear() // removes every entry for my-app/user-123
```

Call from a worker thread or coroutine dispatcher — every operation is synchronous and a
native backend may block or prompt the user. Use the failure `reason` to decide what to do:

```kotlin
suspend fun readApiKey(keychain: CredentialKeychain): String? = withContext(Dispatchers.IO) {
    try {
        keychain.read("api-key")
    } catch (e: KeychainUnavailableException) {
        when (e.reason) {
            KeychainUnavailableException.Reason.Locked -> null // retry after the device unlocks
            KeychainUnavailableException.Reason.Corrupted -> { keychain.clear(); null } // re-authenticate
            else -> throw e
        }
    }
}
```

Inject a single `CredentialKeychain` into shared application code (a repository, a
`ViewModel`, DI graph) rather than calling `forCurrentPlatform` at every call site — this
is also what lets Android supply its `Context`-based implementation without `commonMain`
needing to know about `Context` at all:

```kotlin
// In androidMain:
import com.maniramezan.credentialkeychain.CredentialKeychain
import com.maniramezan.credentialkeychain.forCurrentPlatform

val keychain: CredentialKeychain = CredentialKeychain.forCurrentPlatform(
    context = applicationContext,
    serviceName = "my-app",
    accountName = "user-123",
)
```

The `Context`-free factory on Android returns an unavailable store — every call throws
`KeychainUnavailableException` with reason `Unsupported` — rather than silently working
without one. This avoids retaining an Activity or requiring global initialization just so
`commonMain` can call a zero-argument factory.

### Options

```kotlin
val keychain = CredentialKeychain.forCurrentPlatform(
    serviceName = "my-app",
    accountName = "user-123",
    options = KeychainOptions(
        appleAccessibility = AppleAccessibility.AfterFirstUnlock, // iOS/tvOS/watchOS background access
        desktopCommandTimeout = 60.seconds, // desktop JVM tool timeout, including access prompts
    ),
)
```

Options that don't apply to the current platform are ignored.

### Usernames and passwords

`PasswordStore` keeps username/password credentials per server, using each platform's native
password storage. It is created the same way (Android uses the `Context`-taking overload) and
is independent of a `CredentialKeychain` with the same service and account names:

```kotlin
val passwords = PasswordStore.forCurrentPlatform(serviceName = "my-app", accountName = "user-123")

passwords.save(PasswordCredential(server = "api.example.com", username = "alice", password = "s3cret"))
val alice: PasswordCredential? = passwords.find(server = "api.example.com", username = "alice")
val accounts: List<String> = passwords.findAll(server = "api.example.com").map { it.username } // sorted
passwords.delete(server = "api.example.com", username = "alice")
passwords.clear() // removes every password for my-app/user-123, on every server
```

`PasswordCredential.toString()` never includes the password.

### Hardware-backed signing keys

`HardwareKeyStore` generates non-exportable ECDSA P-256 keys inside secure hardware — StrongBox
or the trusted execution environment on Android, the Secure Enclave on Apple platforms — and
signs with them. Private keys never leave the hardware:

```kotlin
val keys = HardwareKeyStore.forCurrentPlatform(serviceName = "my-app", accountName = "user-123")

val key: HardwareKeyInfo = keys.generate("device-binding") // replaces an existing key
server.register(key.publicKeyDer, key.securityLevel) // X.509 SubjectPublicKeyInfo
val signature: ByteArray? = keys.sign("device-binding", challenge) // DER ECDSA-SHA256; null if missing
keys.delete("device-binding")
```

Generation fails with reason `Unsupported` when no secure hardware is available (emulators,
simulators, unsigned macOS tools, desktop JVM). Pass `HardwareKeySpec(allowSoftwareKeys = true)`
to accept software-backed keys where the platform offers them; `securityLevel` always reports
what you actually got. Android needs no `Context` for this store.

### Certificates and identities

`CertificateStore` keeps X.509 certificates and PKCS#12 identities. Private keys go to native key
storage; certificate chains are returned as DER, leaf first:

```kotlin
val certificates = CertificateStore.forCurrentPlatform(serviceName = "my-app", accountName = "user-123")

val client: CertificateInfo = certificates.importPkcs12("client", pkcs12Bytes, passphrase) // replaces "client"
certificates.importCertificate("pinned-ca", caCertificateDer)
val chain: List<ByteArray>? = certificates.info("client")?.certificateChainDer
val aliases: List<String> = certificates.aliases() // sorted
certificates.delete("pinned-ca")
```

A malformed bundle or wrong passphrase throws `IllegalArgumentException`; the passphrase array is
not cleared for you. Desktop JVM stores identities in the macOS login keychain, the Windows
current-user certificate store, or Linux Secret Service. Android and Apple native backends are
not available yet and throw `KeychainUnavailableException` with reason `Unsupported`.

### Example: storing an OAuth token per user account

Namespacing by `accountName` keeps one secure entry set per signed-in user without
encoding the user id into each key yourself:

```kotlin
fun keychainFor(userId: String): CredentialKeychain =
    CredentialKeychain.forCurrentPlatform(serviceName = "com.example.myapp", accountName = userId)

fun saveTokens(userId: String, accessToken: String, refreshToken: String) {
    val keychain = keychainFor(userId)
    keychain.write("access-token", accessToken)
    keychain.write("refresh-token", refreshToken)
}

fun signOut(userId: String) {
    keychainFor(userId).clear()
}
```

### Example: Compose Multiplatform (shared UI, platform-supplied instance)

```kotlin
// commonMain
@Composable
fun ApiKeyScreen(keychain: CredentialKeychain) {
    var apiKey by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(keychain) {
        apiKey = withContext(Dispatchers.Default) { keychain.read("api-key") }
    }
    // render apiKey / a form that calls keychain.write("api-key", input) on submit
}

// androidMain composition root
val context = LocalContext.current.applicationContext
val keychain = remember(context) { CredentialKeychain.forCurrentPlatform(context, "my-app") }
ApiKeyScreen(keychain)

// iosMain composition root
val keychain = remember { CredentialKeychain.forCurrentPlatform(serviceName = "my-app") }
ApiKeyScreen(keychain)
```

### Apple (iOS, macOS, tvOS, watchOS)

Consumed from Swift, a `CredentialKeychain` created through your KMP framework works
unchanged:

```swift
let keychain = try CredentialKeychainCompanion.shared.forCurrentPlatform(serviceName: "my-app", accountName: "user-123")
try keychain.write(key: "api-key", value: "secret-token")
let token = try keychain.read(key: "api-key")
try keychain.clear()

let passwords = try PasswordStoreCompanion.shared.forCurrentPlatform(serviceName: "my-app", accountName: "user-123")
try passwords.save(credential: PasswordCredential(server: "api.example.com", username: "alice", password: "s3cret"))
let alice = try passwords.find(server: "api.example.com", username: "alice")
```

Export this dependency from your consuming Kotlin framework before importing it in
Swift; this package publishes KLIBs, not a standalone Swift framework. Generated names
can vary with your framework configuration. Every operation declares `@Throws`, so Swift
callers handle failures with `do`/`catch`.

On iOS, tvOS, and watchOS, entries are device-only, never iCloud-synchronized, and readable
according to `appleAccessibility`. The default, `WhenUnlocked`, makes reads fail with
reason `Locked` while the device is locked; use `AfterFirstUnlock` for background refresh.
Changing the option on a later write updates the existing entry.

On macOS, Kotlin/Native entries live in the file-based login keychain, which does not
support accessibility classes: `appleAccessibility` is ignored, and access is controlled by
the keychain's per-item access list, which trusts the application that created the item.
This works for unsigned tools; macOS may prompt when a differently signed build reads an
existing item.

### Desktop JVM (macOS, Linux, Windows)

The same `forCurrentPlatform(serviceName, accountName)` call is used; the OS the JVM runs
on selects the backend (see the [platform table](#platform-support)):

```kotlin
// jvmMain — works unmodified on macOS, Linux, or Windows
val keychain = CredentialKeychain.forCurrentPlatform("my-cli-tool")
keychain.write("github-token", token)
```

## Contract and requirements

- Operations are synchronous and may block or prompt for access. Use a worker thread.
- Reads return `null` for absent entries. Unavailable backends and operational failures
  throw `KeychainUnavailableException`; do not interpret them as missing credentials.
  - `Unsupported` — no usable backend in this platform or environment.
  - `Locked` — the store is locked or access was denied; retrying later may succeed.
  - `Canceled` — the user dismissed an access prompt; retry only on user action.
  - `AuthenticationInvalidated` — the protecting key was permanently invalidated (for
    example, biometric enrollment changed); delete the entry or `clear()`.
  - `Corrupted` — data exists but can't be decrypted or decoded; delete the entry or `clear()`.
  - `Failed` — any other failure, such as an I/O error or timeout.
- `write` stores values exactly, including surrounding whitespace. Blank values throw
  `IllegalArgumentException`; call `delete` to remove an entry.
- Deleting an absent entry or clearing an empty store succeeds when the backend is available.
- Identifiers must be nonblank and cannot contain NUL, CR, or LF; values cannot contain NUL.
- macOS JVM's interactive `security` backend additionally rejects CR/LF in values.
  Native Apple and Android backends accept multiline secrets.
- `PasswordStore` applies the same rules on every platform so credentials stay portable:
  servers and usernames are nonblank without NUL, CR, or LF; usernames are at most 512
  characters; passwords are nonblank, without NUL, CR, or LF, and at most 2,560 UTF-8 bytes
  (the Windows Credential Manager limit). `save` replaces an existing password, and
  `findAll` returns credentials sorted by username.
- Passwords are stored as Keystore-encrypted files on Android, internet-password items
  (security domain = service/account namespace) on Apple and macOS JVM, Secret Service items
  on Linux, and Credential Manager generic credentials on Windows. On macOS JVM, `findAll`
  lists usernames from `security dump-keychain`, which reads attributes but not passwords.
- `HardwareKeyStore` keys are ECDSA P-256; signatures are DER-encoded ECDSA with SHA-256 and
  verify with `SHA256withECDSA`. Android prefers StrongBox (API 28+) and falls back to the TEE;
  before API 31 it reports hardware keys as `TrustedEnvironment` even when StrongBox-backed.
  Apple Secure Enclave keys require a signed app (the data-protection keychain); unsigned macOS
  processes can only use opt-in software keys in the login keychain. Desktop JVM always throws
  `Unsupported`.
- `CertificateStore` accepts PKCS#12 bundles with exactly one private key and DER certificates,
  each at most 1 MiB. Chains and the alias index are kept in the platform's secret storage under
  a separate "certificates" namespace; `aliases()` is not transactional across processes. On
  desktop JVM, identities go to the macOS login keychain (JDK `KeychainStore`), the Windows
  current-user `My` store with a non-exportable key (removed with its key container), or Linux
  Secret Service as a re-encoded PKCS#12 bundle, where bundles over 8 KiB fail with `Unsupported`.
- Android keys stay in Android Keystore; hardware backing depends on the device. Files
  contain authenticated ciphertext with the namespace and key bound as associated data.
  Ciphertext is excluded from backup because Keystore keys cannot be restored with it.
  Access is serialized within the process; sharing a store across Android processes is
  not supported. If the namespace key is lost, reads and writes fail with `Corrupted`
  (existing ciphertext is never silently replaced) until you `delete` the affected entries
  or `clear()` the store.
- Linux requires `secret-tool` and an accessible Secret Service session (for example,
  GNOME Keyring). Headless sessions may not have one. Credentials should stay below
  8 KiB, the input limit of commonly deployed `secret-tool` versions.
- Windows requires Windows PowerShell (`powershell.exe`) and a loaded user profile.
  Ciphertext lives under `%LOCALAPPDATA%\credential-keychain\` in hashed service/account and
  key paths. DPAPI binds decryption to the Windows user, not to a particular application.
- Desktop subprocesses time out after `desktopCommandTimeout` (30 seconds by default).
  Secrets are supplied through stdin, and backend error output is never included in exceptions.

## Security model

The library relies on each platform's secure storage and does not add protection beyond
it. In particular, on desktop JVM any process running as the same OS user can read the
stored credentials: macOS items created through `/usr/bin/security` trust that tool, so
`security find-generic-password` can read them without a prompt; unlocked Secret Service
collections are available to the whole session; and DPAPI and Credential Manager decrypt
for any process of the same Windows user. Service and account names prevent collisions — they are not an
authorization boundary. See [SECURITY.md](SECURITY.md) for the full model and for
reporting vulnerabilities.

## Documentation

- [API reference](https://maniramezan.github.io/credential-keychain-kotlin/) for the latest release.
- [Architecture and verification matrix](docs/architecture.md) — source-set responsibilities,
  storage layout, and runtime evidence per target.
- [Release guide](docs/releasing.md) — verification, API baselines, and Maven Central staging.
- Release notes are published on [GitHub Releases](https://github.com/maniramezan/credential-keychain-kotlin/releases).

## Build and consume locally

Building requires JDK 21, Android SDK 36, and the Gradle wrapper; the published JVM
artifacts run on Java 17+. A macOS host with a compatible Xcode is required to build the
Apple artifacts.

```sh
./gradlew jvmTest
./gradlew assemble macosArm64Test
./gradlew publishToMavenLocal
```

After local publication, a consuming KMP project can add `mavenLocal()` to its repositories
and depend on the same coordinates shown in [Installation](#installation). The build creates
the KMP metadata publication and 10 platform publications; publish the complete set when
distributing the library.

## Verification

```sh
./gradlew ktlintCheck jvmCoverageVerification
./gradlew checkKotlinAbi dokkaGeneratePublicationHtml
./gradlew connectedAndroidDeviceTest
```

The common/JVM coverage gate is 85% lines and 70% branches; reports are under
`build/reports/jacoco/`. These numbers do not measure native Apple or Android execution.

CI runs real-store tests on Windows, macOS, and Linux, Android emulator tests on API 23
and 35, native macOS Keychain tests, Kotlin lint, Apple compilation, API compatibility, documentation, publication-consumer, and Swift interop checks.

Run desktop integration tests against a disposable namespace using:

```sh
CREDENTIAL_KEYCHAIN_INTEGRATION=1 ./gradlew jvmTest --rerun-tasks
```

Signed iOS, tvOS, and watchOS behavior (lock states, reinstall, access groups) requires
device validation; compilation and macOS tests alone do not verify it.
