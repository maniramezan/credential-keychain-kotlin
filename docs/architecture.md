# Architecture and platform verification

`CredentialKeychain` is a synchronous, dependency-free storage boundary. Applications
should create a platform instance in their composition root and inject the interface
into shared code. Android supplies the Context-taking factory; shared code should not
attempt to discover an Android context.

## Project layout

- `core/` is the published `com.maniramezan:credential-keychain-kotlin` library: sources,
  API baselines (`core/api/`), and its Dokka module page (`core/module.md`).
- `biometric/` is the published `com.maniramezan:credential-keychain-kotlin-biometric` artifact
  with `ProtectedKeychain`. It depends on `core` for `KeychainUnavailableException`, copies
  core's internal validators (a parity test keeps them identical), and adds a
  `localAuthenticationMain` source set shared by iOS and macOS, since tvOS has no
  LocalAuthentication framework.
- `build-logic/` holds the `credentialkeychain.library` convention plugin, which applies the
  targets, JVM 17 bytecode, explicit API mode, ABI validation, Dokka, publishing, ktlint, and
  the JaCoCo gate to every published module, plus `credentialkeychain.root` for the root
  project's script lint and aggregated documentation.
- `verification/` holds the separate consumer build and the iOS simulator app harness.

## Responsibilities

- `commonMain` owns the public contract, `KeychainOptions`, the failure `Reason`
  categories, identifier and value validation, collision-resistant namespace encoding,
  and the unavailable-store implementation.
- The internal `expect`/`actual` factory selects a backend. `ValidatingKeychain` wraps
  every public factory result, so validation (including blank-value rejection) is
  consistent across backends and backends never see invalid input.
- Android stores AES-GCM ciphertext in `noBackupFilesDir/<namespace alias>/`, binds it to
  the namespace and entry key with associated data, and keeps one encryption key per
  namespace in Android Keystore. Operations are serialized across instances within one
  process; multi-process use is unsupported. A missing key is reported as `Corrupted` and
  is never silently replaced while ciphertext remains. `clear()` deletes the ciphertext
  directory first and the key second, so a partial failure never strands ciphertext.
- Apple shares one Security-framework implementation across iOS, macOS, tvOS, and
  watchOS. Items are generic passwords whose service attribute is the length-prefixed
  service/account namespace and whose account attribute is the entry key, so `clear()` is
  a single service-scoped query. Items are never synchronized. On iOS, tvOS, and watchOS
  they use the configured `…ThisDeviceOnly` accessibility class, and updates re-apply it.
  On macOS the Security framework uses the file-based login keychain, which ignores
  accessibility classes and relies on per-item access lists; the data-protection keychain
  is not used because it requires signed apps with keychain entitlements.
- JVM selects an OS adapter. The subprocess boundary provides stdin transport,
  simultaneous stdout/stderr draining, a configurable timeout, and sanitized exceptions.
  A tool's non-zero exit code is preserved even if it exits before reading stdin; a zero
  exit without complete input is never trusted. Command runners are injectable for
  deterministic failure tests; real-store tests separately verify the OS tools.
  - macOS uses the same service/account layout as native Apple. `clear()` repeats
    service-scoped deletion until the tool reports no match. `security` exit codes are the
    low byte of the failing `OSStatus`, which maps lock/denial statuses to `Locked`.
  - Windows writes only DPAPI ciphertext under `%LOCALAPPDATA%`, atomically replaces files,
    and implements `clear()` by removing the namespace directory.
  - Linux delegates persistence to the running Secret Service.
- `PasswordStore` follows the same pattern: `ValidatingPasswordStore` applies the shared
  server, username, and password rules and sorts `findAll`, and each platform keeps passwords
  apart from `CredentialKeychain` entries in the same namespace.
  - Android reuses the Keystore file encryption with a separate key and directory:
    `<alias>/<sha256(server)>/<sha256(username)>.bin`. The plaintext is the length-prefixed
    username and password, and the associated data binds the namespace, server, and file name.
  - Apple (native) and macOS (JVM) use internet-password items whose security domain is the
    namespace, with server and account attributes. macOS JVM lists usernames for `findAll`
    from `security dump-keychain`, which prints attributes only, then reads each password.
  - Linux uses `secret-tool` items with a distinct `library` attribute plus `server` and
    `username`; `findAll` reads usernames from `search` and passwords from `lookup`.
  - Windows uses Credential Manager generic credentials through a compiled C# shim for
    `CredWriteW`/`CredReadW`/`CredEnumerateW`/`CredDeleteW`. Target names hash the namespace,
    server, and username; the password is a UTF-8 blob.
- `HardwareKeyStore` creates ECDSA P-256 keys; `ValidatingHardwareKeyStore` validates aliases.
  - Android uses Keystore aliases `com.maniramezan.credentialkeychain.key.<sha256(namespace)>.<sha256(alias)>`,
    requests StrongBox on API 28+ with a TEE fallback, reads the level from `KeyInfo`, and deletes
    software-only keys unless `allowSoftwareKeys` is set. It needs no `Context`.
  - Apple tags private keys with the namespace and labels them with the alias. Generation tries
    the Secure Enclave (data-protection keychain, `kSecAccessControlPrivateKeyUsage`) and only
    then, if allowed, a software key. Lookups search the data-protection keychain and then the
    file-based keychain, because unsigned macOS processes cannot use the former. Public keys are
    exported as uncompressed points and wrapped in a P-256 SubjectPublicKeyInfo.
  - Desktop JVM returns an unsupported store: there is no command-line path to the Secure
    Enclave or a TPM.
- `CertificateStore` shares its logic in `KeychainCertificateStore`: each entry's DER chain and a
  private-key flag live under `certificate:<alias>`, and the alias index under `index`, in the
  platform's `CredentialKeychain` for the service `credentialNamespace(serviceName, "certificates")`.
  A `CertificateBackend` parses input and stores private keys under a namespaced label; parsing
  happens before the old entry is replaced, and a metadata write rejected for size rolls back the
  identity and reports `Unsupported`.
  - macOS JVM uses the JDK `KeychainStore` provider (login keychain, label as alias).
  - Windows imports into the current-user `My` store through .NET `X509Certificate2` with
    `PersistKeySet,UserKeySet`, tagging the friendly name; removal also deletes the CNG/CAPI key
    container. SunMSCAPI was not used because `Windows-MY` only accepts RSA private keys.
  - Linux re-encodes the identity as PKCS#12 and stores it in Secret Service beside the metadata.
  - Android keeps metadata in `AndroidKeychain` files and imports private keys into Android
    Keystore under `com.maniramezan.credentialkeychain.certificate.<sha256(label)>` with
    `KeyProtection`: EC keys for signing, RSA keys for signing and decryption. The common factory
    returns an unsupported store; callers use the `Context`-taking overload.
  - Apple keeps metadata in `AppleKeychain` generic-password items and decodes PKCS#12 with
    `SecPKCS12Import` in memory, passing `kSecImportToMemoryOnly` (looked up with `dlsym`, since
    it exists only from iOS/tvOS 18, watchOS 11, and macOS 15). `SecItemAdd` stores the identity
    with the namespaced label in the data-protection keychain, and deleting the identity by label
    removes its certificate and private key. Unsigned macOS processes get `errSecMissingEntitlement`
    (`Unsupported`), macOS without the import flag is `Unsupported` because decoding would add the
    identity to the default keychain, and an identity already stored under another alias fails.
  - Platform handles resolve an alias through `identityTarget`, which unwraps the validating store,
    rejects stores not created by `forCurrentPlatform`, and returns the backend and label only for
    entries with a private key. `privateKeyEntry` (Android and JVM) reads Android Keystore, the JDK
    `KeychainStore` on macOS, the JDK `Windows-MY` provider on Windows (aliases are the friendly
    names set on import), or the Linux PKCS#12 bundle. `secIdentity` (Apple) returns a retained
    `SecIdentityRef` from the data-protection keychain.

Identifiers isolate entries; they are not an authorization boundary. DPAPI protects data
for the current Windows user, Secret Service access depends on that user's desktop session,
and macOS items created by `/usr/bin/security` trust that tool for every same-user process.
JVM tools are resolved from the process's trusted PATH (except macOS's fixed
`/usr/bin/security`); deployments must control PATH. See [SECURITY.md](../SECURITY.md).

Kotlin exceptions declared with `@Throws` cross the Objective-C/Swift boundary as
errors. Consumers export the library through their own Kotlin framework; this project
publishes KLIBs, not a ready-made Swift framework. `KeychainUnavailableException` keeps a
public constructor so consumer test fakes can simulate failures. CI compiles and runs a
Swift consumer against an exported macOS framework to verify availability and validation
errors.

## Target and execution matrix

| Target family | Production compilation / publication | Automated runtime evidence |
|---|---|---|
| Android JVM, API 23+ | Android AAR and independent Android consumer | Real Keystore emulator tests, API 23 and 35 |
| Desktop JVM (Java 17 bytecode) | JVM JAR and independent consumer | Real stores on Linux, Windows, and ARM macOS; deterministic adapter and process tests |
| `macosArm64` | KLIB and consumer | Native Keychain tests on ARM macOS |
| `iosArm64`, `iosSimulatorArm64` | KLIBs and consumers | iOS simulator app harness against the data-protection keychain; device signing, Secure Enclave, and lock states are not covered by CI |
| `tvosArm64`, `tvosSimulatorArm64` | KLIBs and consumers | Shared implementation tested on macOS; tvOS runtime/signing is not covered by CI |
| `watchosArm64`, `watchosDeviceArm64`, `watchosSimulatorArm64` | KLIBs and consumers | Shared implementation tested on macOS; watchOS runtime/signing is not covered by CI |
| `js`, `wasmJs` | **Not published** | None; browsers have no OS keychain backend |
| Intel Apple (`iosX64`, `macosX64`, `tvosX64`, `watchosX64`) | **Not published** (deprecated by Kotlin) | None; Intel Macs are supported through the JVM target |
| `linuxX64`, `linuxArm64`, `mingwX64` | **Not implemented or published** | None; Linux/Windows support is through JVM only |
| Android/Native | **Not implemented or published** | None; Android support is through the Android JVM target |

Adding native Linux/Windows is a separate backend project: it needs native OS bindings,
native runtime tests on matching hosts, consumer/publication checks, and API baselines.
Declaring targets backed by an unavailable stub would not constitute secure-storage support.

## Quality gates and remaining validation

`ktlintCheck` validates production code, tests, and Gradle scripts; `ktlintFormat`
applies the matching formatting rules. `check` includes lint and JVM coverage, but a
single local `check` cannot validate all platforms. CI explicitly schedules OS and Android
execution plus ABI, Dokka, artifacts (including Java 17 class file versions), consumer
builds, Swift interop, workflow lint, shell syntax, and artifact-validator unit tests.
Workflow actions are pinned to commit SHAs and updated by Dependabot.

JaCoCo measures common code compiled for JVM and JVM adapters only. The gate requires
85% lines and 70% branches without excluding production classes. Android and Apple
have behavioral tests, not measured coverage percentages. Do not present the JVM
percentage as total KMP coverage. Test and coverage reports are uploaded even on failure.

Require the **Required checks** status in repository branch protection. It fails when
any verification job fails, is cancelled, or is skipped.

Before each release, run signed app/device validation on iOS, tvOS, and watchOS for both
accessibility options while locked/unlocked, app relaunch, reinstall, and signing/access-group
changes. Kotlin/Native simulator test executables are not app-hosted and have no keychain
access (`errSecNotAvailable`, reported as `Unsupported`), so `iosSimulatorArm64Test` is not used.
Instead, `scripts/apple-simulator-tests.sh` builds `verification/apple-harness/Harness.swift`
against the exported iOS simulator framework into an ad-hoc signed app with keychain
entitlements embedded in `__TEXT,__entitlements` (as Xcode does for simulators), runs it with
`simctl spawn` on a disposable simulator, and requires `HARNESS-PASS`. That exercises the
data-protection keychain through the public API, but not device-only behavior: Secure Enclave,
lock states, reinstall, and real provisioning. Android hardware-backed Keystore behavior also needs
representative physical-device testing, and separate Android/native coverage reporting remains an
improvement, not an existing gate.
