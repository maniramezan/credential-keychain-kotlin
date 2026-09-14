# Architecture and platform verification

`CredentialKeychain` is a synchronous, dependency-light storage boundary. Applications
should create a platform instance in their composition root and inject the interface
into shared code. Android supplies the Context-taking factory; shared code should not
attempt to discover an Android context.

## Responsibilities

- `commonMain` owns the public contract, identifier validation, blank-write deletion,
  collision-resistant namespace encoding, and the unavailable-store implementation.
- The internal `expect`/`actual` factory selects a backend. `ValidatingKeychain` wraps
  every public factory result, so validation is consistent across backends.
- Android stores AES-GCM ciphertext in `noBackupFilesDir`, binds it to the namespace
  and entry key with associated data, and keeps encryption keys in Android Keystore.
  Operations are serialized across instances within one process. Multi-process use
  is unsupported; a missing encryption key requires explicit ciphertext deletion.
- Apple shares one Security-framework implementation across iOS, macOS, tvOS, and
  watchOS. Entries are device-only, unlocked-only, and not synchronized to iCloud.
  Updates preserve existing items; an insert race retries the update.
- JVM selects an OS adapter. The subprocess boundary provides stdin transport,
  simultaneous stdout/stderr draining, a timeout, and sanitized exceptions. Command
  runners are injectable for deterministic failure tests. Real-store tests separately
  verify the actual OS tools. Windows writes only DPAPI ciphertext and atomically
  replaces files; Linux delegates persistence to the running Secret Service.

Identifiers isolate entries; they are not an authorization boundary. In particular,
DPAPI protects data for the current Windows user, and Secret Service access depends on
that user's desktop session. Do not assume mutually untrusted apps are isolated merely
because they use different service names. JVM tools are resolved from the process's
trusted PATH (except macOS's fixed `/usr/bin/security`); deployments must control PATH.

Kotlin exceptions declared with `@Throws` cross the Objective-C/Swift boundary as
errors. Consumers export the library through their own Kotlin framework; this project
publishes KLIBs, not a ready-made Swift framework. Framework/module naming is owned by
the consumer. The supported failure types are availability errors and invalid input. CI compiles and
runs a Swift consumer against an exported macOS framework to verify both error types.

## Target and execution matrix

| Target family | Production compilation / publication | Automated runtime evidence |
|---|---|---|
| Android JVM, API 23+ | Android AAR and independent Android consumer | Real Keystore emulator tests, API 23 and 35 |
| Desktop JVM | JVM JAR and independent consumer | Real stores on Linux, Windows, and Intel/ARM macOS; deterministic adapter and process tests |
| `macosArm64`, `macosX64` | Both KLIBs and consumers | Native Keychain tests on matching ARM/Intel runners |
| `iosArm64`, `iosSimulatorArm64`, `iosX64` | All KLIBs and consumers | Shared implementation tested on macOS; iOS runtime/signing is not covered by CI |
| `tvosArm64`, `tvosSimulatorArm64`, `tvosX64` | All KLIBs and consumers | Shared implementation tested on macOS; tvOS runtime/signing is not covered by CI |
| `watchosArm64`, `watchosDeviceArm64`, `watchosSimulatorArm64`, `watchosX64` | All KLIBs and consumers | Shared implementation tested on macOS; watchOS runtime/signing is not covered by CI |
| `linuxX64`, `linuxArm64`, `mingwX64` | **Not implemented or published** | None; Linux/Windows support is through JVM only |
| Android/Native (`androidNativeArm32`, `androidNativeArm64`, `androidNativeX86`, `androidNativeX64`) | **Not implemented or published** | None; Android support is through the Android JVM target |
| Web | Existing compatibility stubs retained | Outside this architecture review's scope |

This is not support for every non-Web Kotlin target. Adding native Linux/Windows is a
separate backend project: it needs native OS bindings, native runtime tests on matching
hosts, consumer/publication checks, and API baselines. Declaring targets backed by an
unavailable stub would not constitute secure-storage support. Kotlin's deprecated Intel
Apple targets remain published for existing consumers until an intentional API change.

## Quality gates and remaining validation

`ktlintCheck` validates production code, tests, and Gradle scripts; `ktlintFormat`
applies the matching formatting rules. Generated/build directories are excluded.
`check` includes lint and JVM coverage, but a single local `check` cannot validate all
platforms. CI explicitly schedules OS and Android execution plus ABI, Dokka, artifacts,
consumer builds, workflow lint, shell syntax, and artifact-validator unit tests.

JaCoCo measures common code compiled for JVM and JVM adapters only. The gate requires
85% lines and 70% branches without excluding production classes. Android and Apple
have behavioral tests, not measured coverage percentages. Do not present the JVM
percentage as total KMP coverage. Test and coverage reports are uploaded even on failure.

Require the **Required checks** status in repository branch protection. It fails when
any verification job fails, is cancelled, or is skipped. Workflow files cannot configure
repository protection, environment approvals, or publishing secrets by themselves.

Before release, run signed app/device validation on iOS, tvOS, and watchOS for access
while locked/unlocked, app relaunch, reinstall, and signing/access-group changes. The
shared macOS tests do not establish those behaviors. Android hardware-backed Keystore
behavior also needs representative physical-device testing. A simulator/device harness
and separate Android/native coverage reporting remain improvements, not existing gates.
