# Module credential-keychain-kotlin

Secure credential storage for Kotlin Multiplatform applications. One
[`CredentialKeychain`](https://maniramezan.github.io/credential-keychain-kotlin/-credential%20-keychain%20-kotlin/dev.amoo.credentialkeychain/-credential-keychain/index.html)
interface — `read`, `write`, `delete` — backed by each platform's native secure storage:

- **Android** — Android Keystore, AES-256-GCM, ciphertext in an app-private,
  non-backed-up file.
- **iOS, macOS, tvOS, watchOS** — the native Apple Security framework (Keychain),
  `WhenUnlockedThisDeviceOnly`, not iCloud-synchronized.
- **macOS desktop JVM** — the system Keychain through `/usr/bin/security`.
- **Linux desktop JVM** — Secret Service (for example GNOME Keyring) through
  `secret-tool`.
- **Windows desktop JVM** — current-user DPAPI through Windows PowerShell.
- **Browser / Node.js (`js`, `wasmJs`)** — the API compiles for dependency
  compatibility only; every storage call throws
  [`KeychainUnavailableException`](https://maniramezan.github.io/credential-keychain-kotlin/-credential%20-keychain%20-kotlin/dev.amoo.credentialkeychain/-keychain-unavailable-exception/index.html).
  There is no localStorage, IndexedDB, or in-memory substitute — the library never
  invents a fallback that looks like durable storage but isn't.

No platform falls back to plaintext persistence: an unavailable or failing backend
always throws rather than silently writing to a less secure location.

## Quick start

```kotlin
import dev.amoo.credentialkeychain.CredentialKeychain

val credentials = CredentialKeychain.forCurrentPlatform("my-app", "user-123")
credentials.write("api-token", "secret")
val token = credentials.read("api-token") // null only if absent
credentials.delete("api-token")
```

On Android, import `dev.amoo.credentialkeychain.forCurrentPlatform` and use the overload
that takes `context = applicationContext` — the zero-`Context` overload on Android always
returns a store that throws `KeychainUnavailableException`, by design, so shared code
never silently gets an unusable store. Inject the resulting `CredentialKeychain` into
shared application code (a repository, a `ViewModel`, your DI graph) rather than calling
`forCurrentPlatform` at every call site.

Operations are synchronous and may block or prompt the user (Keychain access dialogs,
`secret-tool`/PowerShell subprocess round-trips): call from a worker thread or a
background coroutine dispatcher, never the UI thread.

## Semantics worth knowing before you integrate

- `null` from `read` means the entry is absent. It is never used to signal failure —
  operational failures and unavailable backends always throw `KeychainUnavailableException`.
- A blank `write` (`""` or all-whitespace) deletes the entry, matching the common pattern
  of clearing a form field by writing an empty string. Non-blank values preserve
  whitespace exactly.
- Deleting a key that has no entry succeeds as long as the backend is available — it is
  not treated as an error.
- Identifiers (`serviceName`, `accountName`, and the `key` passed to each operation) must
  be nonblank and must not contain NUL, CR, or LF. Values must not contain NUL; most
  backends accept multiline values, but macOS JVM's interactive `security` backend
  additionally rejects CR/LF in values.
- Entries are namespaced by **both** `serviceName` and `accountName` — different
  service/account pairs never collide, so one process can safely keep separate stores per
  app, environment, or signed-in user (see the multi-account example in the
  [README](https://github.com/maniramezan/credential-keychain-kotlin#example-storing-an-oauth-token-per-user-account)).

## Full usage and platform guide

This module page covers the API shape. For installation, per-OS runtime requirements
(signing, `secret-tool`, PowerShell), worked examples (Compose Multiplatform, Swift/Apple
interop, multi-account token storage), and build/verification instructions, see the
[usage and platform guide](https://github.com/maniramezan/credential-keychain-kotlin#readme).
See the [release guide](https://github.com/maniramezan/credential-keychain-kotlin/blob/main/docs/releasing.md)
for verification, coverage, and publishing.

# Package dev.amoo.credentialkeychain

The shared credential storage interface, platform factories, and availability exception.

- [`CredentialKeychain`](https://maniramezan.github.io/credential-keychain-kotlin/-credential%20-keychain%20-kotlin/dev.amoo.credentialkeychain/-credential-keychain/index.html) —
  the `read`/`write`/`delete` interface, plus the `forCurrentPlatform` factory on its
  companion object (and the Android `Context`-taking overload of the same name, declared
  in this package for Android targets).
- [`KeychainUnavailableException`](https://maniramezan.github.io/credential-keychain-kotlin/-credential%20-keychain%20-kotlin/dev.amoo.credentialkeychain/-keychain-unavailable-exception/index.html) —
  thrown for any unavailable-backend or operational-failure case; never thrown to mean
  "key not found" (that's a `null` return from `read`).

No platform falls back to plaintext persistence.
