# Module credential-keychain-kotlin

Secure credential storage for Kotlin Multiplatform applications. One
[com.maniramezan.credentialkeychain.CredentialKeychain] interface — `read`, `write`, `delete`,
`clear` — backed by each platform's native secure storage:

- **Android** — Android Keystore, AES-256-GCM, ciphertext in an app-private,
  non-backed-up file.
- **iOS, tvOS, watchOS** — the native Apple Keychain, device-only and never
  iCloud-synchronized, readable according to [com.maniramezan.credentialkeychain.AppleAccessibility].
- **macOS (Kotlin/Native)** — the file-based login keychain through the Security
  framework. macOS ignores the accessibility setting for this keychain.
- **macOS desktop JVM** — the login keychain through `/usr/bin/security`.
- **Linux desktop JVM** — Secret Service (for example GNOME Keyring) through
  `secret-tool`.
- **Windows desktop JVM** — current-user DPAPI through Windows PowerShell.

No platform falls back to plaintext persistence: an unavailable or failing backend
always throws rather than silently writing to a less secure location.

## Quick start

```kotlin
import com.maniramezan.credentialkeychain.CredentialKeychain

val credentials = CredentialKeychain.forCurrentPlatform("my-app", "user-123")
credentials.write("api-token", "secret")
val token = credentials.read("api-token") // null only if absent
credentials.delete("api-token")
credentials.clear() // removes every entry for my-app/user-123
```

On Android, import `com.maniramezan.credentialkeychain.forCurrentPlatform` and use the overload
that takes `context = applicationContext` — the `Context`-free overload on Android always
returns a store that throws `KeychainUnavailableException`, by design. Inject the resulting
`CredentialKeychain` into shared code (a repository, a `ViewModel`, your DI graph) rather
than calling `forCurrentPlatform` at every call site.

Operations are synchronous and may block or prompt the user: call them from a worker
thread or a background coroutine dispatcher, never the UI thread.

## Semantics worth knowing before you integrate

- `null` from `read` means the entry is absent. Failures always throw
  `KeychainUnavailableException`, whose `reason` is `Unsupported`, `Locked`, `Corrupted`,
  or `Failed`.
- `write` stores values exactly, including surrounding whitespace. Blank values are
  rejected with `IllegalArgumentException`; call `delete` to remove an entry.
- Deleting a missing key, or clearing an empty store, succeeds when the backend is available.
- Identifiers (`serviceName`, `accountName`, and each `key`) must be nonblank and must not
  contain NUL, CR, or LF. Values must not contain NUL; macOS JVM additionally rejects CR/LF.
- Entries are namespaced by **both** `serviceName` and `accountName`, so one process can keep
  separate stores per app, environment, or signed-in user.

## Full usage and platform guide

See the [usage and platform guide](https://github.com/maniramezan/credential-keychain-kotlin#readme)
for installation, per-OS runtime requirements, worked examples, and the security model.

# Package com.maniramezan.credentialkeychain

The shared credential storage interface, platform factories, options, and failure type.

- [com.maniramezan.credentialkeychain.CredentialKeychain] — the storage interface plus the
  `forCurrentPlatform` factories on its companion object (Android adds a `Context`-taking
  overload of the same name in this package).
- [com.maniramezan.credentialkeychain.KeychainOptions] — Apple accessibility and desktop command timeout.
- [com.maniramezan.credentialkeychain.KeychainUnavailableException] — thrown for every
  unavailable-backend or operational failure, never for "key not found".
