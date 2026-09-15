# Module credential-keychain-kotlin

Secure credential storage for Kotlin Multiplatform applications.
[com.maniramezan.credentialkeychain.CredentialKeychain] stores secrets by key (`read`, `write`,
`delete`, `clear`), and [com.maniramezan.credentialkeychain.PasswordStore] stores
username/password credentials per server (`save`, `find`, `findAll`, `delete`, `clear`). Both
are backed by each platform's native secure storage:

- **Android** — Android Keystore, AES-256-GCM, ciphertext in an app-private,
  non-backed-up file.
- **iOS, tvOS, watchOS** — the native Apple Keychain, device-only and never
  iCloud-synchronized, readable according to [com.maniramezan.credentialkeychain.AppleAccessibility].
- **macOS (Kotlin/Native)** — the file-based login keychain through the Security
  framework. macOS ignores the accessibility setting for this keychain.
- **macOS desktop JVM** — the login keychain through `/usr/bin/security`.
- **Linux desktop JVM** — Secret Service (for example GNOME Keyring) through
  `secret-tool`.
- **Windows desktop JVM** — current-user DPAPI for secrets and Credential Manager for
  passwords, through Windows PowerShell.

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

val passwords = PasswordStore.forCurrentPlatform("my-app", "user-123")
passwords.save(PasswordCredential(server = "api.example.com", username = "alice", password = "s3cret"))
val alice = passwords.find(server = "api.example.com", username = "alice")
val accounts = passwords.findAll(server = "api.example.com").map { it.username }
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
  `KeychainUnavailableException`, whose `reason` is `Unsupported`, `Locked`, `Canceled`,
  `AuthenticationInvalidated`, `Corrupted`, or `Failed`.
- `write` stores values exactly, including surrounding whitespace. Blank values are
  rejected with `IllegalArgumentException`; call `delete` to remove an entry.
- Deleting a missing key, or clearing an empty store, succeeds when the backend is available.
- Identifiers (`serviceName`, `accountName`, and each `key`) must be nonblank and must not
  contain NUL, CR, or LF. Values must not contain NUL; macOS JVM additionally rejects CR/LF.
- Entries are namespaced by **both** `serviceName` and `accountName`, so one process can keep
  separate stores per app, environment, or signed-in user. A `CredentialKeychain` and a
  `PasswordStore` with the same names never see or clear each other's entries.
- Password credentials follow the same rules everywhere: servers and usernames are nonblank
  without NUL, CR, or LF; usernames are at most 512 characters; passwords are nonblank, without
  NUL, CR, or LF, and at most 2,560 UTF-8 bytes. `PasswordCredential.toString()` redacts the password.

## Full usage and platform guide

See the [usage and platform guide](https://github.com/maniramezan/credential-keychain-kotlin#readme)
for installation, per-OS runtime requirements, worked examples, and the security model.

# Package com.maniramezan.credentialkeychain

The shared credential storage interface, platform factories, options, and failure type.

- [com.maniramezan.credentialkeychain.CredentialKeychain] — the storage interface plus the
  `forCurrentPlatform` factories on its companion object (Android adds a `Context`-taking
  overload of the same name in this package).
- [com.maniramezan.credentialkeychain.PasswordStore] and
  [com.maniramezan.credentialkeychain.PasswordCredential] — username/password storage per server,
  with the same factories (and the same Android `Context`-taking overload).
- [com.maniramezan.credentialkeychain.HardwareKeyStore],
  [com.maniramezan.credentialkeychain.HardwareKeySpec],
  [com.maniramezan.credentialkeychain.HardwareKeyInfo], and
  [com.maniramezan.credentialkeychain.SecurityLevel] — non-exportable ECDSA P-256 signing keys in
  StrongBox, the Android TEE, or the Apple Secure Enclave (no `Context` needed on Android).
- [com.maniramezan.credentialkeychain.CertificateStore] and
  [com.maniramezan.credentialkeychain.CertificateInfo] — X.509 certificates and PKCS#12 identities
  with natively stored private keys on desktop JVM, Android (`Context`-taking overload), and Apple
  platforms (data-protection keychain; apps need keychain entitlements). Stored identities are usable
  through `CertificateStore.privateKeyEntry` on Android and desktop JVM and
  `CertificateStore.secIdentity` on Apple platforms.
- [com.maniramezan.credentialkeychain.KeychainOptions] — Apple accessibility and desktop command timeout.
- [com.maniramezan.credentialkeychain.KeychainUnavailableException] — thrown for every
  unavailable-backend or operational failure, never for "key not found".
