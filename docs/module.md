# Module credential-keychain-kotlin

Secure credential storage for Kotlin Multiplatform applications. Android uses Android
Keystore with AES-GCM; Apple targets use the Security framework; desktop JVM uses
macOS Keychain, Linux Secret Service, or Windows DPAPI.

JavaScript and WebAssembly builds deliberately throw `KeychainUnavailableException`
for every storage operation. They never substitute browser storage or in-memory storage.

## Quick start

```kotlin
val credentials = CredentialKeychain.forCurrentPlatform("my-app", "user-123")
credentials.write("api-token", "secret")
val token = credentials.read("api-token")
credentials.delete("api-token")
```

On Android, import `dev.amoo.credentialkeychain.forCurrentPlatform` and use the overload
with `context = applicationContext`. Inject the resulting `CredentialKeychain` into
shared code. Operations are synchronous: use a worker thread.

`null` means an entry is absent. Operational failures throw. A blank write deletes an
entry; other values preserve whitespace. Service and account isolate entries.

See the [usage and platform guide](https://github.com/maniramezan/credential-keychain-kotlin#readme)
for installation, size limits, signing requirements, and backend behavior. See the
[release guide](https://github.com/maniramezan/credential-keychain-kotlin/blob/main/docs/releasing.md)
for verification and publishing.

# Package dev.amoo.credentialkeychain

The shared credential storage interface, platform factories, and availability exception.
No platform falls back to plaintext persistence.
