# Module credential-keychain-kotlin-biometric

Secrets that require biometric authentication to read, published separately from
`credential-keychain-kotlin` so the core library stays free of `androidx.biometric` and
coroutines.

[com.maniramezan.credentialkeychain.biometric.ProtectedKeychain] stores secrets by key.
`write`, `delete`, and `clear` need no authentication; `read` suspends while the system prompt
is visible and returns the value once the user authenticates with a strong biometric.
Enrollment changes invalidate existing entries, reported as
`KeychainUnavailableException.Reason.AuthenticationInvalidated`.

- **Android (API 23+)** — a Keystore RSA key that requires Class 3 biometric authentication
  wraps a per-entry AES-256-GCM key. Create stores with the overload that takes a `Context` and
  a `FragmentActivity` provider.
- **iOS 15+ and macOS 12+** — data-protection keychain items with `biometryCurrentSet` access
  control, read through `LAContext`. Apps need keychain entitlements, and iOS apps using Face ID
  need `NSFaceIDUsageDescription`.
- **tvOS, watchOS, desktop JVM** — every operation throws `Reason.Unsupported`.

# Package com.maniramezan.credentialkeychain.biometric

`ProtectedKeychain`, its prompt text, and the platform factories.
