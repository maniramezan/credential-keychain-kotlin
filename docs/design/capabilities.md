# Design proposal: passwords, certificates, hardware keys, and biometrics

Status: **draft for review** — nothing here is implemented. Decisions marked **Decide** need
sign-off before implementation starts, because they shape public API that is expensive to
change after 0.1.0.

## Goals

- Add four capabilities beside the existing `CredentialKeychain` secret store:
  1. Username/password credentials.
  2. Certificates and identities (certificate + private key).
  3. Hardware-backed, non-exportable keys.
  4. Secrets that require biometric or device-credential authentication to read.
- Keep the existing guarantees: no plaintext fallback, no secrets in exceptions, one
  `KeychainUnavailableException` with a `reason`, and honest `Unsupported` results where a
  platform cannot provide the capability.
- Keep each capability independently usable and fakeable.

## Non-goals

- Integration with system password managers or AutoFill (iCloud Keychain sharing, Android
  Credential Manager sign-in). Credentials remain app-private.
- Web targets, native Linux/Windows targets.
- Exporting private keys, or general-purpose certificate validation.

## API shape

**Decide:** separate interfaces per capability, created by factories on each interface's
companion, mirroring `CredentialKeychain.forCurrentPlatform`. One god-interface would make
fakes large and force every platform to stub capabilities it lacks.

```kotlin
public interface PasswordStore {
    public fun save(credential: PasswordCredential)
    public fun find(server: String, username: String): PasswordCredential?
    public fun findAll(server: String): List<PasswordCredential>
    public fun delete(server: String, username: String)
    public fun clear()
}

public class PasswordCredential(
    public val server: String,     // host or logical service, e.g. "api.example.com"
    public val username: String,
    public val password: String,
)

public interface CertificateStore {
    public fun importPkcs12(alias: String, pkcs12: ByteArray, passphrase: CharArray)
    public fun importCertificate(alias: String, der: ByteArray)
    public fun certificateChain(alias: String): List<ByteArray>?  // DER; never private keys
    public fun aliases(): List<String>
    public fun delete(alias: String)
    public fun clear()
}

public interface HardwareKeyStore {
    public fun generate(alias: String, spec: HardwareKeySpec = HardwareKeySpec()): HardwareKeyInfo
    public fun info(alias: String): HardwareKeyInfo?
    public fun sign(alias: String, data: ByteArray): ByteArray           // ECDSA P-256, DER signature
    public fun delete(alias: String)
    public fun clear()
}

public class HardwareKeyInfo(
    public val alias: String,
    public val publicKeyDer: ByteArray,    // SubjectPublicKeyInfo
    public val securityLevel: SecurityLevel,
)

public enum class SecurityLevel { Software, TrustedEnvironment, StrongBox, SecureEnclave }

public interface ProtectedKeychain {           // biometric-gated secrets
    public suspend fun read(key: String, prompt: AuthenticationPrompt): String?
    public fun write(key: String, value: String)    // writing needs no authentication
    public fun delete(key: String)
    public fun clear()
}
```

Platform-native handles (Android `PrivateKey`/`KeyStore.PrivateKeyEntry`, JVM `KeyManager`,
Apple `SecIdentityRef`/`SecKeyRef`) are exposed through platform-specific extension functions,
so apps can use identities for mutual TLS and keys for platform crypto APIs without the common
API modelling them.

**Decide:** add failure reasons now. Adding an enum constant after release breaks exhaustive
`when` expressions in consumer code:

- `Canceled` — the user dismissed an authentication prompt.
- `AuthenticationInvalidated` — biometric enrollment changed and the protected key is gone.

## Platform mapping

### 1. Username/password

| Platform | Backend | Notes |
|---|---|---|
| Android | Same AES-GCM Keystore store as today, structured record per server/username | No system password store exists for app-private credentials |
| iOS/tvOS/watchOS/macOS native | `kSecClassInternetPassword` with `kSecAttrServer` + `kSecAttrAccount`; namespace in `kSecAttrSecurityDomain` | Honors `AppleAccessibility`; never synchronized |
| macOS JVM | `security add-internet-password -s server -a user -r` via `-i` stdin | Same same-user readability caveat as generic passwords |
| Linux JVM | Secret Service item with `server`/`username` attributes | Reuses `library` marker |
| Windows JVM | Windows Credential Manager (`CredWriteW`, `CRED_TYPE_GENERIC`) | Replaces DPAPI files for this capability; needs a PowerShell P/Invoke shim |

### 2. Certificates and identities

| Platform | Backend | Notes |
|---|---|---|
| Android | `AndroidKeyStore` `setEntry(PrivateKeyEntry, KeyProtection)` | Private key becomes non-exportable on import (API 23+) |
| Apple native | `SecPKCS12Import`, then `SecItemAdd` identity + certificates | iOS requires identities be imported into the app's keychain |
| macOS JVM | JDK `KeychainStore` provider, or `security import` | `security import -P` takes the passphrase as an argument (visible in `ps`) — **must not be used**; prefer the JCA provider |
| Windows JVM | JDK `SunMSCAPI` `Windows-MY` KeyStore | Native current-user certificate store, no subprocess |
| Linux JVM | PKCS#12 bytes as an encrypted Secret Service item | No standard secure certificate store; the 8 KiB `secret-tool` limit rules out large chains — needs D-Bus instead of `secret-tool`, or `Unsupported` above the limit |

### 3. Hardware-backed keys

| Platform | Backend | Security level |
|---|---|---|
| Android | `KeyPairGenerator` EC P-256 in `AndroidKeyStore`; `setIsStrongBoxBacked` on API 28+ with TEE fallback | Read back via `KeyInfo.getSecurityLevel` (API 31+) or `isInsideSecureHardware` |
| iOS/tvOS/watchOS | `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` | `SecureEnclave` on device; simulator has none → `Unsupported` or `Software` per spec |
| macOS native | Secure Enclave requires the data-protection keychain → signed app with keychain entitlements | Unsigned tools get `Unsupported` |
| Desktop JVM | No CLI path to Secure Enclave or TPM | `Unsupported` |

**Decide:** whether `HardwareKeySpec(requireHardware = true)` fails with `Unsupported` when only
software keys are available, or silently falls back and reports `SecurityLevel.Software`.
Recommendation: fail by default; allow an explicit opt-in to software keys.

### 4. Biometric-protected secrets

| Platform | Backend | Requirements |
|---|---|---|
| Android | Keystore key with `setUserAuthenticationRequired(true)` + `setInvalidatedByBiometricEnrollment(true)`; decrypt through `BiometricPrompt` `CryptoObject` | `androidx.biometric`, a `FragmentActivity` supplied per read, Class 3 biometrics |
| iOS/macOS native | `SecAccessControlCreateWithFlags(.biometryCurrentSet)`; read with `kSecUseAuthenticationContext` (`LAContext`) and `kSecUseOperationPrompt` | `NSFaceIDUsageDescription`; macOS requires the data-protection keychain (signed app) |
| tvOS/watchOS | No biometrics | `Unsupported` |
| Desktop JVM | No supported path | `Unsupported` |

Reads suspend and must not block the main thread while a prompt is visible.

**Decide:** module split. Recommendation: publish biometrics as a separate artifact,
`credential-keychain-kotlin-biometric`, so the core library stays free of `androidx.biometric`
and the `suspend`/UI requirements. This turns the build into a multi-module project, and the
artifact checker and consumer build must cover both artifacts.

## Cross-cutting concerns

- **Namespacing:** every capability uses the same service/account namespace, so `clear()` stays
  scoped per app and user.
- **Validation:** shared validators for server, username, alias, and binary sizes; passphrases as
  `CharArray` that backends zero after use.
- **Testing:** injectable seams (command runner, `SecItem`/Keystore facades) for deterministic
  status mapping; real-store tests on macOS, Linux, and Windows CI; Android emulator tests for
  Keystore, StrongBox skipped where unavailable; Secure Enclave and biometrics need an app-hosted
  device harness, which does not exist yet.
- **Swift interop:** new APIs must bridge cleanly (`@Throws`, no default-argument-only overloads,
  `suspend` functions exported as async completion handlers).

## Proposed phasing

Each phase is its own PR with docs, ABI baselines, and tests. All land before 0.1.0 is tagged.

1. Failure reasons (`Canceled`, `AuthenticationInvalidated`) and shared validation.
2. `PasswordStore` — smallest surface, reuses existing backends.
3. `HardwareKeyStore` — Android and Apple native; `Unsupported` on desktop JVM.
4. `CertificateStore` — the Linux size limit and macOS passphrase handling need care.
5. `ProtectedKeychain` in the biometric module, plus an app-hosted iOS/Android test harness.

## Open decisions

1. Separate interfaces per capability (recommended) vs. one expanded interface.
2. New failure reasons added before 0.1.0.
3. Hardware keys: fail without hardware (recommended) vs. software fallback.
4. Biometrics as a separate artifact (recommended) vs. in core.
5. Windows passwords in Credential Manager (recommended) vs. DPAPI files like generic secrets.
6. Linux certificates: D-Bus client for large items vs. `Unsupported` above 8 KiB.
