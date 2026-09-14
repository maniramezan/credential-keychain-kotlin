# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/maniramezan/credential-keychain-kotlin/security/advisories/new).
Do not open a public issue, pull request, or discussion for a security problem, and never
include real credentials in a report.

Include the affected version, platform/backend, and the smallest reproduction you can.
You should receive an acknowledgement within 7 days. Fixes are released as a new version
with a GitHub security advisory; published Maven Central versions cannot be modified.

## Supported versions

Only the latest released version receives security fixes.

## Security model

`credential-keychain-kotlin` delegates protection to each platform's secure storage. It
never writes plaintext to disk, never falls back to insecure storage, and never includes
credentials in exception messages. It does **not** protect against:

- Code running as the same OS user on desktop JVM. macOS login-keychain items created
  through `/usr/bin/security` trust that tool, so any same-user process can read them
  without a prompt. Linux Secret Service exposes unlocked collections to the whole
  session. Windows DPAPI decrypts for any process running as the same Windows user.
- A compromised, rooted, or jailbroken device, or an attacker with the unlocked device.
- Other code inside your own app process.
- Service and account names as an authorization boundary. They isolate entries from
  accidental collisions, not from untrusted apps running as the same user.

On Android, ciphertext is authenticated (AES-256-GCM) and bound to its namespace and key,
and the encryption key never leaves Android Keystore. On iOS, tvOS, and watchOS, entries
are device-only and never synchronized; see `AppleAccessibility` for lock-state behavior.
