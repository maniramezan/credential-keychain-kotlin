import Foundation
import KeychainConsumer
import Security

// Runs inside an ad-hoc signed iOS simulator app with keychain entitlements, so every store uses
// the data-protection keychain the way a shipped app does. Prints HARNESS-PASS or HARNESS-FAIL lines.

var failures: [String] = []

func check(_ condition: @autoclosure () throws -> Bool, _ message: String) {
    do {
        if try !condition() { failures.append(message) }
    } catch {
        failures.append("\(message): threw \(error)")
    }
}

func reason(of error: Error) -> KeychainUnavailableException.Reason? {
    ((error as NSError).kotlinException as? KeychainUnavailableException)?.reason
}

func bytes(_ values: [Int8]) -> KotlinByteArray {
    let array = KotlinByteArray(size: Int32(values.count))
    for (index, value) in values.enumerated() { array.set(index: Int32(index), value: value) }
    return array
}

func kotlinBytes(_ data: Data) -> KotlinByteArray {
    let array = KotlinByteArray(size: Int32(data.count))
    for (index, byte) in data.enumerated() { array.set(index: Int32(index), value: Int8(bitPattern: byte)) }
    return array
}

func kotlinChars(_ string: String) -> KotlinCharArray {
    let units = Array(string.utf16)
    let array = KotlinCharArray(size: Int32(units.count))
    for (index, unit) in units.enumerated() { array.set(index: Int32(index), value: unit) }
    return array
}

/** Counts every identity in this app's keychain; the harness app starts with none. */
func identityCount() -> Int {
    var result: CFTypeRef?
    let status = SecItemCopyMatching([kSecClass: kSecClassIdentity, kSecMatchLimit: kSecMatchLimitAll, kSecReturnRef: true] as CFDictionary, &result)
    return status == errSecSuccess ? ((result as? [Any])?.count ?? 0) : 0
}

// Throwaway legacy-format EC PKCS#12 identity (passphrase android-test-passphrase), shared with the Android tests.
let ecPkcs12Base64 =
    "MIIDhAIBAzCCAz0GCSqGSIb3DQEHAaCCAy4EggMqMIIDJjCB4wYJKoZIhvcNAQcBoIHVBIHSMIHPMIHMBgsqhkiG9w0BDAoBAqB3MHUwKQYKKoZIhvcNAQwBAzAbBBS2qlejDZje36xaTxA2v+aZ1GqBmgIDAMNQBEgZlxdOFZhMx+sEw9tjX0x3asslOVuFILB4l4xphECK8PE2JVwjLn9mXWMqpLjbEGljT2cwhW5l3SguD13AQzXjJnJsi4tWoUcxRDAfBgkqhkiG9w0BCRQxEh4QAGkAZABlAG4AdABpAHQAeTAhBgkqhkiG9w0BCRUxFAQSVGltZSAxNzg5NDIzNzA2MjI1MIICPAYJKoZIhvcNAQcGoIICLTCCAikCAQAwggIiBgkqhkiG9w0BBwEwKQYKKoZIhvcNAQwBBjAbBBQikssV2C9M4mcuSqSnd5PwVPOtZgIDAMNQgIIB6Gq6AumIFUhKpxo4/LKu3flUbGsY6ZXLZCxoT3YQwPF25H03Ob27Yv/rGjMPzpGffLYbV6o+ihZXjMgZh9JkpTF0FqIWT0rkP2vMbRjYwLBvowaAI5LY8teIfcmT+yAwYnTSJ16DQLeJoR0G/RvzVUNIbQeUWBCwq+oIElCr1Qqwz3SwcyJnlQPXCER9xADlp84hIEIUxMv2NPCaldkd2QS/7pWTsJbj7m4NVoL+hlzWEhftvVLYtcukJGA7o9GaDTb5v36kYPLFkbzZIZ9zBevmZ+f8ruCY8OpX/evvuyXT7FNEMKBEIZUcudCCNHmIcaMaehVuwLrBD1CvkU/YQzM9hG5Kv335g5fYFbrQMWArfIFv7AofsdqGL6b7PqhGszuvoC/SAQWXd0PUS60Tn13aur5LL3Quke5DOgA7z3V/S4ZzCsqMI24MF6G1KP5YymmDiLRC3DGgVjcig8/heA7XMBFcehrzK2tNKFws2PMFrXvIz6fJYBhI2VCIZr8oy8LajvmxGF1IHLX31qBB7qpaHRm1XmBj89pDmN/WV7MqlibYpBTi00dRERo+k0IKbqOd8FkvVC84T8Y2xvGpd2wj6pJi1Zqr7egRBy88Ky/5iB62+8YlM6rDLC80sI/gL77uAje6h5DrMD4wITAJBgUrDgMCGgUABBThyJV2drGDcOXfrbA6/eUOibb07gQUrY1Wnm2v4/Vozr+K2bD+NfVx0JgCAwGGoA=="

let service = "credential-keychain-harness-\(UUID().uuidString)"
print("HARNESS-BEGIN")

do {
    let first = try CredentialKeychainCompanion.shared.forCurrentPlatform(serviceName: service, accountName: "first")
    let second = try CredentialKeychainCompanion.shared.forCurrentPlatform(serviceName: service, accountName: "second")
    defer {
        try? first.clear()
        try? second.clear()
    }
    check(try first.read(key: "token") == nil, "CredentialKeychain starts empty")
    try first.write(key: "token", value: "  秘密\nline two")
    try second.write(key: "token", value: "other account")
    check(try first.read(key: "token") == "  秘密\nline two", "CredentialKeychain round trip")
    check(try second.read(key: "token") == "other account", "CredentialKeychain isolates accounts")
    try first.write(key: "token", value: "updated")
    check(try first.read(key: "token") == "updated", "CredentialKeychain update")
    try first.clear()
    check(try first.read(key: "token") == nil, "CredentialKeychain clear")
    check(try second.read(key: "token") == "other account", "CredentialKeychain clear is namespaced")
} catch {
    failures.append("CredentialKeychain threw \(error)")
}

do {
    let passwords = try PasswordStoreCompanion.shared.forCurrentPlatform(serviceName: service, accountName: "first")
    defer { try? passwords.clear() }
    try passwords.save(credential: PasswordCredential(server: "api.example.com", username: "bob", password: "bob password"))
    try passwords.save(credential: PasswordCredential(server: "api.example.com", username: "alice", password: "a ' \" \\ 秘密"))
    try passwords.save(credential: PasswordCredential(server: "other.example.com", username: "carol", password: "other server"))
    check(try passwords.find(server: "api.example.com", username: "alice")?.password == "a ' \" \\ 秘密", "PasswordStore find")
    check(try passwords.findAll(server: "api.example.com").map { $0.username } == ["alice", "bob"], "PasswordStore findAll is sorted and per server")
    try passwords.delete(server: "api.example.com", username: "bob")
    check(try passwords.find(server: "api.example.com", username: "bob") == nil, "PasswordStore delete")
    try passwords.clear()
    check(try passwords.findAll(server: "other.example.com").isEmpty, "PasswordStore clear")
} catch {
    failures.append("PasswordStore threw \(error)")
}

do {
    let keys = try HardwareKeyStoreCompanion.shared.forCurrentPlatform(serviceName: service, accountName: "first")
    defer { try? keys.clear() }
    do {
        let strict = try keys.generate(alias: "strict", spec: HardwareKeySpec(allowSoftwareKeys: false))
        // Kotlin/Native exports multi-word enum entries in lowercase.
        check(strict.securityLevel == SecurityLevel.secureenclave, "strict generation only returns Secure Enclave keys")
    } catch {
        check(reason(of: error) == KeychainUnavailableException.Reason.unsupported, "strict generation without a Secure Enclave is Unsupported")
        check(try keys.info(alias: "strict") == nil, "failed strict generation leaves no key")
    }
    let key = try keys.generate(alias: "software", spec: HardwareKeySpec(allowSoftwareKeys: true))
    check(key.publicKeyDer.size == 91, "HardwareKeyStore exports a P-256 public key")
    let signature = try keys.sign(alias: "software", data: bytes([1, 2, 3, 4]))
    check(signature != nil && signature!.get(index: 0) == 0x30, "HardwareKeyStore signs with a DER signature")
    check(try keys.info(alias: "software") == key, "HardwareKeyStore info round trip")
    try keys.delete(alias: "software")
    check(try keys.info(alias: "software") == nil, "HardwareKeyStore delete")
} catch {
    failures.append("HardwareKeyStore threw \(error)")
}

do {
    let certificates = try CertificateStoreCompanion.shared.forCurrentPlatform(serviceName: service, accountName: "first")
    defer { try? certificates.clear() }
    let pkcs12 = kotlinBytes(Data(base64Encoded: ecPkcs12Base64)!)
    let passphrase = kotlinChars("android-test-passphrase")
    check(identityCount() == 0, "CertificateStore starts with no keychain identities")

    let identity = try certificates.importPkcs12(alias: "client", pkcs12: pkcs12, passphrase: passphrase)
    check(identity.hasPrivateKey, "CertificateStore imports a PKCS#12 identity")
    check(identityCount() == 1, "the identity is stored in the keychain")
    check(try certificates.info(alias: "client") == identity, "CertificateStore info round trip")

    let pinned = try certificates.importCertificate(alias: "pinned", certificateDer: identity.certificateChainDer[0])
    check(!pinned.hasPrivateKey, "CertificateStore imports a certificate")
    check(try certificates.aliases() == ["client", "pinned"], "CertificateStore aliases are sorted")

    do {
        _ = try certificates.importPkcs12(alias: "wrong", pkcs12: pkcs12, passphrase: kotlinChars("wrong passphrase"))
        failures.append("a wrong PKCS#12 passphrase was accepted")
    } catch {
        check((error as NSError).kotlinException is KotlinIllegalArgumentException, "a wrong passphrase is IllegalArgumentException")
    }

    try certificates.delete(alias: "client")
    check(try certificates.info(alias: "client") == nil, "CertificateStore delete")
    check(identityCount() == 0, "delete removes the certificate and private key from the keychain")
    _ = try certificates.importPkcs12(alias: "client", pkcs12: pkcs12, passphrase: passphrase)
    check(identityCount() == 1, "an identity can be imported again after delete")
    try certificates.clear()
    check(identityCount() == 0, "clear removes identities from the keychain")
    check(try certificates.aliases().isEmpty, "CertificateStore clear")
} catch {
    failures.append("CertificateStore threw \(error)")
}

if failures.isEmpty {
    print("HARNESS-PASS")
    exit(0)
} else {
    failures.forEach { print("HARNESS-FAIL: \($0)") }
    exit(1)
}
