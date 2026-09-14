import Foundation
import KeychainConsumer

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
    do {
        _ = try certificates.aliases()
        failures.append("CertificateStore should be Unsupported until the Apple backend lands")
    } catch {
        check(reason(of: error) == KeychainUnavailableException.Reason.unsupported, "CertificateStore is Unsupported on Apple for now")
    }
} catch {
    failures.append("CertificateStore factory threw \(error)")
}

if failures.isEmpty {
    print("HARNESS-PASS")
    exit(0)
} else {
    failures.forEach { print("HARNESS-FAIL: \($0)") }
    exit(1)
}
