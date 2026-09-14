import Foundation
import KeychainConsumer

func expectError(_ operation: () throws -> Void) -> KotlinThrowable {
    do {
        try operation()
        fatalError("Expected a catchable Kotlin error")
    } catch {
        guard let exception = (error as NSError).kotlinException as? KotlinThrowable else {
            fatalError("Expected a Kotlin exception")
        }
        return exception
    }
}

_ = expectError {
    _ = try CredentialKeychainCompanion.shared.forCurrentPlatform(serviceName: "", accountName: "account")
}
let store = try CredentialKeychainCompanion.shared.forCurrentPlatform(serviceName: "swift-verification", accountName: "account")
_ = expectError { _ = try store.read(key: "") }
_ = expectError { try store.write(key: "key", value: "\0") }
_ = expectError { try store.write(key: "key", value: "  ") }
_ = expectError { try store.delete(key: "") }

_ = expectError {
    _ = try PasswordStoreCompanion.shared.forCurrentPlatform(serviceName: "", accountName: "account")
}
let passwords = try PasswordStoreCompanion.shared.forCurrentPlatform(serviceName: "swift-verification", accountName: "account")
_ = expectError { _ = try passwords.find(server: "", username: "alice") }
_ = expectError { _ = try passwords.findAll(server: "\n") }
_ = expectError { try passwords.save(credential: PasswordCredential(server: "api.example.com", username: "alice", password: "a\nb")) }
_ = expectError { try passwords.delete(server: "api.example.com", username: "") }

let unavailable = ConsumerKt.unavailableForSwift()
for operation in [
    { _ = try unavailable.read(key: "key") },
    { try unavailable.write(key: "key", value: "secret") },
    { try unavailable.delete(key: "key") },
    { try unavailable.clear() },
] as [() throws -> Void] {
    guard let error = expectError(operation) as? KeychainUnavailableException else {
        fatalError("Expected KeychainUnavailableException")
    }
    precondition(error.reason == KeychainUnavailableException.Reason.failed)
}
print("Swift factory, validation, clear, and failure-reason error propagation passed.")
