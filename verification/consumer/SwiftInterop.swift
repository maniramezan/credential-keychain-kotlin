import Foundation
import KeychainConsumer

func expectError(_ operation: () throws -> Void) {
    do {
        try operation()
        fatalError("Expected a catchable Kotlin error")
    } catch {
        precondition((error as NSError).kotlinException != nil)
    }
}

expectError {
    _ = try CredentialKeychainCompanion.shared.forCurrentPlatform(serviceName: "", accountName: "account")
}
let store = try CredentialKeychainCompanion.shared.forCurrentPlatform(serviceName: "swift-verification", accountName: "account")
expectError { _ = try store.read(key: "") }
expectError { try store.write(key: "key", value: "\0") }
expectError { try store.delete(key: "") }

let unavailable = ConsumerKt.unavailableForSwift()
expectError { _ = try unavailable.read(key: "key") }
expectError { try unavailable.write(key: "key", value: "secret") }
expectError { try unavailable.delete(key: "key") }
print("Swift factory, validation, and unavailable-store error propagation passed.")
