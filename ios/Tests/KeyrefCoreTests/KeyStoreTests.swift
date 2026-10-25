// KeyStore tests: in-memory behaviour and the real Keychain-backed store
// (generic-password items, ThisDeviceOnly accessibility). The Keychain
// test only touches items created by this test run under a unique service
// name, so it needs no user interaction.
import XCTest

@testable import KeyrefCore

final class KeyStoreTests: XCTestCase {
    func testInMemoryStoreRoundtrip() throws {
        let store = InMemoryKeyStore()
        XCTAssertNil(try store.retrieve(.vaultID))
        try store.store(.vaultID, Data("abc".utf8))
        XCTAssertEqual(try store.retrieve(.vaultID), Data("abc".utf8))
        // Overwrite semantics.
        try store.store(.vaultID, Data("def".utf8), access: .biometryCurrentSet)
        XCTAssertEqual(try store.retrieve(.vaultID), Data("def".utf8))
        XCTAssertEqual(store.access(of: .vaultID), .biometryCurrentSet)
        try store.remove(.vaultID)
        XCTAssertNil(try store.retrieve(.vaultID))
        // Remove of a missing slot is a no-op.
        try store.remove(.vaultID)
    }

    func testKeychainStoreRoundtrip() throws {
        // Real Keychain: creates, reads, overwrites and deletes its own
        // item under a unique service. Same-process generic passwords need
        // no interaction.
        let store = KeychainKeyStore(service: "app.keyref.tests.\(UUID().uuidString)")
        defer { try? store.removeAll() }

        XCTAssertNil(try store.retrieve(.vaultID))
        try store.store(.vaultID, Data("vault-123".utf8))
        XCTAssertEqual(try store.retrieve(.vaultID), Data("vault-123".utf8))
        try store.store(.vaultID, Data("vault-456".utf8))
        XCTAssertEqual(try store.retrieve(.vaultID), Data("vault-456".utf8))
        try store.remove(.vaultID)
        XCTAssertNil(try store.retrieve(.vaultID))

        // A second slot stays independent, and removeAll clears everything.
        try store.store(.vmkWrap, Data(repeating: 7, count: 32))
        try store.store(.vaultID, Data("v".utf8))
        try store.removeAll()
        XCTAssertNil(try store.retrieve(.vmkWrap))
        XCTAssertNil(try store.retrieve(.vaultID))
    }
}
