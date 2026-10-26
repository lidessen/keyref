// Sync engine tests (docs/protocol.md §8, design §10.6): signature
// verification before applying, revision guards, tombstone cascades,
// grant deletions, revocation delivery, cursor_stale re-bootstrap and
// grants-digest reconciliation. The API layer is a MockURLProtocol.
import CryptoKit
import XCTest

@testable import KeyrefCore

final class SyncEngineTests: XCTestCase {
    private let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    private let ownerDev = "99998888777766665555444433332222"
    private let cliDev = "aaaabbbbccccddddeeeeffff00001111"
    private let itemID = "deadbeefdeadbeefdeadbeefdeadbeef"

    private var owner: OwnerKeys!
    private var ownerSigner: SoftwareP256Signer!
    private var store: InMemorySyncStateStore!

    override func setUpWithError() throws {
        owner = try OwnerKeys.generate(preferEnclave: false)
        // The tests sign rows with a software P-256 key; the pinned owner
        // key is that key's public point.
        ownerSigner = SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
        store = InMemorySyncStateStore()
        try store.setVaultID(vaultID)
        try store.setPinnedOwnerKey(ownerSigner.signPublicKey)
        try store.setOwnDeviceID(cliDev)
    }

    override func tearDown() {
        MockURLProtocol.reset()
    }

    private func makeAPI() -> APIClient {
        APIClient(baseURL: URL(string: "https://sync.example")!,
                  session: MockURLProtocol.makeSession())
    }

    private func signedItem(revision: UInt64, tombstone: Bool = false) throws -> ItemData {
        let t = tombstone
            ? ItemTranscript.tombstone(vaultID: vaultID, itemID: itemID, revision: revision, writerDeviceID: ownerDev)
            : ItemTranscript(vaultID: vaultID, itemID: itemID, revision: revision,
                             metaCiphertext: Data(repeating: 1, count: 40),
                             secretCiphertext: Data(repeating: 2, count: 44),
                             vaultWrappedMetaKey: Data(repeating: 3, count: 44),
                             vaultWrappedItemKey: Data(repeating: 4, count: 44),
                             writerDeviceID: ownerDev)
        return ItemData(vaultID: vaultID, itemID: itemID, revision: revision,
                        tombstone: tombstone,
                        metaCiphertext: t.metaCiphertext, secretCiphertext: t.secretCiphertext,
                        vaultWrappedMetaKey: t.vaultWrappedMetaKey, vaultWrappedItemKey: t.vaultWrappedItemKey,
                        writerDeviceID: ownerDev,
                        signature: try ownerSigner.sign(try t.buildBytes()), updatedAt: 1)
    }

    private func signedGrant(revision: UInt64, deleted: Bool = false,
                             device device: String? = nil) throws -> GrantData {
        let deviceID = device ?? cliDev
        let t = deleted
            ? GrantTranscript.deletion(vaultID: vaultID, deviceID: deviceID, itemID: itemID,
                                       kind: GrantKind.use, revision: revision)
            : GrantTranscript(vaultID: vaultID, deviceID: deviceID, itemID: itemID,
                              kind: GrantKind.use, revision: revision, expiresAt: 1790000000000,
                              hpkeEnc: Data(repeating: 5, count: 32), wrappedKey: Data(repeating: 6, count: 48))
        return GrantData(deviceID: deviceID, itemID: itemID, kind: GrantKind.use,
                         hpkeEnc: t.hpkeEnc, wrappedKey: t.wrappedKey,
                         expiresAt: Int64(bitPattern: t.expiresAt), revision: revision,
                         signature: try ownerSigner.sign(try t.buildBytes()), deleted: deleted)
    }

    private func signedDirectory(revision: UInt64, cliStatus: String) throws -> DirectoryData {
        let dir = DirectoryTranscript(vaultID: vaultID, directoryRevision: revision, devices: [
            DirectoryDevice(deviceID: cliDev, kind: DeviceKind.cli, status: cliStatus,
                            hpkeKEM: KEMName.x25519, hpkePublicKey: Data(repeating: 7, count: 32),
                            signAlg: SignAlg.ed25519, signPublicKey: Data(repeating: 8, count: 32),
                            grantsDigest: emptyGrantsDigest()),
            DirectoryDevice(deviceID: ownerDev, kind: DeviceKind.ios, status: DeviceStatus.active,
                            hpkeKEM: KEMName.p256, hpkePublicKey: Data(repeating: 9, count: 65),
                            signAlg: SignAlg.ecdsaP256, signPublicKey: ownerSigner.signPublicKey,
                            grantsDigest: emptyGrantsDigest()),
        ])
        let bytes = try dir.buildBytes()
        return DirectoryData(directoryRevision: revision, signed: bytes,
                             signature: try ownerSigner.sign(bytes))
    }

    private func change(seq: Int64, entity: String, entityID: String, data: Data) -> SyncChange {
        // The protocol transports change.data as an embedded JSON object
        // (protocol §8.1), so the encoded row is captured as RawJSON.
        SyncChange(seq: seq, entity: entity, entityID: entityID, createdAt: 1,
                   data: (try? RawJSON(json: data)) ?? .null)
    }

    // MARK: items

    func testApplyItemAndRevisionGuard() throws {
        let engine = SyncEngine(api: makeAPI())
        let row = try signedItem(revision: 2)
        var outcome = try engine.apply(response: SyncResponse(cursor: 1, hasMore: false, changes: [
            change(seq: 1, entity: "item", entityID: try EntityID.item(itemID),
                   data: try WireJSON.encoder.encode(row)),
        ]), store: store)
        XCTAssertEqual(outcome.applied, 1)
        XCTAssertEqual(try store.item(itemID)?.revision, 2)

        // Older revision: ignored (design §6.2).
        let old = try signedItem(revision: 1)
        outcome = try engine.apply(response: SyncResponse(cursor: 2, hasMore: false, changes: [
            change(seq: 2, entity: "item", entityID: try EntityID.item(itemID),
                   data: try WireJSON.encoder.encode(old)),
        ]), store: store)
        XCTAssertEqual(outcome.applied, 0)
        XCTAssertEqual(try store.item(itemID)?.revision, 2)

        // Tampered signature: batch rejected, old data stays.
        var bad = try signedItem(revision: 3)
        bad.signature[bad.signature.startIndex] ^= 0x01
        XCTAssertThrowsError(try engine.apply(response: SyncResponse(cursor: 3, hasMore: false, changes: [
            change(seq: 3, entity: "item", entityID: try EntityID.item(itemID),
                   data: try WireJSON.encoder.encode(bad)),
        ]), store: store)) { error in
            guard case SyncError.tampered = error else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(try store.item(itemID)?.revision, 2)
    }

    func testTombstoneCascadesGrants() throws {
        let engine = SyncEngine(api: makeAPI())
        try store.upsertItem(try signedItem(revision: 1))
        try store.upsertGrant(try signedGrant(revision: 1))
        XCTAssertNotNil(try store.item(itemID))

        let tombstone = try signedItem(revision: 2, tombstone: true)
        let outcome = try engine.apply(response: SyncResponse(cursor: 2, hasMore: false, changes: [
            change(seq: 2, entity: "item", entityID: try EntityID.item(itemID),
                   data: try WireJSON.encoder.encode(tombstone)),
        ]), store: store)
        XCTAssertEqual(outcome.deleted, 1)
        XCTAssertNil(try store.item(itemID))
        // Cascade: the item's grants are gone too (design §6.3, §6.5).
        XCTAssertTrue(try store.grants().isEmpty)
    }

    // MARK: grants

    func testGrantApplyForeignVerifiedAndKept() throws {
        let engine = SyncEngine(api: makeAPI())
        // Grant for another device: owner devices keep it (verified) — they
        // need other devices' rows for §8.4 renewal and the grant lists.
        let foreign = try signedGrant(revision: 1, device: "11112222333344441111222233334444")
        var outcome = try engine.apply(response: SyncResponse(cursor: 1, hasMore: false, changes: [
            change(seq: 1, entity: "grant", entityID: try EntityID.grant(deviceID: foreign.deviceID, itemID: itemID, kind: "use"),
                   data: try WireJSON.encoder.encode(foreign)),
        ]), store: store)
        XCTAssertEqual(outcome.applied, 1)
        XCTAssertEqual(try store.grants().count, 1)
        XCTAssertEqual(try store.grants().first?.deviceID, foreign.deviceID)

        // Own grant applies.
        let grant = try signedGrant(revision: 1)
        outcome = try engine.apply(response: SyncResponse(cursor: 1, hasMore: false, changes: [
            change(seq: 1, entity: "grant", entityID: try EntityID.grant(deviceID: cliDev, itemID: itemID, kind: "use"),
                   data: try WireJSON.encoder.encode(grant)),
        ]), store: store)
        XCTAssertEqual(outcome.applied, 1)
        XCTAssertEqual(try store.grants().count, 2)

        // Tampered grant fails closed.
        var bad = try signedGrant(revision: 2)
        bad.wrappedKey[bad.wrappedKey.startIndex] ^= 0x01
        XCTAssertThrowsError(try engine.apply(response: SyncResponse(cursor: 2, hasMore: false, changes: [
            change(seq: 2, entity: "grant", entityID: try EntityID.grant(deviceID: cliDev, itemID: itemID, kind: "use"),
                   data: try WireJSON.encoder.encode(bad)),
        ]), store: store))

        // Deletion form clears the local row (合成 grant 变更) — only the
        // deleted device's row; the foreign row stays.
        let del = try signedGrant(revision: 3, deleted: true)
        outcome = try engine.apply(response: SyncResponse(cursor: 3, hasMore: false, changes: [
            change(seq: 3, entity: "grant", entityID: try EntityID.grant(deviceID: cliDev, itemID: itemID, kind: "use"),
                   data: try WireJSON.encoder.encode(del)),
        ]), store: store)
        XCTAssertEqual(outcome.deleted, 1)
        XCTAssertEqual(try store.grants().count, 1)
        XCTAssertEqual(try store.grants().first?.deviceID, foreign.deviceID)
    }

    // MARK: revocation delivery (§8.4)

    func testRevokedViaDirectoryTriggersCleanup() throws {
        let engine = SyncEngine(api: makeAPI())
        try store.upsertGrant(try signedGrant(revision: 1))
        let dir = try signedDirectory(revision: 7, cliStatus: DeviceStatus.revoked)
        let outcome = try engine.apply(response: SyncResponse(cursor: 7, hasMore: false, changes: [
            change(seq: 7, entity: "directory", entityID: try EntityID.directory(vaultID),
                   data: try WireJSON.encoder.encode(dir)),
        ]), store: store)
        XCTAssertTrue(outcome.revokedSelf)
        // Local cleanup happened (design §8.2).
        XCTAssertTrue(try store.grants().isEmpty)
        XCTAssertNotNil(try store.directory())

        // An active directory does not revoke.
        store = InMemorySyncStateStore()
        try store.setVaultID(vaultID)
        try store.setPinnedOwnerKey(ownerSigner.signPublicKey)
        try store.setOwnDeviceID(cliDev)
        try store.upsertGrant(try signedGrant(revision: 1))
        let active = try signedDirectory(revision: 8, cliStatus: DeviceStatus.active)
        let ok = try engine.apply(response: SyncResponse(cursor: 8, hasMore: false, changes: [
            change(seq: 8, entity: "directory", entityID: try EntityID.directory(vaultID),
                   data: try WireJSON.encoder.encode(active)),
        ]), store: store)
        XCTAssertFalse(ok.revokedSelf)
        XCTAssertEqual(try store.grants().count, 1)
    }

    func testRevokedViaDeviceEntity() throws {
        let engine = SyncEngine(api: makeAPI())
        try store.upsertGrant(try signedGrant(revision: 1))
        let dev = DeviceData(deviceID: cliDev, kind: DeviceKind.cli, status: DeviceStatus.revoked,
                             label: "cli", createdAt: 1, revokedAt: 2)
        let outcome = try engine.apply(response: SyncResponse(cursor: 1, hasMore: false, changes: [
            change(seq: 1, entity: "device", entityID: try EntityID.device(cliDev),
                   data: try WireJSON.encoder.encode(dev)),
        ]), store: store)
        XCTAssertTrue(outcome.revokedSelf)
        XCTAssertTrue(try store.grants().isEmpty)
    }

    // MARK: cursor_stale re-bootstrap (§8.1)

    func testCursorStaleResetsToZero() async throws {
        MockURLProtocol.reset()
        let requested = CursorRecorder()
        let bootstrapRow = try signedItem(revision: 1)
        let itemID = self.itemID
        MockURLProtocol.handler = { request, _ in
            guard request.url!.path.hasSuffix("/sync") else {
                return (200, Data("{\"grants\":[],\"grants_digest\":\"\",\"directory_revision\":1}".utf8))
            }
            let cursor = Int64(URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
                .queryItems!.first(where: { $0.name == "cursor" })!.value!)!
            requested.record(cursor)
            if cursor == 5 {
                return (409, Data("{\"error\":\"cursor_stale\"}".utf8))
            }
            let body = try WireJSON.encoder.encode(SyncResponse(cursor: 9, hasMore: false, changes: [
                SyncChange(seq: 9, entity: "item", entityID: "item:\(itemID)",
                           createdAt: 1, data: (try? RawJSON(json: WireJSON.encoder.encode(bootstrapRow))) ?? .null),
            ]))
            return (200, body)
        }
        try store.setCursor(5)
        let engine = SyncEngine(api: makeAPI())
        let outcome = try await engine.run(store: store)
        XCTAssertFalse(outcome.revokedSelf)
        XCTAssertEqual(outcome.applied, 1)
        XCTAssertEqual(requested.all, [5, 0], "cursor_stale must reset to 0 exactly once")
        XCTAssertEqual(try store.cursor(), 9)
    }

    // MARK: grants reconciliation (§9.1, §10.6)

    func testReconcileGrantsDigestMismatchFailsClosed() async throws {
        let grant = try signedGrant(revision: 1)
        // Server claims a digest that matches neither the local set nor
        // the returned grants.
        MockURLProtocol.handler = { _, _ in
            (200, try WireJSON.encoder.encode(GrantsSelfResponse(
                grants: [grant], grantsDigest: Data(repeating: 9, count: 32), directoryRevision: 1)))
        }
        try store.upsertGrant(grant)
        let engine = SyncEngine(api: makeAPI())
        do {
            try await engine.reconcileGrants(store: store)
            XCTFail("digest mismatch must fail closed")
        } catch let e as SyncError {
            guard case .tampered = e else { return XCTFail("\(e)") }
        }
    }

    func testReconcileMatchesAndPrunes() async throws {
        let grant = try signedGrant(revision: 1)
        let digest = try grantsDigest([grant.transcript(vaultID: vaultID)])
        MockURLProtocol.handler = { _, _ in
            (200, try WireJSON.encoder.encode(GrantsSelfResponse(
                grants: [grant], grantsDigest: digest, directoryRevision: 1)))
        }
        // A stale local grant the server no longer lists gets pruned.
        let stale = try signedGrant(revision: 9)
        try store.upsertGrant(stale)
        try store.upsertGrant(grant)
        let engine = SyncEngine(api: makeAPI())
        try await engine.reconcileGrants(store: store)
        let remaining = try store.grants()
        XCTAssertEqual(remaining.count, 1)
        XCTAssertEqual(remaining.first?.revision, 1)
    }

    func testRunAppliesPagesUntilCurrent() async throws {
        let row = try signedItem(revision: 1)
        let itemID = self.itemID
        MockURLProtocol.handler = { request, _ in
            guard request.url!.path.hasSuffix("/sync") else {
                return (200, Data("{\"grants\":[],\"grants_digest\":\"\",\"directory_revision\":1}".utf8))
            }
            let cursor = Int64(URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
                .queryItems!.first(where: { $0.name == "cursor" })!.value!)!
            if cursor == 0 {
                let page = try WireJSON.encoder.encode(SyncResponse(cursor: 3, hasMore: true, changes: [
                    SyncChange(seq: 1, entity: "item", entityID: "item:\(itemID)",
                               createdAt: 1, data: (try? RawJSON(json: WireJSON.encoder.encode(row))) ?? .null),
                ]))
                return (200, page)
            }
            let page = try WireJSON.encoder.encode(SyncResponse(cursor: 4, hasMore: false, changes: []))
            return (200, page)
        }
        // grants/self for reconciliation.
        let grant = try signedGrant(revision: 1)
        let digest = try grantsDigest([grant.transcript(vaultID: vaultID)])
        let existingHandler = MockURLProtocol.handler
        MockURLProtocol.handler = { request, body in
            if request.url!.path.hasSuffix("/grants/self") {
                return (200, try WireJSON.encoder.encode(GrantsSelfResponse(
                    grants: [grant], grantsDigest: digest, directoryRevision: 1)))
            }
            return try existingHandler!(request, body)
        }
        let engine = SyncEngine(api: makeAPI())
        let outcome = try await engine.run(store: store)
        XCTAssertEqual(outcome.applied, 1)
        XCTAssertEqual(try store.cursor(), 4)
        XCTAssertEqual(try store.grants().count, 1)
    }
}


/// Thread-safe cursor recorder for handler closures.
final class CursorRecorder: @unchecked Sendable {
    private var values: [Int64] = []
    private let lock = NSLock()
    func record(_ v: Int64) {
        lock.lock(); defer { lock.unlock() }
        values.append(v)
    }
    var all: [Int64] {
        lock.lock(); defer { lock.unlock() }
        return values
    }
}
