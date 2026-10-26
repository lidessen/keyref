// Snapshot tests (v0.7, design §6.7): the whole-file copy codec (build /
// verify / reject bad signatures), the engine's build+merge revision rules
// and the SQLite local-secret store round-trip. The signature-first rule
// (下载后先验签再入库) and the 「revision 大者胜」 merge are security-relevant
// pure functions — both pinned here.
import CryptoKit
import XCTest

@testable import KeyrefCore

final class SnapshotEngineTests: XCTestCase {
    let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    let writer = "99998888777766665555444433332222"
    let itemA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    let itemB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    // Owner signatures are ECDSA P-256 only (protocol §1.4; the snapshot
    // codec verifies through verifyOwnerSignature).
    var signer: SoftwareP256Signer!
    var ownerKey: Data!

    override func setUpWithError() throws {
        signer = try SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
        ownerKey = signer.signPublicKey
    }

    func localOnlyRow(itemID: String, revision: UInt64) -> ItemData {
        ItemData.make(vaultID: vaultID, itemID: itemID, revision: revision,
                      tombstone: false, metaCiphertext: Data("meta-\(itemID)".utf8),
                      secretCiphertext: Data(), vaultWrappedMetaKey: Data("vwmeta".utf8),
                      vaultWrappedItemKey: Data(), writerDeviceID: writer,
                      signature: Data("sig".utf8), updatedAt: 0)
    }

    func syncedRow(itemID: String, revision: UInt64) -> ItemData {
        ItemData.make(vaultID: vaultID, itemID: itemID, revision: revision,
                      tombstone: false, metaCiphertext: Data("meta".utf8),
                      secretCiphertext: Data("secret".utf8),
                      vaultWrappedMetaKey: Data("vwmeta".utf8),
                      vaultWrappedItemKey: Data("vwitem".utf8),
                      writerDeviceID: writer, signature: Data("sig".utf8), updatedAt: 0)
    }

    func record(itemID: String, revision: UInt64) -> LocalSecretRecord {
        LocalSecretRecord(itemID: itemID,
                          secretCiphertext: Data("secret-ct-\(itemID)".utf8),
                          vaultWrappedItemKey: Data("vw-item-\(itemID)".utf8),
                          revision: revision, updatedAt: 0)
    }

    // MARK: codec

    func testCodecRoundTripAndVerify() throws {
        let manifest = SnapshotManifest(vaultID: vaultID, snapshotRevision: 3, entries: [
            SnapshotEntry(itemID: itemA, revision: 2, metaCiphertext: Data("m1".utf8),
                          secretCiphertext: Data("s1".utf8),
                          vaultWrappedMetaKey: Data("wm".utf8),
                          vaultWrappedItemKey: Data("wi".utf8), writerDeviceID: writer),
        ])
        let data = try SnapshotCodec.build(manifest, signer: signer)
        let verified = try SnapshotCodec.verify(data, ownerSignPublicKeys: [ownerKey])
        XCTAssertEqual(verified, manifest)
        // parseUnverified agrees on the manifest shape.
        XCTAssertEqual(try SnapshotCodec.parseUnverified(data), manifest)
    }

    func testCodecRejectsBadSignatureAndTampering() throws {
        let manifest = SnapshotManifest(vaultID: vaultID, snapshotRevision: 1, entries: [])
        let data = try SnapshotCodec.build(manifest, signer: signer)

        // Wrong trust anchor → badSignature; nothing may be merged.
        let other = try SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
        XCTAssertThrowsError(try SnapshotCodec.verify(data, ownerSignPublicKeys: [other.signPublicKey])) {
            XCTAssertEqual($0 as? SnapshotFormatError, .badSignature)
        }

        // One flipped manifest byte → badSignature (signature covers magic+length+manifest).
        var tampered = data
        tampered[tampered.startIndex + SnapshotCodec.magic.count + 6] ^= 0xFF
        XCTAssertThrowsError(try SnapshotCodec.verify(tampered, ownerSignPublicKeys: [ownerKey]))

        // Not a snapshot at all.
        XCTAssertThrowsError(try SnapshotCodec.verify(Data("junk".utf8), ownerSignPublicKeys: [ownerKey]))
    }

    // MARK: engine build

    func testBuildIncludesOnlyLocalOnlyRowsWithRecordsAndHonorsExclusions() throws {
        let secrets = InMemoryLocalSecretStore()
        try secrets.save(record(itemID: itemA, revision: 2))
        // itemB is synced (has a server-side secret) → never snapshotted.
        let rows = [localOnlyRow(itemID: itemA, revision: 2),
                    syncedRow(itemID: itemB, revision: 1)]
        let result = try SnapshotEngine.build(vaultID: vaultID, snapshotRevision: 1,
                                              rows: rows, secrets: secrets, signer: signer)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.manifest.entries.map(\.itemID), [itemA])
        XCTAssertEqual(result?.manifest.snapshotRevision, 1)

        // Per-item override (§6.7 每条目覆盖): excluded → nothing to snapshot.
        let empty = try SnapshotEngine.build(vaultID: vaultID, snapshotRevision: 1,
                                             rows: rows, secrets: secrets,
                                             exclusions: [SnapshotExclusion(itemID: itemA,
                                                                            excluded: true,
                                                                            atMillis: 10)],
                                             signer: signer)
        // All entries excluded, but the exclusion markers themselves must
        // still ride to the other devices → a manifest with zero entries.
        XCTAssertNotNil(empty)
        XCTAssertEqual(empty?.manifest.entries.isEmpty, true)
        XCTAssertEqual(empty?.manifest.exclusions.first?.itemID, itemA)

        // No record behind the local-only row → skipped.
        let orphan = try SnapshotEngine.build(vaultID: vaultID, snapshotRevision: 1,
                                              rows: [localOnlyRow(itemID: itemB, revision: 1)],
                                              secrets: secrets, signer: signer)
        XCTAssertNil(orphan)
    }

    func testExclusionsRideThroughCodecAndMergeLWW() throws {
        // The exclusion set is a shared artifact: it must survive a
        // build → verify round-trip and merge last-writer-wins per item.
        let local = [SnapshotExclusion(itemID: itemA, excluded: true, atMillis: 100),
                     SnapshotExclusion(itemID: itemB, excluded: false, atMillis: 100)]
        let manifest = SnapshotManifest(vaultID: vaultID, snapshotRevision: 2,
                                        entries: [], exclusions: local)
        let data = try SnapshotCodec.build(manifest, signer: signer)
        let verified = try SnapshotCodec.verify(data, ownerSignPublicKeys: [ownerKey])
        XCTAssertEqual(verified.exclusions, local)

        // Cloud says itemA excluded (t=100), device re-includes later
        // (t=200) → re-include wins. The other device's OLDER re-include of
        // itemB (t=50) loses to the cloud's exclusion... (itemB cloud t=100
        // included beats local t=50 included — same state either way) —
        // exercise the flip that matters: a NEWER exclusion overrides an
        // older include.
        let reinclude = SnapshotExclusion(itemID: itemA, excluded: false, atMillis: 200)
        let newerExclude = SnapshotExclusion(itemID: itemB, excluded: true, atMillis: 300)
        let merged = SnapshotEngine.mergeExclusions(local, [reinclude, newerExclude])
        XCTAssertEqual(merged, [reinclude, newerExclude].sorted { $0.itemID < $1.itemID })

        // An OLDER local decision never overrides a newer cloud one.
        let stale = SnapshotExclusion(itemID: itemA, excluded: false, atMillis: 50)
        let merged2 = SnapshotEngine.mergeExclusions(local, [stale])
        XCTAssertEqual(merged2.first(where: { $0.itemID == itemA })?.excluded, true)
    }

    // MARK: engine restore / merge (revision 大者胜)

    func testRestoreAppliesOnlyStrictlyNewerEntries() throws {
        let state = InMemorySyncStateStore()
        try state.setVaultID(vaultID)
        let secrets = InMemoryLocalSecretStore()
        // Local: itemA at revision 5, itemB at revision 1.
        try state.upsertItem(localOnlyRow(itemID: itemA, revision: 5))
        try secrets.save(record(itemID: itemA, revision: 5))
        try state.upsertItem(localOnlyRow(itemID: itemB, revision: 1))
        try secrets.save(record(itemID: itemB, revision: 1))

        let manifest = SnapshotManifest(vaultID: vaultID, snapshotRevision: 7, entries: [
            // Older than local → must be kept local.
            SnapshotEntry(itemID: itemA, revision: 4, metaCiphertext: Data("old-a".utf8),
                          secretCiphertext: Data("old-a".utf8),
                          vaultWrappedMetaKey: Data("wm".utf8),
                          vaultWrappedItemKey: Data("wi".utf8), writerDeviceID: writer),
            // Strictly newer → applied.
            SnapshotEntry(itemID: itemB, revision: 2, metaCiphertext: Data("new-b".utf8),
                          secretCiphertext: Data("new-b".utf8),
                          vaultWrappedMetaKey: Data("wm".utf8),
                          vaultWrappedItemKey: Data("wi".utf8), writerDeviceID: writer),
        ])
        let data = try SnapshotCodec.build(manifest, signer: signer)
        let outcome = try SnapshotEngine.restore(data: data, vaultID: vaultID,
                                                 rows: [], state: state, secrets: secrets,
                                                 trustedOwnerKeys: [ownerKey])
        XCTAssertEqual(outcome.applied, 1)
        XCTAssertEqual(outcome.keptLocal, 1)
        XCTAssertEqual(outcome.snapshotRevision, 7)
        XCTAssertEqual(try state.item(itemB)?.revision, 2)
        XCTAssertEqual(try secrets.record(itemID: itemB)?.secretCiphertext,
                       Data("new-b".utf8))
        // itemA untouched.
        XCTAssertEqual(try secrets.record(itemID: itemA)?.secretCiphertext,
                       Data("secret-ct-\(itemA)".utf8))
    }

    func testRestoreRefusesBadSignatureBeforeMerging() throws {
        let state = InMemorySyncStateStore()
        try state.setVaultID(vaultID)
        let secrets = InMemoryLocalSecretStore()
        let manifest = SnapshotManifest(vaultID: vaultID, snapshotRevision: 2, entries: [
            SnapshotEntry(itemID: itemA, revision: 9, metaCiphertext: Data("evil".utf8),
                          secretCiphertext: Data("evil".utf8),
                          vaultWrappedMetaKey: Data("wm".utf8),
                          vaultWrappedItemKey: Data("wi".utf8), writerDeviceID: writer),
        ])
        // Signed by someone else → restore throws, nothing lands.
        let impostor = try SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
        let data = try SnapshotCodec.build(manifest, signer: impostor)
        XCTAssertThrowsError(try SnapshotEngine.restore(data: data, vaultID: vaultID,
                                                        rows: [], state: state,
                                                        secrets: secrets,
                                                        trustedOwnerKeys: [ownerKey])) {
            XCTAssertEqual($0 as? SnapshotEngineError, .badSignature)
        }
        XCTAssertNil(try state.item(itemA))
        XCTAssertNil(try secrets.record(itemID: itemA))

        // Right key but another vault → vaultMismatch.
        let wrongVault = SnapshotManifest(vaultID: self.vaultID.replacingOccurrences(
            of: "0", with: "1"), snapshotRevision: 2, entries: [])
        let data2 = try SnapshotCodec.build(wrongVault, signer: signer)
        XCTAssertThrowsError(try SnapshotEngine.restore(data: data2, vaultID: vaultID,
                                                        rows: [], state: state,
                                                        secrets: secrets,
                                                        trustedOwnerKeys: [ownerKey]))
    }

    // MARK: uploadMerged

    func testUploadMergedConvergesTwoWritersAtHigherRevision() async throws {
        let signerB = try SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
        let store = InMemorySnapshotStore()
        let state = InMemorySyncStateStore()
        try state.setVaultID(vaultID)
        let secrets = InMemoryLocalSecretStore()
        try state.upsertItem(localOnlyRow(itemID: itemA, revision: 3))
        try secrets.save(record(itemID: itemA, revision: 3))

        // Phone B already uploaded itemB at snapshot revision 4.
        try await store.upload(vaultID: vaultID, data: try SnapshotCodec.build(
            SnapshotManifest(vaultID: vaultID, snapshotRevision: 4, entries: [
                SnapshotEntry(itemID: itemB, revision: 2, metaCiphertext: Data("b-meta".utf8),
                              secretCiphertext: Data("b-secret".utf8),
                              vaultWrappedMetaKey: Data("wm".utf8),
                              vaultWrappedItemKey: Data("wi".utf8), writerDeviceID: writer),
            ]), signer: signerB))

        // Phone A uploads: merges B's copy (itemB applied), keeps its own
        // itemA, and lands at a strictly higher revision.
        let uploaded = try await SnapshotEngine.uploadMerged(
            vaultID: vaultID, rows: [localOnlyRow(itemID: itemA, revision: 3)],
            state: state, secrets: secrets, signer: signer, store: store,
            trustedOwnerKeys: [ownerKey, signerB.signPublicKey])
        XCTAssertNotNil(uploaded)
        XCTAssertEqual(uploaded?.snapshotRevision, 5)
        XCTAssertEqual(Set(uploaded?.entries.map(\.itemID) ?? []), [itemA, itemB])
        // Recorded so the next upload starts strictly above 5.
        XCTAssertEqual(try secrets.snapshotRevision(), 5)

        // The uploaded file verifies and carries both entries.
        let cloud = try await store.download(vaultID: vaultID)
        let verified = try SnapshotCodec.verify(try XCTUnwrap(cloud),
                                                ownerSignPublicKeys: [ownerKey, signerB.signPublicKey])
        XCTAssertEqual(verified.snapshotRevision, 5)
    }

    // MARK: SQLiteLocalSecretStore

    func testSQLiteLocalSecretStoreRoundTripAndReopen() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("keyref-tests-\(UUID().uuidString)", isDirectory: true)
        let url = dir.appendingPathComponent("secrets.sqlite")
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = try SQLiteLocalSecretStore(fileURL: url)
        try store.save(record(itemID: itemA, revision: 3))
        try store.save(record(itemID: itemB, revision: 9))
        try store.setSnapshotRevision(41)

        XCTAssertEqual(try store.record(itemID: itemA), record(itemID: itemA, revision: 3))
        XCTAssertEqual(try store.allRecords().count, 2)
        XCTAssertEqual(try store.snapshotRevision(), 41)

        // Update overwrites (upsert semantics).
        try store.save(record(itemID: itemA, revision: 4))
        XCTAssertEqual(try store.record(itemID: itemA)?.revision, 4)

        try store.remove(itemID: itemB)
        XCTAssertNil(try store.record(itemID: itemB))

        // Reopen: everything persisted survives the process "restart".
        let reopened = try SQLiteLocalSecretStore(fileURL: url)
        XCTAssertEqual(try reopened.record(itemID: itemA)?.revision, 4)
        XCTAssertNil(try reopened.record(itemID: itemB))
        XCTAssertEqual(try reopened.snapshotRevision(), 41)
        try reopened.removeAll()
        XCTAssertEqual(try reopened.allRecords().count, 0)
    }
}
