// NEW FILE (v0.7, design §6.7): the flows over the snapshot format —
// building the whole-file copy from local state (仅本机 rows + local secret
// records), uploading it owner-signed with the monotonic snapshot_revision,
// and merging a downloaded, signature-verified copy back with the
// 「revision 大者胜」 rule (§6.7: 与服务器同步同一套冲突规则).
//
// The engine never touches plaintext: entries are the existing ciphertext
// bytes, and the signature is produced with the owner transcript signer.
import Foundation

public struct SnapshotBuildResult: Sendable {
    public var data: Data
    public var manifest: SnapshotManifest
}

public struct SnapshotMergeOutcome: Equatable, Sendable {
    /// Entries applied from the snapshot (newer than local state).
    public var applied = 0
    /// Entries skipped because the local row/record was equal or newer.
    public var keptLocal = 0
    public var snapshotRevision: UInt64 = 0

    public init() {}
}

public enum SnapshotEngineError: Error, Equatable {
    case badSignature
    case vaultMismatch
    case notFound
}

public enum SnapshotEngine {

    /// LWW merge of the per-item snapshot override (§6.7 每条目覆盖). The
    /// exclusion set rides INSIDE the shared snapshot file, so both devices
    /// converge: a later decision (by timestamp) wins per item — one device
    /// excluding an entry cannot be silently flipped by the other's upload,
    /// and a re-include propagates the same way.
    public static func mergeExclusions(_ a: [SnapshotExclusion],
                                       _ b: [SnapshotExclusion]) -> [SnapshotExclusion] {
        var byID: [String: SnapshotExclusion] = [:]
        for e in a + b {
            if let old = byID[e.itemID], old.atMillis >= e.atMillis { continue }
            byID[e.itemID] = e
        }
        return byID.values.sorted { $0.itemID < $1.itemID }
    }

    // MARK: build

    /// Builds the snapshot file from local state: every live row without a
    /// server-side secret (仅本机 rows, `StorageClass.of(_:)`) whose secret
    /// ciphertext + vault_wrapped_item_key exist in the local secret store,
    /// minus the merged per-item overrides (§6.7 全局开关 + 每条目覆盖，
    /// 默认开). Returns nil when there is neither an entry nor an override
    /// to write (an all-excluded vault still uploads — the exclusion markers
    /// must propagate to the other devices).
    public static func build(vaultID: String, snapshotRevision: UInt64,
                             rows: [ItemData], secrets: LocalSecretStore,
                             exclusions: [SnapshotExclusion] = [],
                             signer: TranscriptSigner) throws -> SnapshotBuildResult? {
        let excluded = Set(exclusions.filter(\.excluded).map(\.itemID))
        var entries: [SnapshotEntry] = []
        for row in rows where StorageClass.of(row) == .localOnly {
            guard !excluded.contains(row.itemID) else { continue }
            guard let record = try secrets.record(itemID: row.itemID) else { continue }
            guard !record.secretCiphertext.isEmpty,
                  !record.vaultWrappedItemKey.isEmpty else { continue }
            entries.append(SnapshotEntry(
                itemID: row.itemID,
                revision: max(row.revision, record.revision),
                metaCiphertext: row.metaCiphertext,
                secretCiphertext: record.secretCiphertext,
                vaultWrappedMetaKey: row.vaultWrappedMetaKey,
                vaultWrappedItemKey: record.vaultWrappedItemKey,
                writerDeviceID: row.writerDeviceID))
        }
        guard !entries.isEmpty || !exclusions.isEmpty else { return nil }
        let manifest = SnapshotManifest(vaultID: vaultID,
                                        snapshotRevision: max(snapshotRevision, 1),
                                        entries: entries, exclusions: exclusions)
        return SnapshotBuildResult(data: try SnapshotCodec.build(manifest, signer: signer),
                                   manifest: manifest)
    }

    // MARK: upload (debounce + conflict handling live with the caller)

    /// Upload flow used by the app: merges any cloud copy first (「revision
    /// 大者胜」 both ways — two phones that both wrote a version converge on
    /// the union), builds the merged snapshot at a strictly higher
    /// snapshot_revision, uploads it and records the new revision.
    /// `rows` is the caller's current row set (a SyncStateStore has no
    /// enumeration; the UI store does). Returns the manifest actually
    /// uploaded, or nil when there is nothing to upload (no 仅本机 entries).
    public static func uploadMerged(vaultID: String, rows: [ItemData],
                                    state: SyncStateStore, secrets: LocalSecretStore,
                                    exclusions: [SnapshotExclusion] = [],
                                    signer: TranscriptSigner, store: SnapshotStore,
                                    trustedOwnerKeys: [Data]) async throws -> SnapshotManifest? {
        var byID: [String: ItemData] = [:]
        for row in rows { byID[row.itemID] = row }
        var cloudRevision: UInt64 = 0
        var cloudExclusions: [SnapshotExclusion] = []
        if let cloudData = try await store.download(vaultID: vaultID) {
            if let cloudManifest = try? SnapshotCodec.verify(cloudData, ownerSignPublicKeys: trustedOwnerKeys),
               cloudManifest.vaultID == vaultID {
                let (outcome, appliedRows) = try merge(manifest: cloudManifest, vaultID: vaultID,
                                                       state: state, secrets: secrets)
                for row in appliedRows { byID[row.itemID] = row }
                cloudRevision = outcome.snapshotRevision
                cloudExclusions = cloudManifest.exclusions
            }
        }
        // 排除集随快照分发：云端已有决策与本机决策按 LWW 合并后再上传。
        let mergedExclusions = mergeExclusions(cloudExclusions, exclusions)
        let localRevision = (try? secrets.snapshotRevision()) ?? 0
        guard let result = try build(vaultID: vaultID,
                                     snapshotRevision: max(localRevision, cloudRevision) + 1,
                                     rows: Array(byID.values), secrets: secrets,
                                     exclusions: mergedExclusions,
                                     signer: signer) else {
            return nil
        }
        try await store.upload(vaultID: vaultID, data: result.data)
        try secrets.setSnapshotRevision(result.manifest.snapshotRevision)
        return result.manifest
    }

    // MARK: merge / restore

    /// Verifies and merges a downloaded snapshot into local state. Rows are
    /// upserted per-item by revision: the snapshot entry wins only when
    /// strictly newer than the local row AND record (equal-or-older keeps
    /// local; equal-and-different surfaces through normal sync instead of
    /// being overwritten silently). The secret bytes land in the local
    /// secret store; the row keeps the server shape (meta + wrapped meta
    /// key only). The returned outcome's `snapshotRevision` is the manifest's
    /// — the caller persists it via `LocalSecretStore.setSnapshotRevision`
    /// so the next upload starts strictly above it (§6.7 单调).
    @discardableResult
    public static func restore(data: Data, vaultID: String, rows: [ItemData],
                               state: SyncStateStore, secrets: LocalSecretStore,
                               trustedOwnerKeys: [Data]) throws -> SnapshotMergeOutcome {
        let manifest: SnapshotManifest
        do {
            manifest = try SnapshotCodec.verify(data, ownerSignPublicKeys: trustedOwnerKeys)
        } catch {
            throw SnapshotEngineError.badSignature
        }
        guard manifest.vaultID == vaultID else { throw SnapshotEngineError.vaultMismatch }
        let (outcome, _) = try merge(manifest: manifest, vaultID: vaultID,
                                     state: state, secrets: secrets)
        return outcome
    }

    /// Merge core: applies the manifest's strictly-newer entries into the
    /// state store (server-shape rows) and the local secret store. Returns
    /// the applied rows so callers holding a row set can refresh it.
    static func merge(manifest: SnapshotManifest, vaultID: String,
                      state: SyncStateStore, secrets: LocalSecretStore) throws
        -> (outcome: SnapshotMergeOutcome, appliedRows: [ItemData]) {
        var outcome = SnapshotMergeOutcome()
        outcome.snapshotRevision = manifest.snapshotRevision
        var appliedRows: [ItemData] = []
        for entry in manifest.entries {
            let old = try state.item(entry.itemID)
            let oldRecord = try secrets.record(itemID: entry.itemID)
            let oldRevision = max(old?.revision ?? 0, oldRecord?.revision ?? 0)
            guard entry.revision > oldRevision else {
                outcome.keptLocal += 1
                continue
            }
            // Row: server shape — meta material only; the secret bytes live
            // in the local secret store (§6.6, §8.3 sync rows for 仅本机).
            let row = ItemData.make(
                vaultID: vaultID, itemID: entry.itemID, revision: entry.revision,
                tombstone: false, metaCiphertext: entry.metaCiphertext,
                secretCiphertext: Data(),
                vaultWrappedMetaKey: entry.vaultWrappedMetaKey,
                vaultWrappedItemKey: Data(),
                writerDeviceID: entry.writerDeviceID,
                signature: Data(), updatedAt: 0)
            try secrets.save(LocalSecretRecord(
                itemID: entry.itemID,
                secretCiphertext: entry.secretCiphertext,
                vaultWrappedItemKey: entry.vaultWrappedItemKey,
                revision: entry.revision, updatedAt: 0))
            try state.upsertItem(row)
            appliedRows.append(row)
            outcome.applied += 1
        }
        return (outcome, appliedRows)
    }
}
