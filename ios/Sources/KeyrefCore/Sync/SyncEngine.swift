// Sync engine (docs/protocol.md §8, design §10.6): pulls changes from the
// server, verifies signatures before applying anything, applies items,
// grants, devices and the signed directory to local state, and
// reconciles the grant set against GET /v1/grants/self and the directory
// digest. Verification follows the v2 F owner key chain — the pinned
// owner key plus the active iOS signing keys of the saved directory — and
// a failure abandons the batch and keeps old data.
import Foundation

public enum SyncError: Error, Equatable {
    /// The directory or a device change marks this device revoked; local
    /// cleanup has been performed (design §8.2, §8.4).
    case revoked
    /// Signature or grants-digest mismatch; local state untouched.
    case tampered(String)
    /// Not paired: no pinned owner key or vault id in the store.
    case notPaired
}

/// Local state the engine mutates. The production implementation persists
/// to the app's local store; tests use the in-memory implementation.
public protocol SyncStateStore: AnyObject, Sendable {
    func cursor() throws -> Int64
    func setCursor(_ v: Int64) throws

    func upsertItem(_ item: ItemData) throws
    func item(_ itemID: String) throws -> ItemData?
    /// Deletes the row and cascades its grants (design §6.5).
    func deleteItem(_ itemID: String) throws

    func upsertGrant(_ grant: GrantData) throws
    func grants() throws -> [GrantData]
    /// Keyed by (device, item, kind): an owner device keeps OTHER devices'
    /// grant rows too (§8.4 renewal, grant lists) — several devices can hold
    /// a grant on the same item without colliding.
    func deleteGrant(deviceID: String, itemID: String, kind: String) throws

    func storeDirectory(_ directory: DirectoryData) throws
    func directory() throws -> DirectoryData?

    func setVaultID(_ vaultID: String) throws
    func vaultID() throws -> String?

    func setPinnedOwnerKey(_ key: Data) throws
    func pinnedOwnerKey() throws -> Data?

    func setOwnDeviceID(_ deviceID: String) throws
    func ownDeviceID() throws -> String?

    func clearSessionCaches() throws
}

public struct SyncOutcome: Equatable, Sendable {
    public var applied = 0
    public var deleted = 0
    public var revokedSelf = false

    public init() {}
}

public final class SyncEngine: Sendable {
    public let api: APIClient

    public init(api: APIClient) {
        self.api = api
    }

    /// Pulls pages until the cursor is current, then reconciles grants.
    /// A `cursor_stale` response resets to 0 (bootstrap) once and retries
    /// (§8.1: clients re-bootstrap when the cursor fell out of the 90-day
    /// log window). Returns SyncError.revoked after performing local
    /// cleanup when the directory or a device change revokes this device.
    public func run(store: SyncStateStore) async throws -> SyncOutcome {
        _ = try vaultIDOf(store)
        _ = try ownerKeyOf(store)

        var outcome = SyncOutcome()
        var cursor = try store.cursor()
        var staleRetried = false
        while true {
            let response: SyncResponse
            do {
                response = try await api.sync(cursor: cursor)
            } catch let e as APIError {
                guard case .cursorStale = e, !staleRetried else { throw e }
                staleRetried = true
                cursor = 0
                continue
            }
            let applied = try apply(response: response, store: store)
            outcome.applied += applied.applied
            outcome.deleted += applied.deleted
            if applied.revokedSelf {
                outcome.revokedSelf = true
                return outcome
            }
            cursor = response.cursor
            try store.setCursor(cursor)
            if !response.hasMore { break }
        }

        try await reconcileGrants(store: store)
        return outcome
    }

    // MARK: apply one page

    /// Applies a sync page. Public so tests can feed responses directly.
    @discardableResult
    public func apply(response: SyncResponse, store: SyncStateStore) throws -> SyncOutcome {
        var outcome = SyncOutcome()
        for change in response.changes {
            let payload = try change.decodedData()
            guard let payload else { continue }  // unknown entities: recorded, not applied
            switch payload {
            case .item(let row):
                switch try applyItem(row, store: store) {
                case .applied: outcome.applied += 1
                case .deleted: outcome.deleted += 1
                case .skipped: break
                }
            case .grant(let row):
                switch try applyGrant(row, store: store) {
                case .applied: outcome.applied += 1
                case .deleted: outcome.deleted += 1
                case .skipped: break
                }
            case .device(let row):
                if try applyDevice(row, store: store) { outcome.revokedSelf = true }
            case .directory(let row):
                if try applyDirectory(row, store: store) { outcome.revokedSelf = true }
            case .approval:
                break  // status summaries only; bodies ride the approval endpoints
            }
            if outcome.revokedSelf { return outcome }
        }
        return outcome
    }

    private enum ChangeResult { case applied, deleted, skipped }

    /// Applies an item change. Every row — live or tombstone — must carry
    /// a writer signature that verifies under the active owner device
    /// named by writer_device_id (v2 E/F); tombstones cascade (design
    /// §6.3, §6.5); stale revisions are skipped, not applied (§6.2).
    private func applyItem(_ row: ItemData, store: SyncStateStore) throws -> ChangeResult {
        let vaultID = try vaultIDOf(store)
        if row.tombstone {
            // The v2 E tombstone transcript signs the flag byte and the
            // four empty-field digests (ItemCrypto.signTombstone). A
            // tombstone for an item we do not hold is ignored outright:
            // tombstones signed by a previous owner key (before a recovery
            // takeover) still arrive on bootstrap and must not abort the
            // sync when there is nothing to delete (v2 F).
            if try store.item(row.itemID) == nil {
                return .skipped
            }
            do {
                try verifyItem(row, vaultID: vaultID, store: store)
            } catch {
                throw SyncError.tampered("item \(row.itemID) tombstone signature")
            }
            try store.deleteItem(row.itemID)  // drops grants and cached wraps
            return .deleted
        }
        if let old = try store.item(row.itemID), old.revision >= row.revision {
            // Reject revisions smaller than what has already been seen
            // (design §6.2); equal-and-different conflicts are surfaced by
            // the UI, not silently overwritten.
            return .skipped
        }
        // The stored pins and directory are the trust anchor, not the
        // cursor (design §10.6): verify before applying. Pruned rows are
        // covered by their per-field digests (v2 E).
        do {
            try verifyItem(row, vaultID: vaultID, store: store)
        } catch {
            throw SyncError.tampered("item \(row.itemID) signature")
        }
        try store.upsertItem(row)
        return .applied
    }

    /// Applies a grant change; deletions clear the local row and wrap.
    /// Rows for OTHER devices are verified and kept too: the owner device
    /// needs them for §8.4 renewal and the grant lists (the server's sync
    /// feed only carries all-vault grants to owner devices — CLI feeds are
    /// filtered to the device's own rows server-side, sync.go isOwner).
    /// Every row, including the deletion form, must verify under an active
    /// owner key (v2 F); a failure fails the whole batch.
    private func applyGrant(_ row: GrantData, store: SyncStateStore) throws -> ChangeResult {
        let vaultID = try vaultIDOf(store)
        do {
            try verifyGrant(row, vaultID: vaultID, store: store)
        } catch {
            throw SyncError.tampered("grant \(row.itemID)/\(row.kind) signature")
        }
        if row.deleted || (row.hpkeEnc.isEmpty && row.wrappedKey.isEmpty) {
            // Grant revoked (pointing at ourselves) or item tombstone
            // cascade: clear the local row and wrap (design §6.3, §6.5).
            try store.deleteGrant(deviceID: row.deviceID, itemID: row.itemID, kind: row.kind)
            return .deleted
        }
        try store.upsertGrant(row)
        return .applied
    }

    /// Applies a device change; returns true when it revoked this device.
    private func applyDevice(_ row: DeviceData, store: SyncStateStore) throws -> Bool {
        guard let own = try store.ownDeviceID(),
              row.deviceID == own, row.status == DeviceStatus.revoked else {
            return false
        }
        try cleanupRevoked(store)
        return true
    }

    /// Applies a directory change and checks our own row; returns true
    /// when this device was revoked (§8.4 delivery semantics ride on the
    /// directory even for devices that no longer receive anything else).
    private func applyDirectory(_ row: DirectoryData, store: SyncStateStore) throws -> Bool {
        let vaultID = try vaultIDOf(store)
        do {
            try verifyDirectory(row, store: store)
        } catch {
            throw SyncError.tampered("directory signature")
        }
        // A validly signed but older (or equal) directory must not replace
        // a newer one: skip it, like stale item revisions.
        if let stored = try store.directory(), stored.directoryRevision >= row.directoryRevision {
            return false
        }
        try store.storeDirectory(row)
        if let own = try store.ownDeviceID(),
           row.deviceStatus(of: own, vaultID: vaultID) == DeviceStatus.revoked {
            try cleanupRevoked(store)
            return true
        }
        return false
    }

    /// Drops session caches, grants and wrapped keys after discovering
    /// revocation (design §8.2).
    private func cleanupRevoked(_ store: SyncStateStore) throws {
        try store.clearSessionCaches()
        for g in try store.grants() {
            try store.deleteGrant(deviceID: g.deviceID, itemID: g.itemID, kind: g.kind)
        }
    }

    // MARK: grants reconciliation (§9.1, §10.6)

    /// Cross-checks the local grant set against GET /v1/grants/self and
    /// the server digest: a suppressed or forged grant set disables use
    /// (fail closed). Tolerated offline (transport failure → skip).
    public func reconcileGrants(store: SyncStateStore) async throws {
        let vaultID = try vaultIDOf(store)
        _ = try ownerKeyOf(store)
        guard let own = try store.ownDeviceID() else { throw SyncError.notPaired }

        let selfResp: GrantsSelfResponse
        do {
            selfResp = try await api.grantsSelf()
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return  // offline-tolerated
        }

        for row in selfResp.grants {
            do {
                try verifyGrant(row, vaultID: vaultID, store: store)
            } catch {
                throw SyncError.tampered("grants/self row \(row.itemID)/\(row.kind)")
            }
            try store.upsertGrant(row)
        }

        // Recompute the digest over the returned grants and compare with
        // what the server claims, and with the local set.
        let serverDigest = try grantsDigest(selfResp.grants.map { $0.transcript(vaultID: vaultID) })
        if !selfResp.grantsDigest.isEmpty, selfResp.grantsDigest != serverDigest {
            throw SyncError.tampered("grants/self digest mismatch")
        }
        let local = try store.grants().filter { $0.deviceID == own }
        let localDigest = try grantsDigest(local.map { $0.transcript(vaultID: vaultID) })
        if !selfResp.grantsDigest.isEmpty, selfResp.grantsDigest != localDigest {
            // The server's own set is authoritative; refresh the local rows.
            for g in local where !selfResp.grants.contains(where: {
                $0.itemID == g.itemID && $0.kind == g.kind
            }) {
                try store.deleteGrant(deviceID: g.deviceID, itemID: g.itemID, kind: g.kind)
            }
        }
    }

    // MARK: owner key chain (v2 F)

    /// One signing identity the engine accepts for owner-authored rows:
    /// an active iOS device listed in the saved directory.
    private struct ChainKey {
        var deviceID: String
        var signAlg: String
        var publicKey: Data
    }

    /// Whether a directory is saved locally. Before the first one the
    /// pinned key is the only anchor; once one exists a vault with no
    /// active iOS device is dead and everything fails closed (v2 F).
    private func savedDirectoryPresent(_ store: SyncStateStore) throws -> Bool {
        try store.directory() != nil
    }

    /// Active owner signing keys from the saved directory. Empty before a
    /// directory is stored — the pinned key is then the only anchor.
    private func activeOwnerKeys(_ store: SyncStateStore) throws -> [ChainKey] {
        guard let dir = try store.directory(),
              let vaultID = try store.vaultID(),
              KeyrefEncoding.isValidID(vaultID) else {
            return []
        }
        guard let devices = try? VaultFlows.parseVerifiedDevices(dir.signed, vaultID: vaultID) else {
            return []
        }
        return devices
            .filter { $0.kind == DeviceKind.ios && $0.status == DeviceStatus.active }
            .map { ChainKey(deviceID: $0.deviceID, signAlg: $0.signAlg, publicKey: $0.signPublicKey) }
    }

    /// Item rows verify under the active owner device named by
    /// writer_device_id (v2 F); with no saved directory the pinned key is
    /// the only owner identity known.
    private func verifyItem(_ row: ItemData, vaultID: String, store: SyncStateStore) throws {
        let keys = try activeOwnerKeys(store)
        if !(try savedDirectoryPresent(store)) {
            let pinned = try ownerKeyOf(store)
            try ItemCrypto.verifyItemSignature(row, vaultID: vaultID,
                                               signAlg: SignAlg.ecdsaP256, signPublicKey: pinned)
            return
        }
        guard !keys.isEmpty else {
            throw SyncError.tampered("item \(row.itemID): the saved directory lists no active owner device")
        }
        guard let key = keys.first(where: { $0.deviceID == row.writerDeviceID }) else {
            throw SyncError.tampered("item \(row.itemID): writer \(row.writerDeviceID) is not an active owner device")
        }
        try ItemCrypto.verifyItemSignature(row, vaultID: vaultID,
                                           signAlg: key.signAlg, signPublicKey: key.publicKey)
    }

    /// Grant rows carry no writer id and verify under some active owner
    /// key (v2 F).
    private func verifyGrant(_ row: GrantData, vaultID: String, store: SyncStateStore) throws {
        let keys = try activeOwnerKeys(store)
        if !(try savedDirectoryPresent(store)) {
            let pinned = try ownerKeyOf(store)
            try ItemCrypto.verifyGrantSignature(row, vaultID: vaultID, ownerSignPublicKey: pinned)
            return
        }
        guard !keys.isEmpty else {
            throw SyncError.tampered("grant \(row.itemID)/\(row.kind): the saved directory lists no active owner device")
        }
        var lastError: Error = SyncError.tampered("grant \(row.itemID)/\(row.kind) signature")
        for key in keys {
            do {
                let t = try grantTranscript(row, vaultID: vaultID)
                try verifyDeviceSignature(transcript: try t.buildBytes(),
                                          signature: row.signature,
                                          signAlg: key.signAlg, publicKey: key.publicKey)
                return
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    /// A new directory is accepted iff signed by an active iOS device of
    /// the saved directory; before any saved directory the pinned key is
    /// the only anchor (v2 F).
    private func verifyDirectory(_ row: DirectoryData, store: SyncStateStore) throws {
        let keys = try activeOwnerKeys(store)
        if !(try savedDirectoryPresent(store)) {
            let pinned = try ownerKeyOf(store)
            try verifyOwnerSignature(transcript: row.signed, signature: row.signature,
                                     ownerSignPublicKey: pinned)
            return
        }
        guard !keys.isEmpty else {
            throw SyncError.tampered("directory: the saved directory lists no active owner device")
        }
        for key in keys {
            if (try? verifyDeviceSignature(transcript: row.signed, signature: row.signature,
                                           signAlg: key.signAlg, publicKey: key.publicKey)) != nil {
                return
            }
        }
        throw SyncError.tampered("directory signature")
    }

    private func grantTranscript(_ row: GrantData, vaultID: String) throws -> GrantTranscript {
        GrantTranscript(vaultID: vaultID, deviceID: row.deviceID, itemID: row.itemID,
                        kind: row.kind, revision: row.revision,
                        expiresAt: UInt64(bitPattern: row.expiresAt),
                        hpkeEnc: row.hpkeEnc, wrappedKey: row.wrappedKey)
    }

    // MARK: helpers

    private func vaultIDOf(_ store: SyncStateStore) throws -> String {
        guard let vaultID = try store.vaultID(), KeyrefEncoding.isValidID(vaultID) else {
            throw SyncError.notPaired
        }
        return vaultID
    }

    private func ownerKeyOf(_ store: SyncStateStore) throws -> Data {
        guard let key = try store.pinnedOwnerKey(), !key.isEmpty else {
            throw SyncError.notPaired
        }
        return key
    }
}

// MARK: - directory revocation lookup
//
// Transcripts are write-only (protocol §1.5/D3): verification rebuilds
// bytes rather than parsing. The one place the engine must look *into* an
// already signature-verified directory transcript is to find its own
// device's status for revocation delivery (§8.4). Because device ids are
// unique 32-char lowercase hex, the scan below locates the record for one
// known device id and reads its status; any other use is forbidden.

/// Reads the status recorded for `deviceID` inside a directory transcript
/// (`row.device_status(of:in:)`'s data). Returns nil when the device does
/// not appear; statuses are only ever pending/active/revoked (§3.3).
extension DirectoryData {
    public func deviceStatus(of deviceID: String, vaultID: String) -> String? {
        guard KeyrefEncoding.isValidID(deviceID), KeyrefEncoding.isValidID(vaultID),
              signed.starts(with: Data("KEYREF1".utf8)) else {
            return nil
        }
        let needle = Data(deviceID.utf8) + Data([KeyrefEncoding.fieldSeparator])
        var searchRange = signed.startIndex..<signed.endIndex
        while let found = signed.range(of: needle, options: [], in: searchRange) {
            var i = found.upperBound
            // kind: "ios" or "cli", then NUL
            let kindEnd = signed[i...].firstIndex(of: KeyrefEncoding.fieldSeparator) ?? signed.endIndex
            let kind = String(decoding: signed[i..<kindEnd], as: UTF8.self)
            guard kind == DeviceKind.ios || kind == DeviceKind.cli else {
                searchRange = found.upperBound..<signed.endIndex
                continue
            }
            i = signed.index(after: kindEnd)
            // status: pending | active | revoked, NUL-terminated
            let statusEnd = signed[i...].firstIndex(of: KeyrefEncoding.fieldSeparator) ?? signed.endIndex
            let status = String(decoding: signed[i..<statusEnd], as: UTF8.self)
            if status == DeviceStatus.pending || status == DeviceStatus.active || status == DeviceStatus.revoked {
                return status
            }
            searchRange = found.upperBound..<signed.endIndex
        }
        return nil
    }
}
