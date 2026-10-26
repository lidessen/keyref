// NEW FILE (v0.7, design §6.7): the storage seam behind the iCloud
// whole-file copy. One CloudKit container, one fixed record per vault, one
// CKAsset holding the entire snapshot file — no per-item schema, Apple sees
// only an opaque file's name/size/time (§6.7). Everything CloudKit goes
// through this protocol so the simulator (no iCloud account) and tests run
// on the in-memory / file implementations.
import CloudKit
import Foundation

public enum SnapshotStoreError: Error, Equatable {
    case unavailable(String)   // iCloud 未登录 / 账号受限 / CloudKit 错误（§6.7 降级）
    case invalidData
}

/// Storage for the whole-file snapshot of one vault. Implementations must
/// treat `vaultID` as the addressing key and replace the previous blob on
/// upload (single fixed record, §6.7).
public protocol SnapshotStore: AnyObject, Sendable {
    /// Uploads (replaces) the snapshot file for the vault.
    func upload(vaultID: String, data: Data) async throws
    /// Returns the stored snapshot file, or nil when none exists yet.
    func download(vaultID: String) async throws -> Data?
    /// Probes whether the store can currently be used (iCloud account).
    /// `available == false` carries the reason shown as「副本不可用」.
    func checkAvailability() async -> SnapshotAvailability
}

public struct SnapshotAvailability: Equatable, Sendable {
    public var available: Bool
    public var reason: String?

    public init(available: Bool, reason: String? = nil) {
        self.available = available
        self.reason = reason
    }

    public static let available = SnapshotAvailability(available: true)
}

/// In-memory implementation: tests, previews and the simulator flows.
public final class InMemorySnapshotStore: SnapshotStore, @unchecked Sendable {
    private let lock = NSLock()
    private var blobs: [String: Data] = [:]
    public var failUpload: Bool = false
    public var availabilityResult = SnapshotAvailability.available

    public init() {}

    public func upload(vaultID: String, data: Data) async throws {
        if failUpload { throw SnapshotStoreError.unavailable("upload failed") }
        lock.withLock { blobs[vaultID] = data }
    }

    public func download(vaultID: String) async throws -> Data? {
        lock.withLock { blobs[vaultID] }
    }

    public func checkAvailability() async -> SnapshotAvailability {
        availabilityResult
    }
}

/// File-backed implementation: local whole-file copies (tests, and the
/// manual "copy exists on disk" double). One file per vault under a fixed
/// directory.
public final class FileSnapshotStore: SnapshotStore, @unchecked Sendable {
    private let directory: URL
    private let lock = NSLock()

    public init(directory: URL) {
        self.directory = directory
        try? FileManager.default.createDirectory(at: directory,
                                                 withIntermediateDirectories: true)
    }

    private func url(for vaultID: String) -> URL {
        directory.appendingPathComponent("snapshot-\(vaultID).bin")
    }

    public func upload(vaultID: String, data: Data) async throws {
        try FileManager.default.createDirectory(at: directory,
                                                withIntermediateDirectories: true)
        try data.write(to: url(for: vaultID), options: .atomic)
    }

    public func download(vaultID: String) async throws -> Data? {
        let u = url(for: vaultID)
        guard FileManager.default.fileExists(atPath: u.path) else { return nil }
        return try Data(contentsOf: u)
    }

    public func checkAvailability() async -> SnapshotAvailability {
        SnapshotAvailability.available
    }
}

/// CloudKit implementation (production). Container id is fixed
/// (`iCloud.app.keyref.ios`), record type `vaultSnapshot`, record name
/// `vault-<vault_id>` in the user's private database; the snapshot file
/// rides as a single CKAsset (§6.7). Never blocks local features: every
/// failure surfaces as a thrown error or an unavailable probe and the
/// caller degrades to「副本不可用」.
public final class CloudKitSnapshotStore: SnapshotStore, @unchecked Sendable {
    public static let defaultContainerID = "iCloud.app.keyref.ios"
    public static let recordType = "vaultSnapshot"

    private let containerID: String
    private let field = "snapshot"

    public init(containerID: String = CloudKitSnapshotStore.defaultContainerID) {
        self.containerID = containerID
    }

    private var container: CKContainer { CKContainer(identifier: containerID) }
    private var database: CKDatabase { container.privateCloudDatabase }
    private func recordID(_ vaultID: String) -> CKRecord.ID {
        CKRecord.ID(recordName: "vault-\(vaultID)")
    }

    public func checkAvailability() async -> SnapshotAvailability {
        do {
            let status = try await container.accountStatus()
            switch status {
            case .available: return SnapshotAvailability.available
            case .noAccount: return SnapshotAvailability(available: false, reason: "未登录 iCloud")
            case .restricted: return SnapshotAvailability(available: false, reason: "iCloud 账户受限")
            case .couldNotDetermine: return SnapshotAvailability(available: false, reason: "iCloud 状态未知")
            case .temporarilyUnavailable: return SnapshotAvailability(available: false, reason: "iCloud 暂不可用")
            @unknown default: return SnapshotAvailability(available: false, reason: "iCloud 状态未知")
            }
        } catch {
            return SnapshotAvailability(available: false, reason: "iCloud 不可用")
        }
    }

    public func upload(vaultID: String, data: Data) async throws {
        guard !data.isEmpty else { throw SnapshotStoreError.invalidData }
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("keyref-snapshot-\(UUID().uuidString).bin")
        try data.write(to: tmp, options: .atomic)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let record: CKRecord
        do {
            record = try await database.record(for: recordID(vaultID))
        } catch let e as CKError where e.code == .unknownItem {
            record = CKRecord(recordType: Self.recordType, recordID: recordID(vaultID))
        } catch let e as CKError where e.code == .notAuthenticated {
            throw SnapshotStoreError.unavailable("未登录 iCloud")
        }
        record[field] = CKAsset(fileURL: tmp)
        do {
            _ = try await database.save(record)
        } catch let e as CKError where e.code == .notAuthenticated {
            throw SnapshotStoreError.unavailable("未登录 iCloud")
        }
    }

    public func download(vaultID: String) async throws -> Data? {
        let record: CKRecord
        do {
            record = try await database.record(for: recordID(vaultID))
        } catch let e as CKError where e.code == .unknownItem {
            return nil
        } catch let e as CKError where e.code == .notAuthenticated {
            throw SnapshotStoreError.unavailable("未登录 iCloud")
        }
        guard let asset = record[field] as? CKAsset, let fileURL = asset.fileURL else {
            return nil
        }
        return try Data(contentsOf: fileURL)
    }
}
