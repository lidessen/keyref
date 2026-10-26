// NEW FILE (v0.7, design §6.6 存储类别): the app's own local store for the
// secret ciphertext of 仅本机 items. The bytes are already end-to-end
// ciphertext — AES-256-GCM under the item key, whose vault wrap lives with
// the row — so after lock the store holds inert bytes only (design §6.5:
// plaintext never hits disk; here not even the plaintext's container).
//
// The store also carries two local-only bookkeeping values: each record's
// local revision (advances on local rotation, §8.4) and the monotonic
// snapshot_revision of the iCloud whole-file copy (§6.7).
import Foundation
import SQLite3

/// One local-only item's stored bytes. Everything here is ciphertext that
/// only the VMK (Keychain-wrapped, Face ID gated) can turn back into keys.
public struct LocalSecretRecord: Equatable, Sendable {
    public var itemID: String
    public var secretCiphertext: Data
    public var vaultWrappedItemKey: Data
    /// Local revision of the secret (bumped by local-only rotation, §8.4);
    /// independent of the server row's meta revision.
    public var revision: UInt64
    public var updatedAt: Int64

    public init(itemID: String, secretCiphertext: Data, vaultWrappedItemKey: Data,
                revision: UInt64, updatedAt: Int64) {
        self.itemID = itemID
        self.secretCiphertext = secretCiphertext
        self.vaultWrappedItemKey = vaultWrappedItemKey
        self.revision = revision
        self.updatedAt = updatedAt
    }
}

public enum LocalSecretStoreError: Error, Equatable {
    case sqlite(String)
    case invalidRecord
}

/// Storage seam for 仅本机 secret ciphertext. Production uses the SQLite
/// implementation below; tests use the in-memory store.
public protocol LocalSecretStore: AnyObject, Sendable {
    func save(_ record: LocalSecretRecord) throws
    func record(itemID: String) throws -> LocalSecretRecord?
    func allRecords() throws -> [LocalSecretRecord]
    func remove(itemID: String) throws
    func removeAll() throws

    /// Monotonic §6.7 snapshot_revision of the last uploaded snapshot.
    func snapshotRevision() throws -> UInt64
    func setSnapshotRevision(_ revision: UInt64) throws
}

/// In-memory implementation (tests, previews, and the fallback when the
/// sqlite file cannot be opened — the app still works, 副本与本地条目在
/// 本次运行内有效).
public final class InMemoryLocalSecretStore: LocalSecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var records: [String: LocalSecretRecord] = [:]
    private var snapshotRevisionValue: UInt64 = 0

    public init() {}

    public func save(_ record: LocalSecretRecord) throws {
        lock.lock(); defer { lock.unlock() }
        records[record.itemID] = record
    }

    public func record(itemID: String) throws -> LocalSecretRecord? {
        lock.lock(); defer { lock.unlock() }
        return records[itemID]
    }

    public func allRecords() throws -> [LocalSecretRecord] {
        lock.lock(); defer { lock.unlock() }
        return Array(records.values).sorted { $0.itemID < $1.itemID }
    }

    public func remove(itemID: String) throws {
        lock.lock(); defer { lock.unlock() }
        records.removeValue(forKey: itemID)
    }

    public func removeAll() throws {
        lock.lock(); defer { lock.unlock() }
        records.removeAll()
    }

    public func snapshotRevision() throws -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        return snapshotRevisionValue
    }

    public func setSnapshotRevision(_ revision: UInt64) throws {
        lock.lock(); defer { lock.unlock() }
        snapshotRevisionValue = revision
    }
}

/// SQLite-backed store (design §6.6 建议的 App 自有表). Two tables:
/// `item_secret(item_id PRIMARY KEY, secret_ciphertext, vault_wrapped_item_key,
/// revision, updated_at)` and `snapshot_meta(key PRIMARY KEY, value)` for the
/// monotonic snapshot revision. The file gets the strongest file protection
/// available so the bytes are unreadable before first unlock, and they stay
/// inert ciphertext regardless — decryption requires the VMK.
public final class SQLiteLocalSecretStore: LocalSecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var db: OpaquePointer?
    private let fileURL: URL

    public enum Keys {
        public static let snapshotRevision = "snapshot_revision"
    }

    /// Opens (creating if needed) the database at `fileURL`.
    public init(fileURL: URL) throws {
        self.fileURL = fileURL
        let dir = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(fileURL.path, &handle, flags, nil)
        guard rc == SQLITE_OK, let handle else {
            sqlite3_close(handle)
            throw LocalSecretStoreError.sqlite("open failed rc=\(rc)")
        }
        db = handle
        #if os(iOS) && !targetEnvironment(simulator) || os(iOS)
        // Data protection: the file is unreadable while the device is locked
        // (the bytes are inert ciphertext anyway — this is defense in depth).
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: fileURL.path)
        #endif
        let sql = """
        CREATE TABLE IF NOT EXISTS item_secret (
            item_id TEXT PRIMARY KEY NOT NULL,
            secret_ciphertext BLOB NOT NULL,
            vault_wrapped_item_key BLOB NOT NULL,
            revision INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS snapshot_meta (
            key TEXT PRIMARY KEY NOT NULL,
            value INTEGER NOT NULL
        );
        """
        guard exec(sql) else {
            sqlite3_close(handle)
            db = nil
            throw LocalSecretStoreError.sqlite("schema failed")
        }
    }

    deinit {
        if let db { sqlite3_close(db) }
    }

    private func exec(_ sql: String) -> Bool {
        var err: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(db, sql, nil, nil, &err) == SQLITE_OK else {
            if let err { sqlite3_free(err) }
            return false
        }
        return true
    }

    private func bind(_ stmt: OpaquePointer?, _ index: Int32, _ data: Data) {
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            if let base = raw.baseAddress {
                sqlite3_bind_blob(stmt, index, base, Int32(data.count), SQLITE_TRANSIENT)
            } else {
                sqlite3_bind_zeroblob(stmt, index, 0)
            }
        }
    }

    public func save(_ record: LocalSecretRecord) throws {
        guard !record.itemID.isEmpty else { throw LocalSecretStoreError.invalidRecord }
        lock.lock(); defer { lock.unlock() }
        let sql = """
        INSERT INTO item_secret (item_id, secret_ciphertext, vault_wrapped_item_key, revision, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(item_id) DO UPDATE SET
            secret_ciphertext=excluded.secret_ciphertext,
            vault_wrapped_item_key=excluded.vault_wrapped_item_key,
            revision=excluded.revision,
            updated_at=excluded.updated_at;
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw LocalSecretStoreError.sqlite("prepare save failed")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, record.itemID, -1, SQLITE_TRANSIENT)
        bind(stmt, 2, record.secretCiphertext)
        bind(stmt, 3, record.vaultWrappedItemKey)
        sqlite3_bind_int64(stmt, 4, Int64(bitPattern: record.revision))
        sqlite3_bind_int64(stmt, 5, record.updatedAt)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw LocalSecretStoreError.sqlite("save failed")
        }
    }

    private func readRecord(_ stmt: OpaquePointer?) -> LocalSecretRecord? {
        guard let stmt else { return nil }
        guard let idC = sqlite3_column_text(stmt, 0) else { return nil }
        let itemID = String(cString: idC)
        func blob(_ i: Int32) -> Data {
            guard let p = sqlite3_column_blob(stmt, i) else { return Data() }
            let n = Int(sqlite3_column_bytes(stmt, i))
            return Data(bytes: p, count: n)
        }
        let secret = blob(1)
        let vwItem = blob(2)
        let revision = UInt64(bitPattern: sqlite3_column_int64(stmt, 3))
        let updatedAt = sqlite3_column_int64(stmt, 4)
        return LocalSecretRecord(itemID: itemID, secretCiphertext: secret,
                                 vaultWrappedItemKey: vwItem,
                                 revision: revision, updatedAt: updatedAt)
    }

    public func record(itemID: String) throws -> LocalSecretRecord? {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT item_id, secret_ciphertext, vault_wrapped_item_key, revision, updated_at FROM item_secret WHERE item_id = ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw LocalSecretStoreError.sqlite("prepare get failed")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, itemID, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return readRecord(stmt)
    }

    public func allRecords() throws -> [LocalSecretRecord] {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT item_id, secret_ciphertext, vault_wrapped_item_key, revision, updated_at FROM item_secret ORDER BY item_id;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw LocalSecretStoreError.sqlite("prepare all failed")
        }
        defer { sqlite3_finalize(stmt) }
        var out: [LocalSecretRecord] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let r = readRecord(stmt) { out.append(r) }
        }
        return out
    }

    public func remove(itemID: String) throws {
        lock.lock(); defer { lock.unlock() }
        let sql = "DELETE FROM item_secret WHERE item_id = ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw LocalSecretStoreError.sqlite("prepare delete failed")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, itemID, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw LocalSecretStoreError.sqlite("delete failed")
        }
    }

    public func removeAll() throws {
        lock.lock(); defer { lock.unlock() }
        guard exec("DELETE FROM item_secret;") else {
            throw LocalSecretStoreError.sqlite("removeAll failed")
        }
    }

    public func snapshotRevision() throws -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        return readSnapshotRevisionLocked()
    }

    private func readSnapshotRevisionLocked() -> UInt64 {
        let sql = "SELECT value FROM snapshot_meta WHERE key = ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return 0 }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, Keys.snapshotRevision, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return UInt64(bitPattern: sqlite3_column_int64(stmt, 0))
    }

    public func setSnapshotRevision(_ revision: UInt64) throws {
        lock.lock(); defer { lock.unlock() }
        let sql = """
        INSERT INTO snapshot_meta (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value;
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw LocalSecretStoreError.sqlite("prepare rev failed")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, Keys.snapshotRevision, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int64(stmt, 2, Int64(bitPattern: revision))
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw LocalSecretStoreError.sqlite("set rev failed")
        }
    }
}

/// SQLITE_TRANSIENT (destructor telling sqlite to copy the bound bytes).
private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
