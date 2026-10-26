// In-memory SyncStateStore for tests and previews. Production persists
// the same state in the app's local encrypted store (design §6.5: the
// cache holds ciphertexts, revisions and verified signatures only —
// never plaintext).
import Foundation

public final class InMemorySyncStateStore: SyncStateStore, @unchecked Sendable {
    private struct State {
        var cursor: Int64 = 0
        var items: [String: ItemData] = [:]
        var grants: [String: GrantData] = [:]  // key: itemID|kind
        var directory: DirectoryData?
        var vaultID: String?
        var pinnedOwnerKey: Data?
        var ownDeviceID: String?
        var sessionCachesCleared = 0
    }

    private var state = State()
    private let lock = NSLock()

    public init() {}

    private func grantKey(_ deviceID: String, _ itemID: String, _ kind: String) -> String {
        "\(deviceID)|\(itemID)|\(kind)"
    }

    public func cursor() throws -> Int64 { lock.lock(); defer { lock.unlock() }; return state.cursor }
    public func setCursor(_ v: Int64) throws { lock.lock(); defer { lock.unlock() }; state.cursor = v }

    public func upsertItem(_ item: ItemData) throws {
        lock.lock(); defer { lock.unlock() }
        state.items[item.itemID] = item
    }

    public func item(_ itemID: String) throws -> ItemData? {
        lock.lock(); defer { lock.unlock() }
        return state.items[itemID]
    }

    public func deleteItem(_ itemID: String) throws {
        lock.lock(); defer { lock.unlock() }
        state.items.removeValue(forKey: itemID)
        // Cascade: a tombstoned item drops all its grants (design §6.3).
        state.grants = state.grants.filter { $0.value.itemID != itemID }
    }

    public func upsertGrant(_ grant: GrantData) throws {
        lock.lock(); defer { lock.unlock() }
        state.grants[grantKey(grant.deviceID, grant.itemID, grant.kind)] = grant
    }

    public func grants() throws -> [GrantData] {
        lock.lock(); defer { lock.unlock() }
        return Array(state.grants.values)
    }

    public func deleteGrant(deviceID: String, itemID: String, kind: String) throws {
        lock.lock(); defer { lock.unlock() }
        state.grants.removeValue(forKey: grantKey(deviceID, itemID, kind))
    }

    public func storeDirectory(_ directory: DirectoryData) throws {
        lock.lock(); defer { lock.unlock() }
        state.directory = directory
    }

    public func directory() throws -> DirectoryData? {
        lock.lock(); defer { lock.unlock() }
        return state.directory
    }

    public func setVaultID(_ vaultID: String) throws { lock.lock(); defer { lock.unlock() }; state.vaultID = vaultID }
    public func vaultID() throws -> String? { lock.lock(); defer { lock.unlock() }; return state.vaultID }

    public func setPinnedOwnerKey(_ key: Data) throws { lock.lock(); defer { lock.unlock() }; state.pinnedOwnerKey = key }
    public func pinnedOwnerKey() throws -> Data? { lock.lock(); defer { lock.unlock() }; return state.pinnedOwnerKey }

    public func setOwnDeviceID(_ deviceID: String) throws { lock.lock(); defer { lock.unlock() }; state.ownDeviceID = deviceID }
    public func ownDeviceID() throws -> String? { lock.lock(); defer { lock.unlock() }; return state.ownDeviceID }

    public func clearSessionCaches() throws {
        lock.lock(); defer { lock.unlock() }
        state.sessionCachesCleared += 1
    }
}
