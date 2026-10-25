// The app's local SyncStateStore (design §6.5): holds ciphertexts,
// revisions and verified signatures only — never plaintext. Implements the
// KeyrefCore protocol (usable directly by SyncEngine) and adds the
// enumeration and display-label bookkeeping the UI layer needs. Phase 1
// keeps rows in memory; the KeyStore slots (vault id, VMK wrap) carry the
// "vault exists" fact across launches and the first sync re-bootstraps.
import Foundation
import KeyrefCore

public final class UIStateStore: SyncStateStore, @unchecked Sendable {
    private struct State {
        var cursor: Int64 = 0
        var items: [String: ItemData] = [:]
        var grants: [String: GrantData] = [:]  // key: itemID|kind
        var directory: DirectoryData?
        var vaultID: String?
        var pinnedOwnerKey: Data?
        var ownDeviceID: String?
    }

    /// Display metadata the signed directory does not carry (§6.4 label):
    /// seeded at pairing (CLI 自报名) and editable by the owner afterwards.
    public struct DeviceInfo: Equatable, Sendable {
        public var label: String
        public var createdAt: Int64
        public init(label: String, createdAt: Int64) {
            self.label = label
            self.createdAt = createdAt
        }
    }

    private var state = State()
    private var deviceInfo: [String: DeviceInfo] = [:]
    private let lock = NSLock()

    public init() {}

    private func grantKey(_ itemID: String, _ kind: String) -> String { "\(itemID)|\(kind)" }

    // MARK: protocol conformance (SyncEngine path)

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
        state.grants = state.grants.filter { !$0.key.hasPrefix("\(itemID)|") }
    }

    public func upsertGrant(_ grant: GrantData) throws {
        lock.lock(); defer { lock.unlock() }
        state.grants[grantKey(grant.itemID, grant.kind)] = grant
    }

    public func grants() throws -> [GrantData] {
        lock.lock(); defer { lock.unlock() }
        return Array(state.grants.values)
    }

    public func deleteGrant(itemID: String, kind: String) throws {
        lock.lock(); defer { lock.unlock() }
        state.grants.removeValue(forKey: grantKey(itemID, kind))
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
        state.grants.removeAll()
    }

    // MARK: UI-side enumeration

    public func allItems() -> [ItemData] {
        lock.lock(); defer { lock.unlock() }
        return Array(state.items.values)
    }

    public func itemByID(_ id: String) -> ItemData? {
        lock.lock(); defer { lock.unlock() }
        return state.items[id]
    }

    public func allGrants() -> [GrantData] {
        lock.lock(); defer { lock.unlock() }
        return Array(state.grants.values)
    }

    public func currentDirectory() -> DirectoryData? {
        lock.lock(); defer { lock.unlock() }
        return state.directory
    }

    public func ownID() -> String? {
        lock.lock(); defer { lock.unlock() }
        return state.ownDeviceID
    }

    public func wipeAll() {
        lock.lock(); defer { lock.unlock() }
        state = State()
        deviceInfo = [:]
    }

    // MARK: device labels

    public func setDeviceInfo(_ info: DeviceInfo, for deviceID: String) {
        lock.lock(); defer { lock.unlock() }
        deviceInfo[deviceID] = info
    }

    public func info(for deviceID: String) -> DeviceInfo? {
        lock.lock(); defer { lock.unlock() }
        return deviceInfo[deviceID]
    }

    public func allDeviceInfo() -> [String: DeviceInfo] {
        lock.lock(); defer { lock.unlock() }
        return deviceInfo
    }
}
