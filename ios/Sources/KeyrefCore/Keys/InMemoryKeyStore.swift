// In-memory KeyStore for unit tests and previews. Not for production use.
import Foundation

public final class InMemoryKeyStore: KeyStore, @unchecked Sendable {
    private struct Entry {
        var data: Data
        var access: KeyStoreAccess
    }

    private var entries: [KeyStoreSlot: Entry] = [:]
    private let lock = NSLock()

    public init() {}

    public func store(_ slot: KeyStoreSlot, _ data: Data, access: KeyStoreAccess) throws {
        lock.lock()
        defer { lock.unlock() }
        entries[slot] = Entry(data: data, access: access)
    }

    public func retrieve(_ slot: KeyStoreSlot) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return entries[slot]?.data
    }

    public func remove(_ slot: KeyStoreSlot) throws {
        lock.lock()
        defer { lock.unlock() }
        entries.removeValue(forKey: slot)
    }

    public func removeAll() throws {
        lock.lock()
        defer { lock.unlock() }
        entries.removeAll()
    }

    /// Test helper: which access policy was used for a slot.
    public func access(of slot: KeyStoreSlot) -> KeyStoreAccess? {
        lock.lock()
        defer { lock.unlock() }
        return entries[slot]?.access
    }
}
