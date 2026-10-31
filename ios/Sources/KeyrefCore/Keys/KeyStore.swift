// KeyStore abstraction (design §6.5, §9.3, §9.5): storage for the device
// identities, the owner P-256 keys (Secure Enclave or documented software
// fallback) and the VMK wrap. Production uses the iOS/macOS Keychain;
// tests use an in-memory implementation.
import Foundation

/// Named storage slots used by KeyrefCore. The concrete KeyStore maps
/// these to Keychain accounts (or memory).
public enum KeyStoreSlot: String, CaseIterable, Sendable, Codable {
    /// vault_id, hex-encoded (ThisDeviceOnly, design §8.1).
    case vaultID
    /// HPKE-wrapped VMK blob (enc ‖ ct) stored locally, design §9.3 step 3.
    case vmkWrap
    /// Device HPKE private key: X25519 raw (32B) or P-256 raw scalar.
    case deviceHPKEPrivate
    /// Device signing private key: Ed25519 seed (32B) or P-256 raw scalar.
    case deviceSignPrivate
    /// Owner HPKE private key: P-256 raw scalar (software fallback) or the
    /// Secure Enclave persistent dataRepresentation.
    case ownerHPKEPrivate
    /// Owner signing private key: P-256 raw scalar (software fallback) or
    /// the Secure Enclave persistent dataRepresentation.
    case ownerSignPrivate
    /// Software Ed25519 renewal key seed, ThisDeviceOnly + AfterFirstUnlock
    /// semantics (design §8.4).
    case renewalSignPrivate
    /// This device's own device_id (hex). Persisted so a process restart
    /// can re-seed the in-memory state store — without it the restart would
    /// misreport a healthy wrap as S4 (§9.5) and SyncEngine would treat the
    /// device as unpaired (§10.6).
    case ownDeviceID
    /// The pinned owner signing public key (design §6.5). Persisted for the
    /// same restart reason: sync verification needs it before the first
    /// unlock-driven sync.
    case pinnedOwnerKey
    /// The §10.6 sync cursor. Losing it is survivable (bootstrap re-pull),
    /// but persisting it avoids a full re-download on every launch.
    case syncCursor
    /// HPKE-wrapped VMK of an IN-FLIGHT §8.4 rotation (rotateRecovery): the
    /// new VMK is stashed here before any server PUT so an interrupted
    /// attempt stays resumable after a process restart — rows the server
    /// already holds under the new VMK must remain unwrappable (the ritual
    /// reuses this VMK instead of generating a fresh one). Removed when the
    /// rotation completes.
    case pendingVMKWrap
    /// The sync server origin (absolute URL string, §2.15). Not secret;
    /// persisted so a restart keeps pointing at the user's chosen server
    /// instead of silently falling back to the compiled-in default.
    case serverOrigin
}

/// Access policy for stored items, mapped onto Keychain accessibility
/// constants (design §9.3, §9.5).
public enum KeyStoreAccess: Sendable {
    /// kSecAttrAccessibleWhenUnlockedThisDeviceOnly — never leaves this
    /// device, not included in iCloud/unencrypted backups of keychain.
    case whenUnlockedThisDeviceOnly
    /// Requires the device passcode and the current biometric set
    /// (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly +
    /// .biometryCurrentSet access control); re-enrolling Face ID invalidates
    /// the item by definition (design §9.5).
    case biometryCurrentSet
}

public protocol KeyStore: Sendable {
    func store(_ slot: KeyStoreSlot, _ data: Data, access: KeyStoreAccess) throws
    /// Returns nil when the slot is absent.
    func retrieve(_ slot: KeyStoreSlot) throws -> Data?
    func remove(_ slot: KeyStoreSlot) throws
    /// Removes every slot this store manages (local teardown).
    func removeAll() throws
}

public enum KeyStoreError: Error, Equatable {
    case unavailable(String)
    case unexpected(String)
}

/// Default access for ordinary (non-biometric) slots.
public extension KeyStore {
    func store(_ slot: KeyStoreSlot, _ data: Data) throws {
        try store(slot, data, access: .whenUnlockedThisDeviceOnly)
    }
}
