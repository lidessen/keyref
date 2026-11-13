// JSON shapes of the sync protocol (docs/protocol.md §6, §8) and the
// request/response bodies of every endpoint. Binary fields are Data,
// encoded as standard padded Base64 by the shared WireJSON coder
// (protocol §1.1).
import Foundation

/// Shared JSON encoder/decoder configuration for all wire types: standard
/// Base64 for Data, snake_case keys as declared.
public enum WireJSON {
    public static var encoder: JSONEncoder {
        let e = JSONEncoder()
        e.dataEncodingStrategy = .base64
        e.outputFormatting = [.sortedKeys]
        return e
    }

    public static var decoder: JSONDecoder {
        let d = JSONDecoder()
        d.dataDecodingStrategy = .base64
        return d
    }
}

/// A decoded JSON value of any shape, used for sync `change.data`: the
/// protocol transports it as an embedded JSON object (protocol §8.1), not
/// as a Base64 string, so it must not go through the Base64 Data strategy.
public indirect enum RawJSON: Equatable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([RawJSON])
    case object([String: RawJSON])

    /// Captures raw JSON bytes produced by `WireJSON.encoder` or the server.
    public init(json: Data) throws {
        self = try RawJSON.fromAny(JSONSerialization.jsonObject(with: json))
    }

    /// The value re-encoded as JSON bytes, ready for `WireJSON.decoder`.
    public func jsonData() throws -> Data {
        try JSONSerialization.data(withJSONObject: foundationValue)
    }

    private var foundationValue: Any {
        switch self {
        case .null: return NSNull()
        case .bool(let b): return b
        case .number(let n): return n
        case .string(let s): return s
        case .array(let a): return a.map { $0.foundationValue }
        case .object(let o): return o.mapValues { $0.foundationValue }
        }
    }

    private static func fromAny(_ v: Any) throws -> RawJSON {
        switch v {
        case is NSNull: return .null
        case let n as NSNumber:
            // JSONSerialization hands down both booleans and numbers as
            // NSNumber; only CFBoolean instances are JSON booleans.
            if CFGetTypeID(n) == CFBooleanGetTypeID() {
                return .bool(n.boolValue)
            }
            return .number(n.doubleValue)
        case let s as String: return .string(s)
        case let a as [Any]: return .array(try a.map(fromAny))
        case let o as [String: Any]:
            var out: [String: RawJSON] = [:]
            for (k, v) in o { out[k] = try fromAny(v) }
            return .object(out)
        default:
            throw DecodingError.dataCorrupted(.init(codingPath: [],
                debugDescription: "unsupported JSON value: \(type(of: v))"))
        }
    }
}

extension RawJSON: Decodable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let n = try? c.decode(Double.self) {
            self = .number(n)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([RawJSON].self) {
            self = .array(a)
        } else {
            self = .object(try c.decode([String: RawJSON].self))
        }
    }
}

extension RawJSON: Encodable {
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .number(let n): try c.encode(n)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}

// MARK: - sync rows (§8.3)

/// Item row as delivered by GET /v1/items and by sync "item" changes.
/// Owner devices receive the full row (vault_wrapped_* present); CLI
/// devices never receive those (§8.3).
public struct ItemData: Codable, Equatable, Sendable {
    public var vaultID: String
    public var itemID: String
    public var revision: UInt64
    public var tombstone: Bool
    public var metaCiphertext: Data
    public var secretCiphertext: Data
    public var vaultWrappedMetaKey: Data
    public var vaultWrappedItemKey: Data
    public var writerDeviceID: String
    public var signature: Data
    public var updatedAt: Int64

    enum CodingKeys: String, CodingKey {
        case vaultID = "vault_id"
        case itemID = "item_id"
        case revision
        case tombstone
        case metaCiphertext = "meta_ciphertext"
        case secretCiphertext = "secret_ciphertext"
        case vaultWrappedMetaKey = "vault_wrapped_meta_key"
        case vaultWrappedItemKey = "vault_wrapped_item_key"
        case writerDeviceID = "writer_device_id"
        case signature
        case updatedAt = "updated_at"
    }
}

public extension ItemData {
    /// v0.7 (design §6.6): 仅本机 rows carry secret_ciphertext = NULL and no
    /// vault_wrapped_item_key — the server may emit those fields as JSON
    /// `null` or omit them entirely. Both decode to empty Data so the sync
    /// stream keeps applying; a live row with empty secret fields is exactly
    /// the local-only signal (`StorageClass.of(row:)`). Declared in an
    /// extension so the internal memberwise initializer survives.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        vaultID = try c.decode(String.self, forKey: .vaultID)
        itemID = try c.decode(String.self, forKey: .itemID)
        revision = try c.decode(UInt64.self, forKey: .revision)
        tombstone = try c.decodeIfPresent(Bool.self, forKey: .tombstone) ?? false
        func field(_ key: CodingKeys) throws -> Data {
            if c.contains(key), !(try c.decodeNil(forKey: key)) {
                return try c.decode(Data.self, forKey: key)
            }
            return Data()
        }
        metaCiphertext = try field(.metaCiphertext)
        secretCiphertext = try field(.secretCiphertext)
        vaultWrappedMetaKey = try field(.vaultWrappedMetaKey)
        vaultWrappedItemKey = try field(.vaultWrappedItemKey)
        writerDeviceID = try c.decode(String.self, forKey: .writerDeviceID)
        signature = try field(.signature)
        updatedAt = try c.decodeIfPresent(Int64.self, forKey: .updatedAt) ?? 0
    }
}

/// Grant row (§8.3, §3.2): wire form of PUT /v1/grants entries,
/// grants/self rows and sync "grant" changes. Deleted rows carry
/// deleted=true, a bumped revision and empty crypto fields.
public struct GrantData: Codable, Equatable, Sendable {
    public var deviceID: String
    public var itemID: String
    public var kind: String
    public var hpkeEnc: Data
    public var wrappedKey: Data
    /// Unix milliseconds; 0 = never expires.
    public var expiresAt: Int64
    public var revision: UInt64
    public var signature: Data
    public var deleted: Bool

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case itemID = "item_id"
        case kind
        case hpkeEnc = "hpke_enc"
        case wrappedKey = "wrapped_key"
        case expiresAt = "expires_at"
        case revision
        case signature
        case deleted
    }

    /// Builds the §3.2 transcript for this row (deletion form when deleted).
    public func transcript(vaultID: String) -> GrantTranscript {
        GrantTranscript(vaultID: vaultID, deviceID: deviceID, itemID: itemID,
                        kind: kind, revision: revision,
                        expiresAt: UInt64(bitPattern: expiresAt),
                        hpkeEnc: hpkeEnc, wrappedKey: wrappedKey)
    }
}

/// Tolerant decoding: older/hosted servers may omit `deleted` for live
/// rows (Go's `omitempty` did exactly that). A missing field means "not
/// deleted" — the alternative is failing the whole sync batch. Kept in an
/// extension so the memberwise init stays available.
extension GrantData {
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        deviceID = try c.decode(String.self, forKey: .deviceID)
        itemID = try c.decode(String.self, forKey: .itemID)
        kind = try c.decode(String.self, forKey: .kind)
        hpkeEnc = try c.decode(Data.self, forKey: .hpkeEnc)
        wrappedKey = try c.decode(Data.self, forKey: .wrappedKey)
        expiresAt = try c.decode(Int64.self, forKey: .expiresAt)
        revision = try c.decode(UInt64.self, forKey: .revision)
        signature = try c.decode(Data.self, forKey: .signature)
        deleted = try c.decodeIfPresent(Bool.self, forKey: .deleted) ?? false
    }
}

/// Sync "device" entity data (§8.3): status summary, no key material.
public struct DeviceData: Codable, Equatable, Sendable {
    public var deviceID: String
    public var kind: String
    public var status: String
    public var label: String
    public var createdAt: Int64
    public var revokedAt: Int64?

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case kind
        case status
        case label
        case createdAt = "created_at"
        case revokedAt = "revoked_at"
    }
}

/// Sync "directory" entity data (§8.3): signed transcript blob + signature.
public struct DirectoryData: Codable, Equatable, Sendable {
    public var directoryRevision: UInt64
    public var signed: Data
    public var signature: Data

    enum CodingKeys: String, CodingKey {
        case directoryRevision = "directory_revision"
        case signed = "directory_signed"
        case signature = "directory_signature"
    }
}

/// Sync "approval" entity data (§8.3, D8): status summary only.
public struct ApprovalData: Codable, Equatable, Sendable {
    public var approvalID: String
    public var status: String

    enum CodingKeys: String, CodingKey {
        case approvalID = "approval_id"
        case status
    }
}

// MARK: - sync envelope (§8.1)

public struct SyncChange: Codable, Sendable {
    public var seq: Int64
    public var entity: String
    public var entityID: String
    public var createdAt: Int64
    /// Embedded JSON object whose shape depends on `entity` (protocol §8.1).
    public var data: RawJSON

    enum CodingKeys: String, CodingKey {
        case seq
        case entity
        case entityID = "entity_id"
        case createdAt = "created_at"
        case data
    }

    /// Decodes `data` for the known entities. Unknown entities decode to
    /// nil and are recorded but not applied (same policy as the CLI).
    public func decodedData() throws -> SyncChangePayload? {
        let raw = try data.jsonData()
        switch entity {
        case KeyrefEntity.item: return .item(try WireJSON.decoder.decode(ItemData.self, from: raw))
        case KeyrefEntity.grant: return .grant(try WireJSON.decoder.decode(GrantData.self, from: raw))
        case KeyrefEntity.device: return .device(try WireJSON.decoder.decode(DeviceData.self, from: raw))
        case KeyrefEntity.directory: return .directory(try WireJSON.decoder.decode(DirectoryData.self, from: raw))
        case KeyrefEntity.approval: return .approval(try WireJSON.decoder.decode(ApprovalData.self, from: raw))
        default: return nil
        }
    }
}

public enum SyncChangePayload: Sendable {
    case item(ItemData)
    case grant(GrantData)
    case device(DeviceData)
    case directory(DirectoryData)
    case approval(ApprovalData)
}

public struct SyncResponse: Codable, Sendable {
    public var cursor: Int64
    public var hasMore: Bool
    public var changes: [SyncChange]

    enum CodingKeys: String, CodingKey {
        case cursor
        case hasMore = "has_more"
        case changes
    }
}

// MARK: - session / plan (§6.3, §6.7, §6.25)

public struct PlanLimits: Codable, Equatable, Sendable {
    public var items: Int64?
    public var devicesIOS: Int64?
    public var devicesCLI: Int64?
    public var storageBytes: Int64?
    public var auditRetentionDays: Int64?
    public var auditMaxEvents: Int64?
    public var requestsPerDay: Int64?
    public var requestsPerMinute: Int64?

    enum CodingKeys: String, CodingKey {
        case items
        case devicesIOS = "devices_ios"
        case devicesCLI = "devices_cli"
        case storageBytes = "storage_bytes"
        case auditRetentionDays = "audit_retention_days"
        case auditMaxEvents = "audit_max_events"
        case requestsPerDay = "requests_per_day"
        case requestsPerMinute = "requests_per_minute"
    }
}

/// Body of the session step-two response and of the recovery takeover
/// response (§6.7, §6.3).
public struct SessionResponse: Codable, Equatable, Sendable {
    public var token: String
    public var expiresAt: Int64
    public var origin: String
    public var plan: String
    public var limits: PlanLimits?

    enum CodingKeys: String, CodingKey {
        case token
        case expiresAt = "expires_at"
        case origin
        case plan
        case limits
    }
}

public struct AccountUsage: Codable, Equatable, Sendable {
    public var items: Int64
    public var devicesActive: Int64
    public var storageBytes: Int64
    public var auditEvents: Int64
    public var requestsToday: Int64

    enum CodingKeys: String, CodingKey {
        case items
        case devicesActive = "devices_active"
        case storageBytes = "storage_bytes"
        case auditEvents = "audit_events"
        case requestsToday = "requests_today"
    }
}

public struct AccountResponse: Codable, Sendable {
    public var plan: String
    public var planExpiresAt: Int64?
    public var limits: PlanLimits?
    public var usage: AccountUsage

    enum CodingKeys: String, CodingKey {
        case plan
        case planExpiresAt = "plan_expires_at"
        case limits
        case usage
    }
}

// MARK: - vault creation & recovery (§6.1–§6.4)

/// The structured device object of vault creation and pair completion.
public struct DeviceInput: Codable, Equatable, Sendable {
    public var deviceID: String
    public var kind: String
    public var hpkeKEM: String
    public var hpkePublicKey: Data
    public var signAlg: String
    public var signPublicKey: Data
    public var label: String
    public var renewalSignPublicKey: Data

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case kind
        case hpkeKEM = "hpke_kem"
        case hpkePublicKey = "hpke_public_key"
        case signAlg = "sign_alg"
        case signPublicKey = "sign_public_key"
        case label
        case renewalSignPublicKey = "renewal_sign_public_key"
    }
}

public struct PoWSolution: Codable, Equatable, Sendable {
    public var challenge: Data
    public var nonce: Data  // 8 bytes, u64be

    public init(challenge: Data, nonce: Data) {
        self.challenge = challenge
        self.nonce = nonce
    }

    enum CodingKeys: String, CodingKey {
        case challenge
        case nonce
    }
}

public struct CreateVaultRequest: Codable, Sendable {
    public var vaultID: String
    public var device: DeviceInput
    public var recoveryWrap: Data
    public var recoveryKDFJSON: String
    public var recoverySignPub: Data
    public var directoryRevision: UInt64
    public var directorySigned: Data
    public var signature: Data
    public var pow: PoWSolution?

    enum CodingKeys: String, CodingKey {
        case vaultID = "vault_id"
        case device
        case recoveryWrap = "recovery_wrap"
        case recoveryKDFJSON = "recovery_kdf_json"
        case recoverySignPub = "recovery_sign_pub"
        case directoryRevision = "directory_revision"
        case directorySigned = "directory_signed"
        case signature
        case pow
    }
}

public struct CreateVaultResponse: Codable, Equatable, Sendable {
    public var vaultID: String

    enum CodingKeys: String, CodingKey {
        case vaultID = "vault_id"
    }
}

public struct RecoveryMaterialsResponse: Codable, Equatable, Sendable {
    public var vaultID: String
    public var recoveryWrap: Data
    public var recoveryKDFJSON: String
    public var recoverySignPub: Data
    public var directoryRevision: UInt64
    public var directorySigned: Data
    public var directorySignature: Data

    enum CodingKeys: String, CodingKey {
        case vaultID = "vault_id"
        case recoveryWrap = "recovery_wrap"
        case recoveryKDFJSON = "recovery_kdf_json"
        case recoverySignPub = "recovery_sign_pub"
        case directoryRevision = "directory_revision"
        case directorySigned = "directory_signed"
        case directorySignature = "directory_signature"
    }
}

/// Both signatures cover the same §3.3 directory transcript bytes (§6.3,
/// D13): the recovery signing authority and the new owner key.
public struct RecoveryDirectoryRequest: Codable, Sendable {
    public var vaultID: String
    public var directoryRevision: UInt64
    public var directorySigned: Data
    public var recoverySignature: Data
    public var ownerSignature: Data

    enum CodingKeys: String, CodingKey {
        case vaultID = "vault_id"
        case directoryRevision = "directory_revision"
        case directorySigned = "directory_signed"
        case recoverySignature = "recovery_signature"
        case ownerSignature = "owner_signature"
    }
}

public struct PutVaultRecoveryRequest: Codable, Sendable {
    public var recoveryWrap: Data
    public var recoveryKDFJSON: String
    public var recoverySignPub: Data
    public var signature: Data

    enum CodingKeys: String, CodingKey {
        case recoveryWrap = "recovery_wrap"
        case recoveryKDFJSON = "recovery_kdf_json"
        case recoverySignPub = "recovery_sign_pub"
        case signature
    }
}

// MARK: - vault delete (§6.5)

public struct DeleteVaultRequest: Codable, Sendable {
    public var challenge: Data?
    public var signature: Data?

    enum CodingKeys: String, CodingKey {
        case challenge
        case signature
    }
}

// MARK: - session two-step (§6.7)

public struct SessionRequest: Codable, Sendable {
    public var deviceID: String
    public var challenge: Data?
    public var signature: Data?

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case challenge
        case signature
    }
}

public struct SessionChallengeResponse: Codable, Equatable, Sendable {
    public var challenge: Data
    public var expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case challenge
        case expiresAt = "expires_at"
    }
}

// MARK: - items & grants (§6.10–§6.14)

public struct PutItemRequest: Codable, Sendable {
    public var revision: UInt64
    public var tombstone: Bool
    public var metaCiphertext: Data
    public var secretCiphertext: Data
    public var vaultWrappedMetaKey: Data
    public var vaultWrappedItemKey: Data
    public var writerDeviceID: String
    public var signature: Data

    enum CodingKeys: String, CodingKey {
        case revision
        case tombstone
        case metaCiphertext = "meta_ciphertext"
        case secretCiphertext = "secret_ciphertext"
        case vaultWrappedMetaKey = "vault_wrapped_meta_key"
        case vaultWrappedItemKey = "vault_wrapped_item_key"
        case writerDeviceID = "writer_device_id"
        case signature
    }
}

public struct PutItemResponse: Codable, Equatable, Sendable {
    public var revision: UInt64
    public var updatedAt: Int64

    enum CodingKeys: String, CodingKey {
        case revision
        case updatedAt = "updated_at"
    }
}

public struct DeleteItemRequest: Codable, Sendable {
    public var revision: UInt64
    public var signature: Data

    enum CodingKeys: String, CodingKey {
        case revision
        case signature
    }
}

public struct PutGrantsRequest: Codable, Sendable {
    public var grants: [GrantData]

    enum CodingKeys: String, CodingKey {
        case grants
    }
}

public struct PutGrantsResponse: Codable, Equatable, Sendable {
    public var applied: Int

    enum CodingKeys: String, CodingKey {
        case applied
    }
}

public struct DeleteGrantRequest: Codable, Sendable {
    public var deviceID: String
    public var itemID: String
    public var kind: String
    public var revision: UInt64
    public var signature: Data

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case itemID = "item_id"
        case kind
        case revision
        case signature
    }
}

public struct GrantsSelfResponse: Codable, Sendable {
    public var grants: [GrantData]
    public var grantsDigest: Data
    public var directoryRevision: UInt64

    enum CodingKeys: String, CodingKey {
        case grants
        case grantsDigest = "grants_digest"
        case directoryRevision = "directory_revision"
    }
}

// MARK: - directory (§6.15)

public struct PutDirectoryRequest: Codable, Sendable {
    public var directoryRevision: UInt64
    public var directorySigned: Data
    public var signature: Data

    enum CodingKeys: String, CodingKey {
        case directoryRevision = "directory_revision"
        case directorySigned = "directory_signed"
        case signature
    }
}

public struct PutDirectoryResponse: Codable, Equatable, Sendable {
    public var directoryRevision: UInt64

    enum CodingKeys: String, CodingKey {
        case directoryRevision = "directory_revision"
    }
}

// MARK: - pairing (§6.16–§6.18)

public struct PairRegisterRequest: Codable, Sendable {
    public var nonce: String
    public var hpkeKEM: String
    public var hpkePublicKey: Data
    public var signAlg: String
    public var signPublicKey: Data
    public var proposedName: String
    public var signature: Data

    enum CodingKeys: String, CodingKey {
        case nonce
        case hpkeKEM = "hpke_kem"
        case hpkePublicKey = "hpke_public_key"
        case signAlg = "sign_alg"
        case signPublicKey = "sign_public_key"
        case proposedName = "proposed_name"
        case signature
    }
}

public struct PairRegisterResponse: Codable, Equatable, Sendable {
    public var expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case expiresAt = "expires_at"
    }
}

public struct PairCompleteRequest: Codable, Sendable {
    public var nonce: String
    public var device: DeviceInput
    public var grants: [GrantData]
    public var signature: Data
    /// Pairing confirmation MAC (protocol §3.13, v2 D): HMAC-SHA256 over
    /// the pair transcript under the QR secret `c`, required. The server
    /// stores it opaquely and echoes it at pair/status; the paired device
    /// re-computes it from its own `c` before pinning the owner key.
    public var pairingMac: Data

    enum CodingKeys: String, CodingKey {
        case nonce
        case device
        case grants
        case signature
        case pairingMac = "pairing_mac"
    }
}

public struct PairStatusResponse: Codable, Sendable {
    public var status: String
    public var vaultID: String?
    public var deviceID: String?
    public var ownerSignPublicKey: Data?
    public var pairingSignature: Data?
    public var pairingMac: Data?
    public var directoryRevision: UInt64?
    public var directorySigned: Data?
    public var directorySignature: Data?
    public var grants: [GrantData]?

    enum CodingKeys: String, CodingKey {
        case status
        case vaultID = "vault_id"
        case deviceID = "device_id"
        case ownerSignPublicKey = "owner_sign_public_key"
        case pairingSignature = "pairing_signature"
        case pairingMac = "pairing_mac"
        case directoryRevision = "directory_revision"
        case directorySigned = "directory_signed"
        case directorySignature = "directory_signature"
        case grants
    }
}

// MARK: - approvals (§6.19–§6.22)

public struct CreateApprovalRequest: Codable, Sendable {
    public var itemID: String
    public var requestCiphertext: Data
    public var requestSignature: Data
    public var expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case itemID = "item_id"
        case requestCiphertext = "request_ciphertext"
        case requestSignature = "request_signature"
        case expiresAt = "expires_at"
    }
}

public struct CreateApprovalResponse: Codable, Equatable, Sendable {
    public var approvalID: String
    public var expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case approvalID = "approval_id"
        case expiresAt = "expires_at"
    }
}

public struct ApprovalListResponse: Codable, Sendable {
    public var approvals: [PendingApproval]

    enum CodingKeys: String, CodingKey {
        case approvals
    }
}

/// A pending approval as the owner receives it. The request ciphertext is
/// opened before display, and the CLI signature is verified first (§6.20).
///
/// A row has exactly one subject (protocol D16): `item_id` for an item
/// consumption, or `message_id` for an SMS consumption (design v0.8
/// §14.5). The server omits the empty one, so both decode as "".
public struct PendingApproval: Codable, Equatable, Sendable {
    public var approvalID: String
    public var cliDeviceID: String
    public var itemID: String
    /// Set when the subject is `message:<id>`; empty for items.
    public var messageID: String
    /// The CLI's one-time X25519 public key, sent in the clear for both
    /// subjects: the request signature (§3.11, v2 A) covers it, so a
    /// decider — which never decrypts the request — can trust it.
    public var cliEphemeralPublicKey: Data
    public var requestCiphertext: Data
    public var requestSignature: Data
    public var createdAt: Int64
    public var expiresAt: Int64

    /// True when this approval consumes an SMS message.
    public var isMessageSubject: Bool { !messageID.isEmpty }

    enum CodingKeys: String, CodingKey {
        case approvalID = "approval_id"
        case cliDeviceID = "cli_device_id"
        case itemID = "item_id"
        case messageID = "message_id"
        case cliEphemeralPublicKey = "cli_ephemeral_public_key"
        case requestCiphertext = "request_ciphertext"
        case requestSignature = "request_signature"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        approvalID = try c.decode(String.self, forKey: .approvalID)
        cliDeviceID = try c.decode(String.self, forKey: .cliDeviceID)
        // Omitted for the other subject kind — never a decode failure.
        itemID = try c.decodeIfPresent(String.self, forKey: .itemID) ?? ""
        messageID = try c.decodeIfPresent(String.self, forKey: .messageID) ?? ""
        cliEphemeralPublicKey = try c.decodeIfPresent(Data.self, forKey: .cliEphemeralPublicKey) ?? Data()
        requestCiphertext = try c.decode(Data.self, forKey: .requestCiphertext)
        requestSignature = try c.decode(Data.self, forKey: .requestSignature)
        createdAt = try c.decode(Int64.self, forKey: .createdAt)
        expiresAt = try c.decode(Int64.self, forKey: .expiresAt)
    }

    /// Memberwise (declaring `init(from:)` suppresses the synthesized one).
    public init(approvalID: String, cliDeviceID: String, itemID: String,
                messageID: String = "", cliEphemeralPublicKey: Data = Data(),
                requestCiphertext: Data, requestSignature: Data,
                createdAt: Int64, expiresAt: Int64) {
        self.approvalID = approvalID
        self.cliDeviceID = cliDeviceID
        self.itemID = itemID
        self.messageID = messageID
        self.cliEphemeralPublicKey = cliEphemeralPublicKey
        self.requestCiphertext = requestCiphertext
        self.requestSignature = requestSignature
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }
}

public struct ApprovalDecisionRequest: Codable, Sendable {
    public var decision: String  // "approved" | "denied"
    public var oneTimeEnc: Data?
    public var oneTimeWrappedKey: Data?
    /// The deciding device's signature over the approval-decision
    /// transcript (§3.12, v2 B). Required on approved and denied
    /// decisions alike — the CLI verifies it before it unwraps.
    public var decisionSignature: Data

    enum CodingKeys: String, CodingKey {
        case decision
        case oneTimeEnc = "one_time_enc"
        case oneTimeWrappedKey = "one_time_wrapped_key"
        case decisionSignature = "decision_signature"
    }

    /// Memberwise (declaring `init(from:)` is not done here, so the
    /// synthesized init is internal).
    init(decision: String, oneTimeEnc: Data?, oneTimeWrappedKey: Data?,
         decisionSignature: Data) {
        self.decision = decision
        self.oneTimeEnc = oneTimeEnc
        self.oneTimeWrappedKey = oneTimeWrappedKey
        self.decisionSignature = decisionSignature
    }
}

public struct ApprovalStatusResponse: Codable, Sendable {
    public var approvalID: String
    public var status: String
    public var oneTimeEnc: Data?
    public var oneTimeWrappedKey: Data?
    public var expiresAt: Int64?
    /// The device that signed the decision (owner or decider); absent
    /// while the row is pending (§6.22, v2 B).
    public var decisionDeviceID: String?
    /// The decision signature, returned next to `decision_device_id`.
    public var decisionSignature: Data?

    enum CodingKeys: String, CodingKey {
        case approvalID = "approval_id"
        case status
        case oneTimeEnc = "one_time_enc"
        case oneTimeWrappedKey = "one_time_wrapped_key"
        case expiresAt = "expires_at"
        case decisionDeviceID = "decision_device_id"
        case decisionSignature = "decision_signature"
    }
}

// MARK: - audit (§6.23, §6.24)

public struct AuditEnvelopeRequest: Codable, Sendable {
    public var ciphertext: Data

    enum CodingKeys: String, CodingKey {
        case ciphertext
    }
}

public struct AuditEnvelopeResponse: Codable, Equatable, Sendable {
    public var seq: Int64

    enum CodingKeys: String, CodingKey {
        case seq
    }
}

public struct AuditEventRow: Codable, Equatable, Sendable {
    public var seq: Int64
    public var deviceID: String
    public var createdAt: Int64
    public var ciphertext: Data

    enum CodingKeys: String, CodingKey {
        case seq
        case deviceID = "device_id"
        case createdAt = "created_at"
        case ciphertext
    }
}

public struct AuditPageResponse: Codable, Sendable {
    public var events: [AuditEventRow]
    public var cursor: Int64
    public var hasMore: Bool

    enum CodingKeys: String, CodingKey {
        case events
        case cursor
        case hasMore = "has_more"
    }
}

// MARK: - billing (§6.26)

public struct BillingAppleRequest: Codable, Sendable {
    public var transactionID: String

    enum CodingKeys: String, CodingKey {
        case transactionID = "transaction_id"
    }
}

public struct BillingAppleResponse: Codable, Equatable, Sendable {
    public var plan: String
    public var planExpiresAt: Int64?

    enum CodingKeys: String, CodingKey {
        case plan
        case planExpiresAt = "plan_expires_at"
    }
}

// MARK: - messages (§6.28–§6.31, design v0.8 §14)

/// One message row from `GET /v1/messages` (§6.29). `envelope` is the
/// §3.9 blob; it only opens for a device that is one of its recipients.
public struct MessageRow: Codable, Equatable, Sendable {
    public var messageID: String
    public var sourceDeviceID: String
    public var status: String          // "active" | "consumed"
    public var envelope: Data
    /// The source device's Ed25519 signature over the §3.9
    /// message-upload transcript; readers re-verify it against the
    /// signed directory before decrypting (protocol v2 C).
    public var requestSignature: Data
    /// Sender-reported arrival time — display only (ordering and policy
    /// use `createdAt`, §6.29).
    public var receivedAt: Int64
    public var createdAt: Int64
    public var expiresAt: Int64

    public var isActive: Bool { status == "active" }

    enum CodingKeys: String, CodingKey {
        case messageID = "message_id"
        case sourceDeviceID = "source_device_id"
        case status
        case envelope
        case requestSignature = "request_signature"
        case receivedAt = "received_at"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        messageID = try c.decode(String.self, forKey: .messageID)
        sourceDeviceID = try c.decode(String.self, forKey: .sourceDeviceID)
        status = try c.decode(String.self, forKey: .status)
        envelope = try c.decode(Data.self, forKey: .envelope)
        // Absent on a row that predates v2 C; verification treats empty
        // as a failure, so an old row never decrypts either.
        requestSignature = try c.decodeIfPresent(Data.self, forKey: .requestSignature) ?? Data()
        receivedAt = try c.decode(Int64.self, forKey: .receivedAt)
        createdAt = try c.decode(Int64.self, forKey: .createdAt)
        expiresAt = try c.decode(Int64.self, forKey: .expiresAt)
    }

    /// Memberwise (declaring `init(from:)` suppresses the synthesized one).
    public init(messageID: String, sourceDeviceID: String, status: String,
                envelope: Data, requestSignature: Data = Data(),
                receivedAt: Int64, createdAt: Int64, expiresAt: Int64) {
        self.messageID = messageID
        self.sourceDeviceID = sourceDeviceID
        self.status = status
        self.envelope = envelope
        self.requestSignature = requestSignature
        self.receivedAt = receivedAt
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }
}

public struct MessageListResponse: Codable, Equatable, Sendable {
    public var messages: [MessageRow]
    public var cursor: Int64
    public var hasMore: Bool

    enum CodingKeys: String, CodingKey {
        case messages
        case cursor
        case hasMore = "has_more"
    }
}

/// One backfill record of `PUT /v1/messages/:id/wraps` (§6.30): the owner
/// re-wraps a message key for a decider that paired after the message
/// landed.
public struct MessageWrap: Codable, Equatable, Sendable {
    public var deviceID: String
    public var hpkeEnc: Data
    public var wrappedKey: Data

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case hpkeEnc = "hpke_enc"
        case wrappedKey = "wrapped_key"
    }
}

public struct MessageWrapsRequest: Codable, Equatable, Sendable {
    public var wraps: [MessageWrap]
}
