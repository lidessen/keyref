// Signed transcript builders (docs/protocol.md §3).
//
// Transcripts are write-only byte strings: a signer assembles them from
// structured fields in the exact order the protocol fixes, and a verifier
// rebuilds the same bytes from the fields it wants to assert, then checks
// the signature (protocol §1.5, decision D3). Transcripts are never parsed
// by splitting on NUL — binary fields may contain 0x00.
import CryptoKit
import Foundation

public enum KeyrefWireError: Error, Equatable {
    case invalidField(String)
    case badSignature
}

/// The ASCII prefix every transcript starts with (protocol §3).
public let transcriptPrefix = "KEYREF1"

/// Fixed binary field sizes (protocol §1.4).
public enum KeyrefSizes {
    public static let x25519Key = 32
    public static let p256Key = 65
    public static let ed25519Key = 32
    public static let digest = 32
    public static let challenge = 32
    public static let pairNonce = 16
}

/// Algorithm identifiers carried in JSON and the devices table (§1.4).
public enum SignAlg {
    public static let ed25519 = "ed25519"
    public static let ecdsaP256 = "ecdsa-p256"
}

public enum KEMName {
    public static let x25519 = "X25519"
    public static let p256 = "P-256"
}

public enum DeviceKind {
    public static let ios = "ios"
    public static let cli = "cli"
}

public enum DeviceStatus {
    public static let pending = "pending"
    public static let active = "active"
    public static let revoked = "revoked"
}

public enum GrantKind {
    public static let view = "view"
    public static let use = "use"
}

/// Device labels and proposed pairing names are bounded (design §6.4).
public let labelMaxBytes = 32

// MARK: - assembly helpers

private func begin(_ kind: String) -> Data {
    var b = Data()
    b.append(contentsOf: transcriptPrefix.utf8)
    b.append(KeyrefEncoding.fieldSeparator)
    b.append(contentsOf: kind.utf8)
    b.append(KeyrefEncoding.fieldSeparator)
    return b
}

private func requireID(_ name: String, _ v: String) throws {
    guard KeyrefEncoding.isValidID(v) else {
        throw KeyrefWireError.invalidField("\(name) must be 32 lowercase hex characters")
    }
}

private func requireKEM(_ kem: String) throws {
    guard kem == KEMName.x25519 || kem == KEMName.p256 else {
        throw KeyrefWireError.invalidField("hpke_kem must be \"X25519\" or \"P-256\"")
    }
}

private func requireSignAlg(_ alg: String) throws {
    guard alg == SignAlg.ed25519 || alg == SignAlg.ecdsaP256 else {
        throw KeyrefWireError.invalidField("sign_alg must be \"ed25519\" or \"ecdsa-p256\"")
    }
}

private func requireGrantKind(_ kind: String) throws {
    guard kind == GrantKind.view || kind == GrantKind.use else {
        throw KeyrefWireError.invalidField("kind must be \"view\" or \"use\"")
    }
}

private func requireUTF8(_ s: String, maxBytes: Int, name: String) throws {
    // Swift strings are unicode scalars; enforce valid UTF-8 bytes and the
    // byte bound the way Go's utf8.ValidString + len() does.
    let bytes = Data(s.utf8)
    guard String(decoding: bytes, as: UTF8.self) == s else {
        throw KeyrefWireError.invalidField("\(name) must be valid utf-8")
    }
    guard bytes.count <= maxBytes else {
        throw KeyrefWireError.invalidField("\(name) must be at most \(maxBytes) bytes")
    }
}

// MARK: - item transcript (§3.1)

public struct ItemTranscript: Sendable {
    public var vaultID: String
    public var itemID: String
    public var revision: UInt64
    public var metaCiphertext: Data
    public var secretCiphertext: Data
    public var vaultWrappedMetaKey: Data
    public var vaultWrappedItemKey: Data
    public var writerDeviceID: String

    public init(vaultID: String, itemID: String, revision: UInt64,
                metaCiphertext: Data, secretCiphertext: Data,
                vaultWrappedMetaKey: Data, vaultWrappedItemKey: Data,
                writerDeviceID: String) {
        self.vaultID = vaultID
        self.itemID = itemID
        self.revision = revision
        self.metaCiphertext = metaCiphertext
        self.secretCiphertext = secretCiphertext
        self.vaultWrappedMetaKey = vaultWrappedMetaKey
        self.vaultWrappedItemKey = vaultWrappedItemKey
        self.writerDeviceID = writerDeviceID
    }

    /// Tombstone rows carry four zero-length ciphertext fields.
    public static func tombstone(vaultID: String, itemID: String, revision: UInt64, writerDeviceID: String) -> ItemTranscript {
        ItemTranscript(vaultID: vaultID, itemID: itemID, revision: revision,
                       metaCiphertext: Data(), secretCiphertext: Data(),
                       vaultWrappedMetaKey: Data(), vaultWrappedItemKey: Data(),
                       writerDeviceID: writerDeviceID)
    }

    public func buildBytes() throws -> Data {
        try requireID("vault_id", vaultID)
        try requireID("item_id", itemID)
        try requireID("writer_device_id", writerDeviceID)
        guard revision >= 1 else {
            throw KeyrefWireError.invalidField("revision must be >= 1")
        }
        var b = begin("item")
        b.append(contentsOf: vaultID.utf8); b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: itemID.utf8); b.append(KeyrefEncoding.fieldSeparator)
        KeyrefEncoding.appendU64BE(revision, to: &b); b.append(KeyrefEncoding.fieldSeparator)
        b.append(metaCiphertext); b.append(KeyrefEncoding.fieldSeparator)
        b.append(secretCiphertext); b.append(KeyrefEncoding.fieldSeparator)
        b.append(vaultWrappedMetaKey); b.append(KeyrefEncoding.fieldSeparator)
        b.append(vaultWrappedItemKey); b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: writerDeviceID.utf8)
        return b
    }
}

// MARK: - grant transcript (§3.2)

public struct GrantTranscript: Sendable {
    public var vaultID: String
    public var deviceID: String
    public var itemID: String
    public var kind: String
    public var revision: UInt64
    /// Unix milliseconds; 0 = never expires (protocol D5).
    public var expiresAt: UInt64
    public var hpkeEnc: Data
    public var wrappedKey: Data

    public init(vaultID: String, deviceID: String, itemID: String, kind: String,
                revision: UInt64, expiresAt: UInt64, hpkeEnc: Data, wrappedKey: Data) {
        self.vaultID = vaultID
        self.deviceID = deviceID
        self.itemID = itemID
        self.kind = kind
        self.revision = revision
        self.expiresAt = expiresAt
        self.hpkeEnc = hpkeEnc
        self.wrappedKey = wrappedKey
    }

    /// Deletion form: expires_at 0 and empty crypto fields.
    public static func deletion(vaultID: String, deviceID: String, itemID: String,
                                kind: String, revision: UInt64) -> GrantTranscript {
        GrantTranscript(vaultID: vaultID, deviceID: deviceID, itemID: itemID,
                        kind: kind, revision: revision, expiresAt: 0,
                        hpkeEnc: Data(), wrappedKey: Data())
    }

    public func buildBytes() throws -> Data {
        try requireID("vault_id", vaultID)
        try requireID("device_id", deviceID)
        try requireID("item_id", itemID)
        try requireGrantKind(kind)
        guard revision >= 1 else {
            throw KeyrefWireError.invalidField("revision must be >= 1")
        }
        guard hpkeEnc.isEmpty == wrappedKey.isEmpty else {
            throw KeyrefWireError.invalidField("hpke_enc and wrapped_key must be both empty (deletion form) or both present")
        }
        var b = begin("grant")
        b.append(contentsOf: vaultID.utf8); b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: deviceID.utf8); b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: itemID.utf8); b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: kind.utf8); b.append(KeyrefEncoding.fieldSeparator)
        KeyrefEncoding.appendU64BE(revision, to: &b); b.append(KeyrefEncoding.fieldSeparator)
        KeyrefEncoding.appendU64BE(expiresAt, to: &b); b.append(KeyrefEncoding.fieldSeparator)
        b.append(hpkeEnc); b.append(KeyrefEncoding.fieldSeparator)
        b.append(wrappedKey)
        return b
    }
}

/// Orders grants by (item_id hex ascending, kind byte ascending); "use"
/// sorts before "view" (protocol §3.3, D6).
private func sortedGrants(_ grants: [GrantTranscript]) -> [GrantTranscript] {
    grants.sorted { a, b in
        if a.itemID != b.itemID { return a.itemID < b.itemID }
        return a.kind < b.kind
    }
}

/// Per-device grants digest carried in directory records (§3.3):
/// SHA-256 over the concatenated grant transcripts ordered by (item_id,
/// kind). An empty grant set digests the empty string.
public func grantsDigest(_ grants: [GrantTranscript]) throws -> Data {
    var h = SHA256()
    for g in sortedGrants(grants) {
        h.update(data: try g.buildBytes())
    }
    return Data(h.finalize())
}

/// The digest of a device with no grants: SHA-256 of the empty string.
public func emptyGrantsDigest() -> Data {
    Data(SHA256.hash(data: Data()))
}

// MARK: - directory transcript (§3.3)

public struct DirectoryDevice: Sendable {
    public var deviceID: String
    public var kind: String
    public var status: String
    public var hpkeKEM: String
    public var hpkePublicKey: Data
    public var signAlg: String
    public var signPublicKey: Data
    /// Ed25519 renewal public key (§8.4); empty when the device has none.
    public var renewalSignPublicKey: Data
    public var grantsDigest: Data

    public init(deviceID: String, kind: String, status: String,
                hpkeKEM: String, hpkePublicKey: Data,
                signAlg: String, signPublicKey: Data,
                renewalSignPublicKey: Data = Data(),
                grantsDigest: Data) {
        self.deviceID = deviceID
        self.kind = kind
        self.status = status
        self.hpkeKEM = hpkeKEM
        self.hpkePublicKey = hpkePublicKey
        self.signAlg = signAlg
        self.signPublicKey = signPublicKey
        self.renewalSignPublicKey = renewalSignPublicKey
        self.grantsDigest = grantsDigest
    }
}

public struct DirectoryTranscript: Sendable {
    public var vaultID: String
    public var directoryRevision: UInt64
    public var devices: [DirectoryDevice]

    public init(vaultID: String, directoryRevision: UInt64, devices: [DirectoryDevice]) {
        self.vaultID = vaultID
        self.directoryRevision = directoryRevision
        self.devices = devices
    }
}

private func validateDirectoryDevice(_ d: DirectoryDevice) throws {
    try requireID("device_id", d.deviceID)
    guard d.kind == DeviceKind.ios || d.kind == DeviceKind.cli else {
        throw KeyrefWireError.invalidField("kind must be \"ios\" or \"cli\"")
    }
    guard d.status == DeviceStatus.pending || d.status == DeviceStatus.active || d.status == DeviceStatus.revoked else {
        throw KeyrefWireError.invalidField("status must be \"pending\", \"active\" or \"revoked\"")
    }
    try requireKEM(d.hpkeKEM)
    let kemLen = d.hpkeKEM == KEMName.x25519 ? KeyrefSizes.x25519Key : KeyrefSizes.p256Key
    guard d.hpkePublicKey.count == kemLen else {
        throw KeyrefWireError.invalidField("hpke_public_key must be \(kemLen) bytes for hpke_kem \(d.hpkeKEM)")
    }
    try requireSignAlg(d.signAlg)
    let signLen = d.signAlg == SignAlg.ed25519 ? KeyrefSizes.ed25519Key : KeyrefSizes.p256Key
    guard d.signPublicKey.count == signLen else {
        throw KeyrefWireError.invalidField("sign_public_key must be \(signLen) bytes for sign_alg \(d.signAlg)")
    }
    guard d.renewalSignPublicKey.isEmpty || d.renewalSignPublicKey.count == KeyrefSizes.ed25519Key else {
        throw KeyrefWireError.invalidField("renewal_sign_public_key must be empty or \(KeyrefSizes.ed25519Key) bytes")
    }
    guard d.grantsDigest.count == KeyrefSizes.digest else {
        throw KeyrefWireError.invalidField("grants_digest must be \(KeyrefSizes.digest) bytes")
    }
}

extension DirectoryTranscript {
    public func buildBytes() throws -> Data {
        try requireID("vault_id", vaultID)
        guard directoryRevision >= 1 else {
            throw KeyrefWireError.invalidField("directory_revision must be >= 1")
        }
        let sorted = devices.sorted { $0.deviceID < $1.deviceID }
        var b = begin("directory")
        b.append(contentsOf: vaultID.utf8); b.append(KeyrefEncoding.fieldSeparator)
        KeyrefEncoding.appendU64BE(directoryRevision, to: &b); b.append(KeyrefEncoding.fieldSeparator)
        for (i, d) in sorted.enumerated() {
            try validateDirectoryDevice(d)
            if i > 0 {
                guard d.deviceID != sorted[i - 1].deviceID else {
                    throw KeyrefWireError.invalidField("duplicate device_id in directory")
                }
                b.append(KeyrefEncoding.fieldSeparator)
            }
            b.append(contentsOf: d.deviceID.utf8); b.append(KeyrefEncoding.fieldSeparator)
            b.append(contentsOf: d.kind.utf8); b.append(KeyrefEncoding.fieldSeparator)
            b.append(contentsOf: d.status.utf8); b.append(KeyrefEncoding.fieldSeparator)
            b.append(contentsOf: d.hpkeKEM.utf8); b.append(KeyrefEncoding.fieldSeparator)
            b.append(d.hpkePublicKey); b.append(KeyrefEncoding.fieldSeparator)
            b.append(contentsOf: d.signAlg.utf8); b.append(KeyrefEncoding.fieldSeparator)
            b.append(d.signPublicKey); b.append(KeyrefEncoding.fieldSeparator)
            b.append(d.renewalSignPublicKey); b.append(KeyrefEncoding.fieldSeparator)
            b.append(d.grantsDigest)
        }
        return b
    }
}

// MARK: - pair transcript (§3.4)

public struct PairTranscript: Sendable {
    public var vaultID: String
    public var ownerSignPublicKey: Data
    public var nonce: String  // 16-byte nonce as 32 hex characters
    public var deviceID: String
    public var hpkeKEM: String
    public var hpkePublicKey: Data
    public var signAlg: String
    public var signPublicKey: Data
    public var label: String
    public var grants: [GrantTranscript]

    public init(vaultID: String, ownerSignPublicKey: Data, nonce: String,
                deviceID: String, hpkeKEM: String, hpkePublicKey: Data,
                signAlg: String, signPublicKey: Data, label: String,
                grants: [GrantTranscript]) {
        self.vaultID = vaultID
        self.ownerSignPublicKey = ownerSignPublicKey
        self.nonce = nonce
        self.deviceID = deviceID
        self.hpkeKEM = hpkeKEM
        self.hpkePublicKey = hpkePublicKey
        self.signAlg = signAlg
        self.signPublicKey = signPublicKey
        self.label = label
        self.grants = grants
    }
}

extension PairTranscript {
    public func buildBytes() throws -> Data {
        try requireID("vault_id", vaultID)
        try requireID("nonce", nonce)
        try requireID("device_id", deviceID)
        guard ownerSignPublicKey.count == KeyrefSizes.p256Key, ownerSignPublicKey.first == 0x04 else {
            throw KeyrefWireError.invalidField("owner_sign_public_key must be a \(KeyrefSizes.p256Key)-byte uncompressed P-256 point")
        }
        try requireKEM(hpkeKEM)
        let kemLen = hpkeKEM == KEMName.x25519 ? KeyrefSizes.x25519Key : KeyrefSizes.p256Key
        guard hpkePublicKey.count == kemLen else {
            throw KeyrefWireError.invalidField("hpke_public_key must be \(kemLen) bytes for hpke_kem \(hpkeKEM)")
        }
        try requireSignAlg(signAlg)
        let signLen = signAlg == SignAlg.ed25519 ? KeyrefSizes.ed25519Key : KeyrefSizes.p256Key
        guard signPublicKey.count == signLen else {
            throw KeyrefWireError.invalidField("sign_public_key must be \(signLen) bytes for sign_alg \(signAlg)")
        }
        try requireUTF8(label, maxBytes: labelMaxBytes, name: "label")
        let sorted = sortedGrants(grants)
        for g in sorted {
            guard g.vaultID == vaultID else {
                throw KeyrefWireError.invalidField("grant vault_id does not match the pair transcript")
            }
            guard g.deviceID == deviceID else {
                throw KeyrefWireError.invalidField("grant device_id does not match the paired device")
            }
        }
        var b = begin("pair")
        b.append(contentsOf: vaultID.utf8); b.append(KeyrefEncoding.fieldSeparator)
        b.append(ownerSignPublicKey); b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: nonce.utf8); b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: deviceID.utf8); b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: hpkeKEM.utf8); b.append(KeyrefEncoding.fieldSeparator)
        b.append(hpkePublicKey); b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: signAlg.utf8); b.append(KeyrefEncoding.fieldSeparator)
        b.append(signPublicKey); b.append(KeyrefEncoding.fieldSeparator)
        b.append(Data(label.utf8)); b.append(KeyrefEncoding.fieldSeparator)
        KeyrefEncoding.appendU64BE(UInt64(sorted.count), to: &b); b.append(KeyrefEncoding.fieldSeparator)
        for g in sorted {
            b.append(try g.buildBytes())
        }
        return b
    }
}

// MARK: - simple transcripts (§3.5, §3.6)

/// "KEYREF1" NUL "pair-register" NUL nonce(16 raw) NUL proposed_name
public func buildPairRegisterTranscript(nonce: Data, proposedName: String) throws -> Data {
    guard nonce.count == KeyrefSizes.pairNonce else {
        throw KeyrefWireError.invalidField("nonce must be \(KeyrefSizes.pairNonce) raw bytes")
    }
    try requireUTF8(proposedName, maxBytes: labelMaxBytes, name: "proposed_name")
    var b = begin("pair-register")
    b.append(nonce)
    b.append(KeyrefEncoding.fieldSeparator)
    b.append(Data(proposedName.utf8))
    return b
}

/// "KEYREF1" NUL "session" NUL device_id(hex) NUL challenge(32 raw)
public func buildSessionTranscript(deviceID: String, challenge: Data) throws -> Data {
    try requireID("device_id", deviceID)
    guard challenge.count == KeyrefSizes.challenge else {
        throw KeyrefWireError.invalidField("challenge must be \(KeyrefSizes.challenge) raw bytes")
    }
    var b = begin("session")
    b.append(contentsOf: deviceID.utf8)
    b.append(KeyrefEncoding.fieldSeparator)
    b.append(challenge)
    return b
}

/// "KEYREF1" NUL "vault-delete" NUL vault_id(hex) NUL challenge(32 raw)
public func buildVaultDeleteTranscript(vaultID: String, challenge: Data) throws -> Data {
    try requireID("vault_id", vaultID)
    guard challenge.count == KeyrefSizes.challenge else {
        throw KeyrefWireError.invalidField("challenge must be \(KeyrefSizes.challenge) raw bytes")
    }
    var b = begin("vault-delete")
    b.append(contentsOf: vaultID.utf8)
    b.append(KeyrefEncoding.fieldSeparator)
    b.append(challenge)
    return b
}

/// "KEYREF1" NUL "vault-recovery" NUL vault_id(hex) NUL recovery_wrap NUL
/// recovery_kdf_json(utf-8) NUL recovery_sign_pub
public func buildVaultRecoveryTranscript(vaultID: String, recoveryWrap: Data,
                                         recoveryKDFJSON: String,
                                         recoverySignPub: Data) throws -> Data {
    try requireID("vault_id", vaultID)
    try requireUTF8(recoveryKDFJSON, maxBytes: Int.max, name: "recovery_kdf_json")
    guard recoverySignPub.count == KeyrefSizes.ed25519Key else {
        throw KeyrefWireError.invalidField("recovery_sign_pub must be \(KeyrefSizes.ed25519Key) bytes")
    }
    var b = begin("vault-recovery")
    b.append(contentsOf: vaultID.utf8)
    b.append(KeyrefEncoding.fieldSeparator)
    b.append(recoveryWrap)
    b.append(KeyrefEncoding.fieldSeparator)
    b.append(Data(recoveryKDFJSON.utf8))
    b.append(KeyrefEncoding.fieldSeparator)
    b.append(recoverySignPub)
    return b
}
