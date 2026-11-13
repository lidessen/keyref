// Owner-side item cryptography (docs/design.md §6.1, §9): seal and open
// item meta/secret ciphertexts, wrap and unwrap vault keys with the VMK,
// and build the signed item rows the server stores. Mirrors the Go
// cli/internal/itemcrypt and cli/internal/testowner paths on the wire
// formats of docs/protocol.md §1.5, §3.1, §3.7.
import Foundation

// MARK: - plaintext models (design §6.1)

public struct ItemPolicy: Codable, Equatable, Sendable {
    public var sensitivity: String
    public var commandPolicy: String
    public var allowCommands: [String]
    public var allowedHosts: [String]
    public var allowArgv: Bool

    public init(sensitivity: String = "standard", commandPolicy: String = "deny-shells",
                allowCommands: [String] = [], allowedHosts: [String] = [],
                allowArgv: Bool = false) {
        self.sensitivity = sensitivity
        self.commandPolicy = commandPolicy
        self.allowCommands = allowCommands
        self.allowedHosts = allowedHosts
        self.allowArgv = allowArgv
    }
}

public struct ItemMeta: Codable, Equatable, Sendable {
    public var v: Int
    public var ref: String
    public var name: String
    public var description: String
    public var type: String
    public var masked: String
    public var injectable: Bool
    public var policy: ItemPolicy

    public init(v: Int = 1, ref: String, name: String, description: String,
                type: String, masked: String, injectable: Bool, policy: ItemPolicy) {
        self.v = v
        self.ref = ref
        self.name = name
        self.description = description
        self.type = type
        self.masked = masked
        self.injectable = injectable
        self.policy = policy
    }
}

public struct SecretPlaintext: Codable, Equatable, Sendable {
    public var v: Int
    public var value: String
    public var username: String
    public var notes: String
    public var fields: [String: String]

    public init(v: Int = 1, value: String, username: String = "", notes: String = "",
                fields: [String: String] = [:]) {
        self.v = v
        self.value = value
        self.username = username
        self.notes = notes
        self.fields = fields
    }
}

public enum ItemCrypto {
    // MARK: JSON coding of plaintexts

    public static func encodeMeta(_ meta: ItemMeta) throws -> Data {
        try JSONEncoder().encode(meta)
    }

    public static func decodeMeta(_ data: Data) throws -> ItemMeta {
        try JSONDecoder().decode(ItemMeta.self, from: data)
    }

    public static func encodeSecret(_ secret: SecretPlaintext) throws -> Data {
        try JSONEncoder().encode(secret)
    }

    public static func decodeSecret(_ data: Data) throws -> SecretPlaintext {
        try JSONDecoder().decode(SecretPlaintext.self, from: data)
    }

    // MARK: item ciphertexts (§1.5, §3.7 — AAD binds vault + item, not revision)

    public static func sealMeta(key: Data, meta: ItemMeta, vaultID: String, itemID: String) throws -> Data {
        try BlobCrypto.sealBlob(key: key, aad: metaAAD(vaultID: vaultID, itemID: itemID),
                                plaintext: encodeMeta(meta))
    }

    public static func openMeta(key: Data, blob: Data, vaultID: String, itemID: String) throws -> ItemMeta {
        try decodeMeta(try BlobCrypto.openBlob(key: key, aad: metaAAD(vaultID: vaultID, itemID: itemID), blob: blob))
    }

    public static func sealSecret(key: Data, secret: SecretPlaintext, vaultID: String, itemID: String) throws -> Data {
        try BlobCrypto.sealBlob(key: key, aad: secretAAD(vaultID: vaultID, itemID: itemID),
                                plaintext: encodeSecret(secret))
    }

    public static func openSecret(key: Data, blob: Data, vaultID: String, itemID: String) throws -> SecretPlaintext {
        try decodeSecret(try BlobCrypto.openBlob(key: key, aad: secretAAD(vaultID: vaultID, itemID: itemID), blob: blob))
    }

    // MARK: vault-wrapped keys (§3.1: vault_wrapped_meta_key / vault_wrapped_item_key)

    public static func wrapMetaKeyWithVMK(vmk: Data, metaKey: Data, vaultID: String, itemID: String) throws -> Data {
        try BlobCrypto.sealBlob(key: vmk, aad: vaultWrappedMetaKeyAAD(vaultID: vaultID, itemID: itemID), plaintext: metaKey)
    }

    public static func wrapItemKeyWithVMK(vmk: Data, itemKey: Data, vaultID: String, itemID: String) throws -> Data {
        try BlobCrypto.sealBlob(key: vmk, aad: vaultWrappedItemKeyAAD(vaultID: vaultID, itemID: itemID), plaintext: itemKey)
    }

    public static func unwrapMetaKey(vmk: Data, blob: Data, vaultID: String, itemID: String) throws -> Data {
        try BlobCrypto.openBlob(key: vmk, aad: vaultWrappedMetaKeyAAD(vaultID: vaultID, itemID: itemID), blob: blob)
    }

    public static func unwrapItemKey(vmk: Data, blob: Data, vaultID: String, itemID: String) throws -> Data {
        try BlobCrypto.openBlob(key: vmk, aad: vaultWrappedItemKeyAAD(vaultID: vaultID, itemID: itemID), blob: blob)
    }

    // MARK: grant wrapping (§3.2)

    /// Wraps a key for a recipient device (HPKE X25519 to a CLI, or P-256
    /// to another owner) and returns the enc / ct pair for the grant row.
    public static func wrapGrantKey(kemName: String, recipientPublicKey: Data,
                                    kind: String, vaultID: String, recipientDeviceID: String,
                                    key: Data) throws -> (hpkeEnc: Data, wrappedKey: Data) {
        let purpose = kind == GrantKind.view ? KeyrefPurpose.metaKey : KeyrefPurpose.itemKey
        let info = try hpkeInfo(purpose: purpose, vaultID: vaultID, recipientDeviceID: recipientDeviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: kemName, recipientPublicKey: recipientPublicKey,
                                         info: info, plaintext: key)
        return (enc, ct)
    }

    /// Unwraps a granted key for this device (view → meta key, use → item key).
    public static func unwrapGrantKey(kemName: String, receiver: HPKEReceiverKey,
                                      grantKind: String, vaultID: String, deviceID: String,
                                      hpkeEnc: Data, wrappedKey: Data) throws -> Data {
        let purpose: String
        switch grantKind {
        case GrantKind.view: purpose = KeyrefPurpose.metaKey
        case GrantKind.use: purpose = KeyrefPurpose.itemKey
        default: throw KeyrefWireError.invalidField("unknown grant kind")
        }
        let info = try hpkeInfo(purpose: purpose, vaultID: vaultID, recipientDeviceID: deviceID)
        return try KeyrefHPKE.unwrapKey(kemName: kemName, receiver: receiver,
                                  info: info, enc: hpkeEnc, ct: wrappedKey)
    }

    /// Unwraps an approval-driven one-time item key (§7.1, §8.3): the info
    /// binds vault, recipient device, item, approval id and the SHA-256 of
    /// the request ciphertext, so the wrap answers exactly one request.
    public static func unwrapOneTimeItemKey(kemName: String, receiver: HPKEReceiverKey,
                                            vaultID: String, deviceID: String, itemID: String,
                                            approvalID: String, requestCiphertext: Data,
                                            enc: Data, wrappedKey: Data) throws -> Data {
        let info = try oneTimeItemKeyInfo(vaultID: vaultID, recipientDeviceID: deviceID,
                                          itemID: itemID, approvalID: approvalID,
                                          requestCiphertext: requestCiphertext)
        return try KeyrefHPKE.unwrapKey(kemName: kemName, receiver: receiver,
                                  info: info, enc: enc, ct: wrappedKey)
    }

    // MARK: signed item rows (§3.1)

    /// A freshly sealed item plus the transcript and its owner signature,
    /// ready for PUT /v1/items/:item_id.
    public struct SealedItem: Sendable {
        public var transcript: ItemTranscript
        public var signature: Data
        public var metaKey: Data
        public var itemKey: Data
    }

    /// Seals an item under fresh meta/item keys, wraps both under the VMK
    /// and signs the §3.1 transcript.
    public static func sealItem(vaultID: String, itemID: String, revision: UInt64,
                                writerDeviceID: String, vmk: Data,
                                signer: TranscriptSigner,
                                meta: ItemMeta, secret: SecretPlaintext) throws -> SealedItem {
        let metaKey = randomKey()
        let itemKey = randomKey()
        let metaCT = try sealMeta(key: metaKey, meta: meta, vaultID: vaultID, itemID: itemID)
        let secretCT = try sealSecret(key: itemKey, secret: secret, vaultID: vaultID, itemID: itemID)
        let vwMeta = try wrapMetaKeyWithVMK(vmk: vmk, metaKey: metaKey, vaultID: vaultID, itemID: itemID)
        let vwItem = try wrapItemKeyWithVMK(vmk: vmk, itemKey: itemKey, vaultID: vaultID, itemID: itemID)
        let t = ItemTranscript(vaultID: vaultID, itemID: itemID, revision: revision,
                               metaCiphertext: metaCT, secretCiphertext: secretCT,
                               vaultWrappedMetaKey: vwMeta, vaultWrappedItemKey: vwItem,
                               writerDeviceID: writerDeviceID)
        let tb = try t.buildBytes()
        return SealedItem(transcript: t, signature: try signer.sign(tb),
                          metaKey: metaKey, itemKey: itemKey)
    }

    /// Signs a tombstone row: the §3.1 transcript with four zero-length
    /// ciphertext fields (§3.1, §6.11).
    public static func signTombstone(vaultID: String, itemID: String, revision: UInt64,
                                     writerDeviceID: String, signer: TranscriptSigner) throws -> Data {
        try signer.sign(try ItemTranscript.tombstone(vaultID: vaultID, itemID: itemID,
                                                     revision: revision,
                                                     writerDeviceID: writerDeviceID).buildBytes())
    }

    /// Verifies a delivered item row end to end (protocol §3.1 v2 E):
    /// every ciphertext field present in the row must hash to its digest,
    /// then the writer's signature must verify over the digest-form
    /// transcript under the given signing algorithm and key (v2 F: the
    /// writer is the device named by writer_device_id). Fields a CLI view
    /// pruned are covered by their digests alone.
    public static func verifyItemSignature(_ row: ItemData, vaultID: String,
                                           signAlg: String, signPublicKey: Data) throws {
        let fields: [(field: Data, digest: Data)] = [
            (row.metaCiphertext, row.metaDigest),
            (row.secretCiphertext, row.secretDigest),
            (row.vaultWrappedMetaKey, row.vaultWrappedMetaKeyDigest),
            (row.vaultWrappedItemKey, row.vaultWrappedItemKeyDigest),
        ]
        for (field, digest) in fields {
            guard digest.count == KeyrefSizes.digest else {
                throw KeyrefWireError.invalidField("item \(row.itemID): field digest must be \(KeyrefSizes.digest) bytes")
            }
            if !field.isEmpty, itemFieldDigest(field) != digest {
                throw KeyrefWireError.invalidField("item \(row.itemID): field does not match its digest")
            }
        }
        let t = ItemTranscript(vaultID: vaultID, itemID: row.itemID, revision: row.revision,
                               metaCiphertext: row.metaCiphertext,
                               secretCiphertext: row.secretCiphertext,
                               vaultWrappedMetaKey: row.vaultWrappedMetaKey,
                               vaultWrappedItemKey: row.vaultWrappedItemKey,
                               writerDeviceID: row.writerDeviceID,
                               tombstone: row.tombstone)
        try verifyDeviceSignature(transcript: try t.buildBytes(), signature: row.signature,
                                  signAlg: signAlg, publicKey: signPublicKey)
    }

    /// Verifies a grant row's owner signature (§3.2). vaultID is the vault
    /// the row was received for; it is not carried in the JSON.
    public static func verifyGrantSignature(_ row: GrantData, vaultID: String,
                                            ownerSignPublicKey: Data) throws {
        let t = GrantTranscript(vaultID: vaultID, deviceID: row.deviceID, itemID: row.itemID,
                                kind: row.kind, revision: row.revision,
                                expiresAt: UInt64(bitPattern: row.expiresAt),
                                hpkeEnc: row.hpkeEnc, wrappedKey: row.wrappedKey)
        try verifyOwnerSignature(transcript: try t.buildBytes(), signature: row.signature,
                                 ownerSignPublicKey: ownerSignPublicKey)
    }
}

/// 32 random bytes (meta keys, item keys, VMK, event keys).
public func randomKey() -> Data {
    var d = Data(count: 32)
    _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
    return d
}

/// 12 random bytes.
public func randomNonce() -> Data {
    var d = Data(count: BlobCrypto.nonceSize)
    _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, BlobCrypto.nonceSize, $0.baseAddress!) }
    return d
}
