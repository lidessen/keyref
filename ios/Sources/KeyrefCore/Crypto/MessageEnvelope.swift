// Message envelope (docs/protocol.md §3.9, D15; design v0.8 §14.3).
//
// Layout:
//
//	u8 wrap_count
//	‖ per record (ordered by device_id hex ascending, no separators):
//	    u16be(32) ‖ device_id(hex ascii) ‖ u16be(enc_len) ‖ enc ‖ wrapped
//	‖ body blob: nonce(12) ‖ ct ‖ tag(16)
//
// One random 256-bit message key encrypts the plaintext JSON
// (AES-256-GCM, AAD binds vault + source device — the source seals before
// the server mints a message_id). The key is HPKE-wrapped once per
// recipient (active owners and delegated deciders) under purpose
// `source-message`, with the recipient's device id pinned inside the
// record — unlike the audit envelope (D12) the recipient set has two
// kinds, so an implicit ordering would not identify who a wrap is for.
//
// `wrapped` is an ordinary HPKE wrap (`enc ‖ ct`, 48 bytes for a 32-byte
// key), exactly like every other wrap in §3.7.
import CryptoKit
import Foundation

/// The §3.9 plaintext carried inside a message envelope.
public struct MessagePlaintext: Codable, Equatable, Sendable {
    public var v: Int
    public var sender: String
    public var body: String
    public var sim: String?
    public var receivedAt: Int64

    public init(v: Int = 1, sender: String, body: String, sim: String? = nil,
                receivedAt: Int64) {
        self.v = v
        self.sender = sender
        self.body = body
        self.sim = sim
        self.receivedAt = receivedAt
    }

    enum CodingKeys: String, CodingKey {
        case v
        case sender
        case body
        case sim
        case receivedAt = "received_at"
    }

    /// Decodes the §3.9 JSON bytes and rejects an unknown version.
    public static func decode(_ raw: Data) throws -> MessagePlaintext {
        let decoded = try WireJSON.decoder.decode(MessagePlaintext.self, from: raw)
        guard decoded.v == 1 else { throw KeyrefCryptoError.invalidBlob }
        return decoded
    }
}

public enum MessageEnvelope {
    /// HPKE ciphertext of one 32-byte message key (32 + 16-byte tag).
    public static let wrappedKeySize = 48
    public static let encHeaderSize = 2
    public static let idSize = 32

    /// One parsed record of an envelope.
    public struct Record: Equatable, Sendable {
        public var deviceID: String
        public var enc: Data
        public var wrapped: Data
    }

    // MARK: - parsing

    /// Splits an envelope into its records and the trailing body blob.
    /// Structural only — nothing is decrypted, so the caller can walk the
    /// recipient list without any key (the decider backfill uses this).
    public static func split(_ envelope: Data) throws -> (records: [Record], body: Data) {
        guard !envelope.isEmpty else { throw KeyrefCryptoError.invalidBlob }
        let count = Int(envelope[envelope.startIndex])
        guard count >= 1 else { throw KeyrefCryptoError.invalidBlob }
        var offset = envelope.startIndex + 1
        var records: [Record] = []
        for _ in 0..<count {
            guard envelope.endIndex - offset >= encHeaderSize else {
                throw KeyrefCryptoError.invalidBlob
            }
            let idLen = (Int(envelope[offset]) << 8) | Int(envelope[offset + 1])
            offset += encHeaderSize
            guard idLen == idSize, envelope.endIndex - offset >= idLen + encHeaderSize else {
                throw KeyrefCryptoError.invalidBlob
            }
            let deviceID = String(decoding: envelope[offset..<offset + idLen], as: UTF8.self)
            offset += idLen
            let encLen = (Int(envelope[offset]) << 8) | Int(envelope[offset + 1])
            offset += encHeaderSize
            guard encLen > 0, envelope.endIndex - offset >= encLen + wrappedKeySize else {
                throw KeyrefCryptoError.invalidBlob
            }
            let enc = Data(envelope[offset..<offset + encLen])
            offset += encLen
            let wrapped = Data(envelope[offset..<offset + wrappedKeySize])
            offset += wrappedKeySize
            guard isValidID(deviceID) else { throw KeyrefCryptoError.invalidBlob }
            records.append(Record(deviceID: deviceID, enc: enc, wrapped: wrapped))
        }
        let body = Data(envelope[offset...])
        guard !body.isEmpty else { throw KeyrefCryptoError.invalidBlob }
        return (records, body)
    }

    // MARK: - opening (owner / decider side)

    /// Opens this device's wrap and returns the 32-byte message key.
    /// `owner` is any device that holds an X25519 or P-256 private key for
    /// its own record — owners today, deciders once they exist.
    public static func openKey(envelope: Data, vaultID: String,
                               ownerDeviceID: String,
                               unwrap: (Data, Data, Data) throws -> Data) throws -> Data {
        let (records, _) = try split(envelope)
        guard let mine = records.first(where: { $0.deviceID == ownerDeviceID }) else {
            // Not sealed to this device: the 24-hour TTL heals the gap for
            // a device that joined later (design §14.3).
            throw KeyrefCryptoError.invalidBlob
        }
        let info = try sourceMessageInfo(vaultID: vaultID, recipientDeviceID: ownerDeviceID)
        let key = try unwrap(info, mine.enc, mine.wrapped)
        guard key.count == 32 else { throw KeyrefCryptoError.invalidBlob }
        return key
    }

    /// Decrypts one message as this owner device and returns the plaintext.
    /// `sourceDeviceID` comes from the enclosing row (§6.29) and feeds the
    /// AES-segment AAD.
    public static func open(envelope: Data, vaultID: String,
                            sourceDeviceID: String,
                            ownerDeviceID: String, owner: OwnerKeys) throws -> MessagePlaintext {
        try MessagePlaintext.decode(openRaw(envelope: envelope, vaultID: vaultID,
                                            sourceDeviceID: sourceDeviceID,
                                            ownerDeviceID: ownerDeviceID, owner: owner))
    }

    /// The decrypted §3.9 JSON bytes, undecoded. The phone sends exactly
    /// these bytes to the CLI when it approves a consumption (D18), so the
    /// approval path needs them before any parsing.
    public static func openRaw(envelope: Data, vaultID: String,
                               sourceDeviceID: String,
                               ownerDeviceID: String, owner: OwnerKeys) throws -> Data {
        let (_, body) = try split(envelope)
        let key = try openKey(envelope: envelope, vaultID: vaultID, ownerDeviceID: ownerDeviceID) {
            info, enc, wrapped in
            try owner.unwrap(info: info, enc: enc, ct: wrapped)
        }
        defer { var k = key; wipe(&k) }
        let aad = try messageAAD(vaultID: vaultID, sourceDeviceID: sourceDeviceID)
        return try BlobCrypto.openBlob(key: key, aad: aad, blob: body)
    }

    // MARK: - sealing

    /// HPKE-wraps one message key to a recipient (owner P-256 or decider
    /// X25519 public key) — the owner-side backfill of §6.30 uses this to
    /// cover a device that paired after the message landed.
    public static func sealKey(vaultID: String, recipientDeviceID: String,
                               recipientPublicKey: Data, messageKey: Data) throws -> Record {
        guard messageKey.count == 32 else { throw KeyrefCryptoError.invalidBlob }
        let info = try sourceMessageInfo(vaultID: vaultID, recipientDeviceID: recipientDeviceID)
        let (enc, wrapped) = try KeyrefHPKE.wrapKey(
            kemName: try kemOf(recipientPublicKey),
            recipientPublicKey: recipientPublicKey,
            info: info, plaintext: messageKey)
        guard wrapped.count == wrappedKeySize else { throw KeyrefCryptoError.invalidBlob }
        return Record(deviceID: recipientDeviceID, enc: enc, wrapped: wrapped)
    }

    /// Encodes one record in the §3.9 byte layout (no separators).
    public static func encode(_ record: Record) throws -> Data {
        guard isValidID(record.deviceID),
              record.enc.count > 0, record.enc.count <= 0xFFFF,
              record.wrapped.count == wrappedKeySize else {
            throw KeyrefCryptoError.invalidBlob
        }
        var out = Data()
        out.append(UInt8((idSize >> 8) & 0xFF)); out.append(UInt8(idSize & 0xFF))
        out.append(contentsOf: record.deviceID.utf8)
        out.append(UInt8((record.enc.count >> 8) & 0xFF)); out.append(UInt8(record.enc.count & 0xFF))
        out.append(record.enc)
        out.append(record.wrapped)
        return out
    }

    // MARK: - helpers

    private static func isValidID(_ s: String) -> Bool {
        guard s.count == 32 else { return false }
        return s.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    /// KEM by public-key length: X25519 (32) or P-256 (65) (§1.4).
    static func kemOf(_ publicKey: Data) throws -> String {
        switch publicKey.count {
        case KeyrefSizes.x25519Key: return KEMName.x25519
        case KeyrefSizes.p256Key: return KEMName.p256
        default: throw KeyrefCryptoError.invalidBlob
        }
    }
}
