// Audit event envelope (docs/protocol.md §6.23, D12; design §7.7).
//
// Envelope layout: u8 wrap_count ‖ per owner { u16be enc_len ‖ enc ‖
// 48-byte wrapped event key } ‖ nonce(12)‖ct‖tag (AES-GCM of the event
// plaintext under the random event key). MVP wrap_count = 1 (single
// owner); multi-owner extenders keep the format. The event key is wrapped
// to each owner's HPKE public key with the §3.7 audit-event-key info; the
// AES segment AAD binds vault and the reporting device.
import Foundation

/// Plaintext fields of an audit event (design §7.7: no secret values).
/// Field names and types match the Go CLI producer exactly
/// (cli/internal/audit.Event), so the owner decodes its events directly.
public struct AuditEventPayload: Codable, Equatable, Sendable {
    public var time: Int64
    public var deviceID: String
    public var refs: [String]
    public var injection: [String]
    /// argv in placeholder form — never replaced secrets (§7.7).
    public var argv: [String]
    public var allowArgv: Bool
    public var policyResult: String
    public var approvalResult: String?
    /// Device that signed the approval decision behind `approvalResult`
    /// (design v0.8 §14.5/§14.8, protocol §6.22) — the owner or the
    /// delegated decider. Optional: events from before this field, and
    /// runs no approval decided, omit it and still decode.
    public var decisionDeviceID: String?
    public var childExit: Int
    public var redactions: Int

    public init(time: Int64, deviceID: String, refs: [String], injection: [String],
                argv: [String], allowArgv: Bool, policyResult: String,
                approvalResult: String? = nil, decisionDeviceID: String? = nil,
                childExit: Int = 0, redactions: Int = 0) {
        self.time = time
        self.deviceID = deviceID
        self.refs = refs
        self.injection = injection
        self.argv = argv
        self.allowArgv = allowArgv
        self.policyResult = policyResult
        self.approvalResult = approvalResult
        self.decisionDeviceID = decisionDeviceID
        self.childExit = childExit
        self.redactions = redactions
    }

    enum CodingKeys: String, CodingKey {
        case time
        case deviceID = "device_id"
        case refs
        case injection
        case argv
        case allowArgv = "allow_argv"
        case policyResult = "policy_result"
        case approvalResult = "approval_result"
        case decisionDeviceID = "decision_device_id"
        case childExit = "child_exit"
        case redactions
    }
}

public enum AuditEnvelope {
    public static let wrappedKeySize = 48  // 32-byte event key + 16-byte GCM tag
    public static let encHeaderSize = 2    // u16be enc_len

    /// Seals one event to one owner device (MVP wrap_count = 1).
    public static func seal(event: AuditEventPayload, vaultID: String,
                            reportingDeviceID: String,
                            ownerDeviceID: String, ownerHPKEPublicKey: Data) throws -> Data {
        let eventKey = randomKey()
        defer { var k = eventKey; wipe(&k) }

        let aad = try auditAAD(vaultID: vaultID, deviceID: reportingDeviceID)
        let blob = try BlobCrypto.sealBlob(key: eventKey, aad: aad,
                                           plaintext: try WireJSON.encoder.encode(event))
        let info = try hpkeInfo(purpose: KeyrefPurpose.auditEventKey, vaultID: vaultID,
                                recipientDeviceID: ownerDeviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: kemOf(ownerHPKEPublicKey),
                                         recipientPublicKey: ownerHPKEPublicKey,
                                         info: info, plaintext: eventKey)

        var out = Data([1])  // wrap_count
        var lenBytes = Data()
        KeyrefEncoding.appendU64BE(UInt64(enc.count), to: &lenBytes)
        out.append(contentsOf: lenBytes.suffix(2))
        out.append(enc)
        out.append(ct)
        precondition(ct.count == wrappedKeySize, "wrapped event key must be 48 bytes")
        out.append(blob)
        return out
    }

    /// Opens one envelope as the owner and returns the event payload.
    /// `reportingDeviceID` comes from the enclosing row (§6.24) and feeds
    /// the AES-segment AAD.
    public static func open(envelope: Data, vaultID: String,
                            reportingDeviceID: String,
                            owner: OwnerKeys, ownerDeviceID: String) throws -> AuditEventPayload {
        guard envelope.count >= 1 else { throw KeyrefCryptoError.invalidBlob }
        let wrapCount = Int(envelope[envelope.startIndex])
        guard wrapCount >= 1 else { throw KeyrefCryptoError.invalidBlob }
        var offset = envelope.startIndex + 1
        // First pass: walk every wrap record to find where the body starts.
        var wraps: [(enc: Data, wrapped: Data)] = []
        for _ in 0..<wrapCount {
            guard envelope.endIndex >= offset + encHeaderSize else { throw KeyrefCryptoError.invalidBlob }
            let b0 = Int(envelope[offset]), b1 = Int(envelope[offset + 1])
            let encLen = (b0 << 8) | b1
            offset += encHeaderSize
            guard envelope.endIndex >= offset + encLen + wrappedKeySize else {
                throw KeyrefCryptoError.invalidBlob
            }
            let enc = Data(envelope[offset..<offset + encLen])
            let wrapped = Data(envelope[offset + encLen..<offset + encLen + wrappedKeySize])
            wraps.append((enc: enc, wrapped: wrapped))
            offset += encLen + wrappedKeySize
        }
        // The body (nonce‖ct‖tag) follows ALL wraps.
        let blob = Data(envelope[offset...])
        var lastError: Error = KeyrefCryptoError.invalidBlob
        for (enc, wrapped) in wraps {
            do {
                let info = try hpkeInfo(purpose: KeyrefPurpose.auditEventKey, vaultID: vaultID,
                                        recipientDeviceID: ownerDeviceID)
                let eventKey = try owner.unwrap(info: info, enc: enc, ct: wrapped)
                let aad = try auditAAD(vaultID: vaultID, deviceID: reportingDeviceID)
                let plaintext = try BlobCrypto.openBlob(key: eventKey, aad: aad, blob: blob)
                return try WireJSON.decoder.decode(AuditEventPayload.self, from: plaintext)
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    /// KEM selection by encoded public-key length (§1.4).
    static func kemOf(_ publicKey: Data) -> String {
        publicKey.count == KeyrefSizes.x25519Key ? KEMName.x25519 : KEMName.p256
    }
}

/// Best-effort zeroization of a key buffer (design §12.2 analogue on
/// Swift: CryptoKit SymmetricKey wipes on dealloc; explicit wipes cover
/// Data copies we hand around).
public func wipe(_ data: inout Data) {
    data.resetBytes(in: data.startIndex..<data.endIndex)
}
