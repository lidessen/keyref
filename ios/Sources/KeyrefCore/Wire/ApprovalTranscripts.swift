// Approval transcripts (docs/protocol.md §3.11–§3.12, protocol v2 A/B).
//
// The CLI signs every approval request, and the deciding device signs
// every decision. Both signatures cover structured fields, never a raw
// ciphertext: the request signature is what authenticates the one-time
// public key a decider seals the SMS plaintext to, and the decision
// signature is what stops the server from handing the CLI a wrap it
// fabricated (HPKE base mode authenticates nobody).
import CryptoKit
import Foundation

/// The subject kinds an approval request can be about (§3.11).
public enum ApprovalSubjectKind {
    public static let item = "item"
    public static let message = "message"
}

/// §3.11 `approval-request`.
public struct ApprovalRequestTranscript: Sendable {
    public var vaultID: String
    public var cliDeviceID: String
    public var subjectKind: String  // "item" | "message"
    public var subjectID: String
    public var expiresAt: UInt64
    public var cliEphemeralPublicKey: Data
    public var requestCiphertext: Data

    public init(vaultID: String, cliDeviceID: String, subjectKind: String, subjectID: String,
                expiresAt: UInt64, cliEphemeralPublicKey: Data, requestCiphertext: Data) {
        self.vaultID = vaultID
        self.cliDeviceID = cliDeviceID
        self.subjectKind = subjectKind
        self.subjectID = subjectID
        self.expiresAt = expiresAt
        self.cliEphemeralPublicKey = cliEphemeralPublicKey
        self.requestCiphertext = requestCiphertext
    }
}

/// Builds `"KEYREF1" NUL "approval-request" NUL vault_id NUL cli_device_id
/// NUL subject_kind NUL subject_id NUL u64be(expires_at) NUL
/// cli_ephemeral_public_key(32 raw) NUL SHA-256(request_ciphertext)`.
public func buildApprovalRequestTranscript(_ t: ApprovalRequestTranscript) throws -> Data {
    try requireID("vault_id", t.vaultID)
    try requireID("cli_device_id", t.cliDeviceID)
    guard t.subjectKind == ApprovalSubjectKind.item || t.subjectKind == ApprovalSubjectKind.message else {
        throw KeyrefWireError.invalidField("subject_kind must be item or message")
    }
    try requireID("subject_id", t.subjectID)
    guard t.expiresAt != 0 else {
        throw KeyrefWireError.invalidField("expires_at must be set")
    }
    guard t.cliEphemeralPublicKey.count == KeyrefSizes.x25519Key else {
        throw KeyrefWireError.invalidField("cli_ephemeral_public_key must be \(KeyrefSizes.x25519Key) bytes")
    }
    guard !t.requestCiphertext.isEmpty else {
        throw KeyrefWireError.invalidField("request_ciphertext must not be empty")
    }
    let digest = Data(SHA256.hash(data: t.requestCiphertext))
    var b = begin("approval-request")
    b.append(contentsOf: t.vaultID.utf8); b.append(KeyrefEncoding.fieldSeparator)
    b.append(contentsOf: t.cliDeviceID.utf8); b.append(KeyrefEncoding.fieldSeparator)
    b.append(contentsOf: t.subjectKind.utf8); b.append(KeyrefEncoding.fieldSeparator)
    b.append(contentsOf: t.subjectID.utf8); b.append(KeyrefEncoding.fieldSeparator)
    KeyrefEncoding.appendU64BE(t.expiresAt, to: &b); b.append(KeyrefEncoding.fieldSeparator)
    b.append(t.cliEphemeralPublicKey); b.append(KeyrefEncoding.fieldSeparator)
    b.append(digest)
    return b
}

/// §3.12 `approval-decision`.
public struct ApprovalDecisionTranscript: Sendable {
    public var vaultID: String
    public var approvalID: String
    public var decisionDeviceID: String
    public var decision: String  // "approved" | "denied"
    public var requestCiphertext: Data
    public var oneTimeEnc: Data
    public var oneTimeWrappedKey: Data

    public init(vaultID: String, approvalID: String, decisionDeviceID: String, decision: String,
                requestCiphertext: Data, oneTimeEnc: Data = Data(),
                oneTimeWrappedKey: Data = Data()) {
        self.vaultID = vaultID
        self.approvalID = approvalID
        self.decisionDeviceID = decisionDeviceID
        self.decision = decision
        self.requestCiphertext = requestCiphertext
        self.oneTimeEnc = oneTimeEnc
        self.oneTimeWrappedKey = oneTimeWrappedKey
    }
}

/// `u16be(len(one_time_enc)) ‖ one_time_enc ‖ one_time_wrapped_key`.
public func packApprovalWrap(enc: Data, wrapped: Data) throws -> Data {
    guard enc.count <= 0xFFFF else {
        throw KeyrefWireError.invalidField("one_time_enc too long")
    }
    var out = Data(capacity: 2 + enc.count + wrapped.count)
    out.append(UInt8((enc.count >> 8) & 0xff))
    out.append(UInt8(enc.count & 0xff))
    out.append(enc)
    out.append(wrapped)
    return out
}

/// Builds `"KEYREF1" NUL "approval-decision" NUL vault_id NUL approval_id
/// NUL decision_device_id NUL decision NUL SHA-256(request_ciphertext) NUL
/// SHA-256(one_time_wrap)`.
public func buildApprovalDecisionTranscript(_ t: ApprovalDecisionTranscript) throws -> Data {
    try requireID("vault_id", t.vaultID)
    try requireID("approval_id", t.approvalID)
    try requireID("decision_device_id", t.decisionDeviceID)
    var wrap = Data()
    switch t.decision {
    case "approved":
        guard !t.oneTimeEnc.isEmpty, !t.oneTimeWrappedKey.isEmpty else {
            throw KeyrefWireError.invalidField("an approved decision must carry the one-time wrap")
        }
        wrap = try packApprovalWrap(enc: t.oneTimeEnc, wrapped: t.oneTimeWrappedKey)
    case "denied":
        guard t.oneTimeEnc.isEmpty, t.oneTimeWrappedKey.isEmpty else {
            throw KeyrefWireError.invalidField("a denied decision carries no wrap")
        }
    default:
        throw KeyrefWireError.invalidField("decision must be approved or denied")
    }
    guard !t.requestCiphertext.isEmpty else {
        throw KeyrefWireError.invalidField("request_ciphertext must not be empty")
    }
    let reqDigest = Data(SHA256.hash(data: t.requestCiphertext))
    let wrapDigest = Data(SHA256.hash(data: wrap))
    var b = begin("approval-decision")
    b.append(contentsOf: t.vaultID.utf8); b.append(KeyrefEncoding.fieldSeparator)
    b.append(contentsOf: t.approvalID.utf8); b.append(KeyrefEncoding.fieldSeparator)
    b.append(contentsOf: t.decisionDeviceID.utf8); b.append(KeyrefEncoding.fieldSeparator)
    b.append(contentsOf: t.decision.utf8); b.append(KeyrefEncoding.fieldSeparator)
    b.append(reqDigest); b.append(KeyrefEncoding.fieldSeparator)
    b.append(wrapDigest)
    return b
}
