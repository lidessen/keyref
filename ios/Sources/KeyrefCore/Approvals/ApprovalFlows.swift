// NEW FILE (Phase 2, design §8.3 / docs/protocol.md §6.19–§6.21, decisions
// D4 & D7): owner-side approval cryptography. The CLI HPKEs its request to
// the owner and Ed25519-signs the ciphertext; this file opens the request,
// re-verifies the CLI signature against the device directory, and builds
// the one-time item-key wrap that answers exactly one request for one item
// (info binds vault, recipient device, item, approval id and the SHA-256 of
// the request ciphertext). Wire additions only — the HTTP calls stay on the
// existing APIClient (§6.20 listApprovals, §6.21 submitApprovalDecision).
import CryptoKit
import Foundation

// MARK: - request plaintext (§6.19)

/// The decrypted approval request. `argv` is the raw command line with
/// `{{keyref:REF}}` placeholders — never substituted secrets (design §7.5,
/// §8.3): `--allow-argv` / `--reply` patterns ride inside argv untouched.
public struct ApprovalRequestPlaintext: Codable, Equatable, Sendable {
    public var v: Int
    public var cliDeviceID: String
    public var itemID: String
    public var argv: [String]
    public var refs: [String]
    public var injection: String
    public var hosts: [String]
    public var ephemeralKEM: String
    public var ephemeralPublicKey: Data
    public var createdAt: Int64
    /// Set for an SMS consumption (design v0.8 §14.5); `itemID` is then
    /// empty. Exactly one subject is present (protocol D16).
    public var messageID: String

    enum CodingKeys: String, CodingKey {
        case v
        case cliDeviceID = "cli_device_id"
        case itemID = "item_id"
        case messageID = "message_id"
        case argv
        case refs
        case injection
        case hosts
        case ephemeralKEM = "ephemeral_kem"
        case ephemeralPublicKey = "ephemeral_public_key"
        case createdAt = "created_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(Int.self, forKey: .v)
        cliDeviceID = try c.decode(String.self, forKey: .cliDeviceID)
        // The CLI omits the subject field it is not using.
        itemID = try c.decodeIfPresent(String.self, forKey: .itemID) ?? ""
        messageID = try c.decodeIfPresent(String.self, forKey: .messageID) ?? ""
        argv = try c.decode([String].self, forKey: .argv)
        refs = try c.decode([String].self, forKey: .refs)
        injection = try c.decode(String.self, forKey: .injection)
        hosts = try c.decode([String].self, forKey: .hosts)
        ephemeralKEM = try c.decode(String.self, forKey: .ephemeralKEM)
        ephemeralPublicKey = try c.decode(Data.self, forKey: .ephemeralPublicKey)
        createdAt = try c.decode(Int64.self, forKey: .createdAt)
    }

    /// Internal memberwise for the CLI simulation in tests.
    init(v: Int, cliDeviceID: String, itemID: String, messageID: String = "",
         argv: [String], refs: [String],
         injection: String, hosts: [String], ephemeralKEM: String,
         ephemeralPublicKey: Data, createdAt: Int64) {
        self.v = v
        self.cliDeviceID = cliDeviceID
        self.itemID = itemID
        self.messageID = messageID
        self.argv = argv
        self.refs = refs
        self.injection = injection
        self.hosts = hosts
        self.ephemeralKEM = ephemeralKEM
        self.ephemeralPublicKey = ephemeralPublicKey
        self.createdAt = createdAt
    }

    /// Decodes from JSON bytes (the HPKE plaintext).
    public static func decode(_ data: Data) throws -> ApprovalRequestPlaintext {
        try WireJSON.decoder.decode(ApprovalRequestPlaintext.self, from: data)
    }
}

// MARK: - public constructors for the wire rows this flow consumes
//
// Same pattern as WireTypes+PublicInits.swift: the synthesized memberwise
// initializers are internal, so the UI builds rows through `make` factories
// instead of same-signature extension inits (which would be ambiguous).

public extension PendingApproval {
    static func make(approvalID: String, cliDeviceID: String, itemID: String,
                     requestCiphertext: Data, requestSignature: Data,
                     createdAt: Int64, expiresAt: Int64) -> PendingApproval {
        PendingApproval(approvalID: approvalID, cliDeviceID: cliDeviceID, itemID: itemID,
                        requestCiphertext: requestCiphertext,
                        requestSignature: requestSignature,
                        createdAt: createdAt, expiresAt: expiresAt)
    }
}

public extension ApprovalListResponse {
    static func make(approvals: [PendingApproval]) -> ApprovalListResponse {
        ApprovalListResponse(approvals: approvals)
    }
}

public extension ApprovalDecisionRequest {
    /// §6.21 同意：one_time_enc ‖ one_time_wrapped_key 是发给 CLI 临时公钥的
    /// 一次性 item key 包裹。
    static func approved(oneTimeEnc: Data, oneTimeWrappedKey: Data) -> ApprovalDecisionRequest {
        ApprovalDecisionRequest(decision: "approved",
                                oneTimeEnc: oneTimeEnc,
                                oneTimeWrappedKey: oneTimeWrappedKey)
    }

    /// §6.21 拒绝：不带包裹。
    static func denied() -> ApprovalDecisionRequest {
        ApprovalDecisionRequest(decision: "denied", oneTimeEnc: nil, oneTimeWrappedKey: nil)
    }
}

// MARK: - the owner-side approval flow

public enum ApprovalFlows {
    /// Opens the request ciphertext for this owner (purpose
    /// `approval-request`, recipient = this owner device, §3.7). The
    /// ciphertext layout is `enc ‖ ct‖tag` (§1.5) where `enc` is the KEM
    /// encapsulation for the RECIPIENT's KEM — P-256 for the owner (65B),
    /// even though the CLI's ephemeral key inside the plaintext is X25519.
    /// A thrown error here means the request is not for us or is corrupt —
    /// the caller shows it as invalid (验不过的请求显示为无效并可忽略).
    public static func openRequest(_ pending: PendingApproval, owner: OwnerKeys,
                                   vaultID: String, ownerDeviceID: String) throws -> ApprovalRequestPlaintext {
        try requireID("vault_id", vaultID)
        try requireID("owner_device_id", ownerDeviceID)
        let encSize = try KeyrefHPKE.publicKeySize(kemName: owner.kemKEMName)
        guard pending.requestCiphertext.count > encSize else {
            throw KeyrefCryptoError.invalidBlob
        }
        let info = try hpkeInfo(purpose: KeyrefPurpose.approvalRequest,
                                vaultID: vaultID, recipientDeviceID: ownerDeviceID)
        let plaintext = try owner.unwrap(info: info,
                                         enc: pending.requestCiphertext.prefix(encSize),
                                         ct: pending.requestCiphertext.dropFirst(encSize))
        return try ApprovalRequestPlaintext.decode(plaintext)
    }

    /// Re-verifies the CLI's Ed25519 signature over the request ciphertext
    /// (decision D7; design §8.3 step 3: 解开后先验签名，通过才展示). The
    /// public key comes from the signed device directory entry for
    /// `pending.cliDeviceID` — never from the mutable devices table alone.
    /// Requests that fail here display as invalid and can be ignored.
    public static func verifyRequestSignature(_ pending: PendingApproval,
                                              device: KeyrefDirectoryDevice) throws {
        guard device.deviceID == pending.cliDeviceID else {
            throw KeyrefWireError.badSignature
        }
        try verifyDeviceSignature(transcript: pending.requestCiphertext,
                                  signature: pending.requestSignature,
                                  signAlg: device.signAlg,
                                  publicKey: device.signPublicKey)
    }

    /// Cross-checks the opened plaintext against the server row (a request
    /// whose inner ids disagree with its own envelope row is invalid).
    /// Exactly one subject must be present and must match the row (D16).
    public static func validatePlaintext(_ plaintext: ApprovalRequestPlaintext,
                                         pending: PendingApproval) throws {
        guard plaintext.v == 1 else {
            throw KeyrefWireError.invalidField("unsupported approval request version")
        }
        guard plaintext.cliDeviceID == pending.cliDeviceID else {
            throw KeyrefWireError.invalidField("approval request ids do not match its envelope row")
        }
        if pending.isMessageSubject {
            guard plaintext.messageID == pending.messageID,
                  plaintext.itemID.isEmpty else {
                throw KeyrefWireError.invalidField("approval request ids do not match its envelope row")
            }
            try requireID("message_id", plaintext.messageID)
        } else {
            guard plaintext.itemID == pending.itemID,
                  plaintext.messageID.isEmpty else {
                throw KeyrefWireError.invalidField("approval request ids do not match its envelope row")
            }
            try requireID("item_id", plaintext.itemID)
        }
        guard plaintext.ephemeralKEM == KEMName.x25519,
              plaintext.ephemeralPublicKey.count == KeyrefSizes.x25519Key else {
            throw KeyrefWireError.invalidField("ephemeral key must be a 32-byte X25519 public key")
        }
        try requireID("cli_device_id", plaintext.cliDeviceID)
    }

    /// §6.21 approved decision: wraps the item key to the request's
    /// ephemeral X25519 public key with the §3.7 one-time info —
    /// `keyref v1 <US> one-time-item-key <US> vault_id <US> cli_device_id
    /// <US> item_id <US> approval_id <US> SHA-256(request_ciphertext)` — so
    /// the wrap answers exactly this request for this item (design §8.3
    /// step 3, decision D4). Returns enc ‖ ct in the decision request.
    public static func approveDecision(vaultID: String, pending: PendingApproval,
                                       plaintext: ApprovalRequestPlaintext,
                                       itemKey: Data) throws -> ApprovalDecisionRequest {
        let info = try oneTimeItemKeyInfo(vaultID: vaultID,
                                          recipientDeviceID: plaintext.cliDeviceID,
                                          itemID: plaintext.itemID,
                                          approvalID: pending.approvalID,
                                          requestCiphertext: pending.requestCiphertext)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: plaintext.ephemeralKEM,
                                               recipientPublicKey: plaintext.ephemeralPublicKey,
                                               info: info, plaintext: itemKey)
        return .approved(oneTimeEnc: enc, oneTimeWrappedKey: ct)
    }

    /// §6.21 / §14.5 approved decision for an SMS consumption.
    ///
    /// The payload is the message's PLAINTEXT JSON, not its key (D18): the
    /// message key never leaves the owner/decider domain, the CLI has no
    /// endpoint to fetch `messages.envelope`, and what the agent needs is
    /// the body. The binding is the same one-time shape with the message id
    /// in the item position, so a decision answers exactly this message and
    /// this request.
    public static func approveMessageDecision(vaultID: String, pending: PendingApproval,
                                              plaintext: ApprovalRequestPlaintext,
                                              messagePlaintext: Data) throws -> ApprovalDecisionRequest {
        guard pending.isMessageSubject else {
            throw KeyrefWireError.invalidField("not a message-subject approval")
        }
        let info = try oneTimeMessageKeyInfo(recipientDeviceID: plaintext.cliDeviceID,
                                             vaultID: vaultID,
                                             messageID: pending.messageID,
                                             approvalID: pending.approvalID,
                                             requestCiphertext: pending.requestCiphertext)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: plaintext.ephemeralKEM,
                                               recipientPublicKey: plaintext.ephemeralPublicKey,
                                               info: info, plaintext: messagePlaintext)
        return .approved(oneTimeEnc: enc, oneTimeWrappedKey: ct)
    }

    /// §6.21 denied decision — carries no key material.
    public static func denyDecision() -> ApprovalDecisionRequest {
        .denied()
    }

    private static func requireID(_ name: String, _ v: String) throws {
        guard KeyrefEncoding.isValidID(v) else {
            throw KeyrefWireError.invalidField("\(name) must be 32 lowercase hex characters")
        }
    }
}
