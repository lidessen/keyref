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
    /// Execution context (protocol §6.19, review 2026-11): where the
    /// command runs, which file actually executes, which ambient variables
    /// are forwarded, which names hold the injected secret and where the
    /// fd payload goes. Names, paths and templates only — never a value.
    /// Always present; empty when unused.
    public var cwd: String
    public var executable: String
    public var executableReal: String
    public var executableLayers: [String]
    public var passNames: [String]
    public var envNames: [String]
    public var fdTargets: [Int]
    public var fdTemplate: String

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
        case cwd
        case executable
        case executableReal = "executable_real"
        case executableLayers = "executable_layers"
        case passNames = "pass_names"
        case envNames = "env_names"
        case fdTargets = "fd_targets"
        case fdTemplate = "fd_template"
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
        cwd = try c.decode(String.self, forKey: .cwd)
        executable = try c.decode(String.self, forKey: .executable)
        executableReal = try c.decode(String.self, forKey: .executableReal)
        executableLayers = try c.decode([String].self, forKey: .executableLayers)
        passNames = try c.decode([String].self, forKey: .passNames)
        envNames = try c.decode([String].self, forKey: .envNames)
        fdTargets = try c.decode([Int].self, forKey: .fdTargets)
        fdTemplate = try c.decode(String.self, forKey: .fdTemplate)
    }

    /// Internal memberwise for the CLI simulation in tests.
    init(v: Int, cliDeviceID: String, itemID: String, messageID: String = "",
         argv: [String], refs: [String],
         injection: String, hosts: [String], ephemeralKEM: String,
         ephemeralPublicKey: Data, createdAt: Int64,
         cwd: String = "", executable: String = "", executableReal: String = "",
         executableLayers: [String] = [], passNames: [String] = [],
         envNames: [String] = [], fdTargets: [Int] = [], fdTemplate: String = "") {
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
        self.cwd = cwd
        self.executable = executable
        self.executableReal = executableReal
        self.executableLayers = executableLayers
        self.passNames = passNames
        self.envNames = envNames
        self.fdTargets = fdTargets
        self.fdTemplate = fdTemplate
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
                     cliEphemeralPublicKey: Data,
                     requestCiphertext: Data, requestSignature: Data,
                     createdAt: Int64, expiresAt: Int64) -> PendingApproval {
        PendingApproval(approvalID: approvalID, cliDeviceID: cliDeviceID, itemID: itemID,
                        cliEphemeralPublicKey: cliEphemeralPublicKey,
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
    /// §6.21 approved: one_time_enc ‖ one_time_wrapped_key is the one-time
    /// item key wrap for the CLI's ephemeral public key; `decisionSignature`
    /// is the deciding device's signature over the approval-decision
    /// transcript (§3.12, v2 B).
    static func approved(oneTimeEnc: Data, oneTimeWrappedKey: Data,
                         decisionSignature: Data) -> ApprovalDecisionRequest {
        ApprovalDecisionRequest(decision: "approved",
                                oneTimeEnc: oneTimeEnc,
                                oneTimeWrappedKey: oneTimeWrappedKey,
                                decisionSignature: decisionSignature)
    }

    /// §6.21 denied: no wrap — but the decision is still signed
    /// (§3.12, v2 B).
    static func denied(decisionSignature: Data) -> ApprovalDecisionRequest {
        ApprovalDecisionRequest(decision: "denied", oneTimeEnc: nil,
                                oneTimeWrappedKey: nil,
                                decisionSignature: decisionSignature)
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

    /// Re-verifies the CLI's Ed25519 signature over the approval-request
    /// transcript (§3.11, v2 A). The transcript covers the subject, the
    /// expiry, the request's one-time X25519 public key and the digest of
    /// the request ciphertext — so a signature that passes here also
    /// authenticates the key a decider would seal a message to.
    ///
    /// The public key comes from the signed device directory entry for
    /// `pending.cliDeviceID` — never from the mutable devices table alone.
    /// The device must be an active `kind = cli` entry. Requests that fail
    /// here display as invalid and can be ignored.
    public static func verifyRequestSignature(_ pending: PendingApproval,
                                              vaultID: String,
                                              device: KeyrefDirectoryDevice) throws {
        guard device.deviceID == pending.cliDeviceID else {
            throw KeyrefWireError.badSignature
        }
        guard device.kind == DeviceKind.cli,
              device.status == DeviceStatus.active else {
            throw KeyrefWireError.badSignature
        }
        let transcript = try buildApprovalRequestTranscript(ApprovalRequestTranscript(
            vaultID: vaultID,
            cliDeviceID: pending.cliDeviceID,
            subjectKind: pending.isMessageSubject ? ApprovalSubjectKind.message : ApprovalSubjectKind.item,
            subjectID: pending.isMessageSubject ? pending.messageID : pending.itemID,
            expiresAt: UInt64(max(0, pending.expiresAt)),
            cliEphemeralPublicKey: pending.cliEphemeralPublicKey,
            requestCiphertext: pending.requestCiphertext))
        try verifyDeviceSignature(transcript: transcript,
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
        // The row's one-time key must be the one inside the request: the
        // row is what a decider (which never decrypts the request) trusts
        // (§3.11, v2 A).
        guard plaintext.ephemeralPublicKey == pending.cliEphemeralPublicKey else {
            throw KeyrefWireError.invalidField("the request's ephemeral key does not match the approval row")
        }
        try requireID("cli_device_id", plaintext.cliDeviceID)
    }

    /// §6.21 approved decision: wraps the item key to the request's
    /// ephemeral X25519 public key with the §3.7 one-time info —
    /// `keyref v1 <US> one-time-item-key <US> vault_id <US> cli_device_id
    /// <US> item_id <US> approval_id <US> SHA-256(request_ciphertext)` — so
    /// the wrap answers exactly this request for this item (design §8.3
    /// step 3, decision D4). The result is signed over the
    /// approval-decision transcript (§3.12, v2 B): HPKE base mode
    /// authenticates nobody, so the CLI must be able to tell a real
    /// decision from one the server made up.
    public static func approveDecision(vaultID: String, pending: PendingApproval,
                                       plaintext: ApprovalRequestPlaintext,
                                       itemKey: Data,
                                       decisionDeviceID: String,
                                       signer: TranscriptSigner) throws -> ApprovalDecisionRequest {
        let info = try oneTimeItemKeyInfo(vaultID: vaultID,
                                          recipientDeviceID: plaintext.cliDeviceID,
                                          itemID: plaintext.itemID,
                                          approvalID: pending.approvalID,
                                          requestCiphertext: pending.requestCiphertext)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: plaintext.ephemeralKEM,
                                               recipientPublicKey: plaintext.ephemeralPublicKey,
                                               info: info, plaintext: itemKey)
        return try signedDecision(vaultID: vaultID, pending: pending,
                                  decisionDeviceID: decisionDeviceID,
                                  decision: "approved",
                                  oneTimeEnc: enc, oneTimeWrappedKey: ct,
                                  signer: signer)
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
                                              messagePlaintext: Data,
                                              decisionDeviceID: String,
                                              signer: TranscriptSigner) throws -> ApprovalDecisionRequest {
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
        return try signedDecision(vaultID: vaultID, pending: pending,
                                  decisionDeviceID: decisionDeviceID,
                                  decision: "approved",
                                  oneTimeEnc: enc, oneTimeWrappedKey: ct,
                                  signer: signer)
    }

    /// §6.21 denied decision — carries no key material, but is still
    /// signed: a denial the CLI cannot authenticate is not evidence that
    /// the owner refused (§3.12, v2 B).
    public static func denyDecision(vaultID: String, pending: PendingApproval,
                                    decisionDeviceID: String,
                                    signer: TranscriptSigner) throws -> ApprovalDecisionRequest {
        try signedDecision(vaultID: vaultID, pending: pending,
                           decisionDeviceID: decisionDeviceID,
                           decision: "denied",
                           oneTimeEnc: Data(), oneTimeWrappedKey: Data(),
                           signer: signer)
    }

    /// Signs the decision over the approval-decision transcript
    /// (§3.12, v2 B) and returns the request body for
    /// `POST /v1/approvals/{id}/decision`.
    static func signedDecision(vaultID: String, pending: PendingApproval,
                                decisionDeviceID: String, decision: String,
                                oneTimeEnc: Data, oneTimeWrappedKey: Data,
                                signer: TranscriptSigner) throws -> ApprovalDecisionRequest {
        let transcript = try buildApprovalDecisionTranscript(ApprovalDecisionTranscript(
            vaultID: vaultID,
            approvalID: pending.approvalID,
            decisionDeviceID: decisionDeviceID,
            decision: decision,
            requestCiphertext: pending.requestCiphertext,
            oneTimeEnc: oneTimeEnc,
            oneTimeWrappedKey: oneTimeWrappedKey))
        let signature = try signer.sign(transcript)
        if decision == "approved" {
            return .approved(oneTimeEnc: oneTimeEnc, oneTimeWrappedKey: oneTimeWrappedKey,
                             decisionSignature: signature)
        }
        return .denied(decisionSignature: signature)
    }

    private static func requireID(_ name: String, _ v: String) throws {
        guard KeyrefEncoding.isValidID(v) else {
            throw KeyrefWireError.invalidField("\(name) must be 32 lowercase hex characters")
        }
    }
}
