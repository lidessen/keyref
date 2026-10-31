// NEW FILE (v0.7, design §6.6 存储类别 + §8.3 审批): the approval decision
// for 仅本机 items. There is no server-side secret_ciphertext to decrypt
// with a one-time item key, so the decision delivers the secret VALUE
// itself — the decrypted plaintext in the §3.7 secret-JSON wire shape —
// HPKE-wrapped to the CLI's ephemeral public key (§6.6: 审批 decision
// 直接投递 secret 值，CLI 的 RequestSecret 把解开结果当注入值；decision
// 体积上限相应放宽到 96 KiB). The HPKE `info` binding is UNCHANGED
// (purpose `one-time-item-key`, vault/recipient/item/approval_id/request
// digest) — the wrap still answers exactly one request for one item.
import Foundation

public extension ApprovalFlows {
    /// §6.21 approved decision for a 仅本机 item: wraps `secretValueBytes`
    /// (the decrypted secret plaintext in the §3.7 secret-JSON shape) to
    /// the request's ephemeral X25519 public key with the same one-time
    /// info as `approveDecision`. Returns enc ‖ ct in the decision request.
    static func approveSecretDeliveryDecision(vaultID: String, pending: PendingApproval,
                                              plaintext: ApprovalRequestPlaintext,
                                              secretValueBytes: Data) throws -> ApprovalDecisionRequest {
        guard !secretValueBytes.isEmpty else {
            throw KeyrefWireError.invalidField("secret value must not be empty")
        }
        let info = try oneTimeItemKeyInfo(vaultID: vaultID,
                                          recipientDeviceID: plaintext.cliDeviceID,
                                          itemID: plaintext.itemID,
                                          approvalID: pending.approvalID,
                                          requestCiphertext: pending.requestCiphertext)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: plaintext.ephemeralKEM,
                                               recipientPublicKey: plaintext.ephemeralPublicKey,
                                               info: info, plaintext: secretValueBytes)
        return .approved(oneTimeEnc: enc, oneTimeWrappedKey: ct)
    }
}
