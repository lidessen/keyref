// NEW FILE (v0.7, design §6.6 存储类别 + §8.3 审批): the approval decision
// for 仅本机 items. There is no server-side secret_ciphertext to decrypt
// with a one-time item key, so the decision delivers the item's secret
// ciphertext bytes instead of the item key (§6.6: 审批 decision 直接投递
// secret 密文，HPKE 包给 CLI 临时公钥；decision 体积上限相应放宽到
// 96 KiB). The HPKE `info` binding is UNCHANGED (purpose
// `one-time-item-key`, vault/recipient/item/approval_id/request digest) —
// the wrap still answers exactly one request for one item.
import Foundation

public extension ApprovalFlows {
    /// §6.21 approved decision for a 仅本机 item: wraps `secretCiphertext`
    /// (the AES-GCM(item key) bytes from the local secret store) to the
    /// request's ephemeral X25519 public key with the same one-time info as
    /// `approveDecision`. Returns enc ‖ ct in the decision request.
    static func approveSecretDeliveryDecision(vaultID: String, pending: PendingApproval,
                                              plaintext: ApprovalRequestPlaintext,
                                              secretCiphertext: Data) throws -> ApprovalDecisionRequest {
        guard !secretCiphertext.isEmpty else {
            throw KeyrefWireError.invalidField("secret ciphertext must not be empty")
        }
        let info = try oneTimeItemKeyInfo(vaultID: vaultID,
                                          recipientDeviceID: plaintext.cliDeviceID,
                                          itemID: plaintext.itemID,
                                          approvalID: pending.approvalID,
                                          requestCiphertext: pending.requestCiphertext)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: plaintext.ephemeralKEM,
                                               recipientPublicKey: plaintext.ephemeralPublicKey,
                                               info: info, plaintext: secretCiphertext)
        return .approved(oneTimeEnc: enc, oneTimeWrappedKey: ct)
    }
}
