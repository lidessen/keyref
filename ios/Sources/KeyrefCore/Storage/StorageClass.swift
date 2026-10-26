// NEW FILE (v0.7, design §6.6 存储类别): the user-facing choice of where a
// secret lives. It replaces the old `sensitivity` wording —「要不要审批」对
// 用户是安全术语，「存在哪」不是。`sensitivity` becomes a derived property:
// 同步 ⟹ standard, 仅本机 ⟹ approval (design §6.6 table + server checks:
// local-only items must never carry a `use` grant, and secret_ciphertext is
// mutually exclusive with `use` grants server-side).
import Foundation

public enum StorageClass: String, Equatable, CaseIterable, Sendable {
    /// 同步到服务器：secret 密文上传，恢复码即可找回，可有长期 use 授权。
    case synced
    /// 仅本机：secret 密文只在本机的本地加密存储（服务器行
    /// secret_ciphertext = NULL），每次 exec 审批，永不授予 use。
    case localOnly

    /// The derived §6.1 policy.sensitivity value sealed into item meta.
    public var sensitivity: String {
        switch self {
        case .synced: return "standard"
        case .localOnly: return "approval"
        }
    }

    /// Reads the storage class back from a decrypted meta's sensitivity.
    public init(sensitivity: String) {
        self = sensitivity == "approval" ? .localOnly : .synced
    }

    /// Reads the storage class from a synced item row without decrypting:
    /// the server never stores a secret for local-only items, so a live row
    /// with an empty secret_ciphertext / vault_wrapped_item_key is
    /// local-only (tombstones are excluded).
    public static func of(_ row: ItemData) -> StorageClass {
        if !row.tombstone, !row.metaCiphertext.isEmpty,
           row.secretCiphertext.isEmpty, row.vaultWrappedItemKey.isEmpty {
            return .localOnly
        }
        return .synced
    }

    /// UI wording following the §6.6 table.
    public var label: String {
        switch self {
        case .synced: return "同步到服务器"
        case .localOnly: return "仅本机"
        }
    }
}
