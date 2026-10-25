// Error-code → copy mapping for the sync-failure banner and failure
// detail (docs/ios-ui.md §2.4 table). Server error codes are shown verbatim
// with one Chinese explanation line (§2.0 note).
import Foundation
import KeyrefCore

public enum SyncMessage: Equatable, Sendable {
    case networkUnreachable
    case rateLimited
    case quotaExceeded
    case deviceRevoked
    case verificationRejected
    case other(code: String?, detail: String)

    /// Copy for the failure detail; several cases carry follow-up actions.
    public var headline: String {
        switch self {
        case .networkUnreachable: return "连不上服务器，稍后自动重试。"
        case .rateLimited: return "请求太快被限流，稍后自动重试。"
        case .quotaExceeded: return "免费额度已用尽。"
        case .deviceRevoked: return "这台设备已被撤销。"
        case .verificationRejected: return "服务器返回的数据没有通过校验，已拒绝应用。"
        case .other: return "同步没有完成。"
        }
    }

    public var subline: String? {
        switch self {
        case .deviceRevoked:
            return "接管自另一台手机后，旧手机会走到这里。可以用恢复码重新接管。"
        case .quotaExceeded:
            return "仍可查看与删除。"
        case .verificationRejected:
            return "不自动重试，等下一次手动刷新。"
        case .other(let code, let detail):
            if let code { return "服务器返回 \(code)。\(detail)" }
            return detail.isEmpty ? nil : detail
        default: return nil
        }
    }

    public var isVerification: Bool {
        if case .verificationRejected = self { return true }
        return false
    }

    /// Maps a thrown error from the sync path. `cursor_stale` is handled
    /// silently by the engine (§10.6) and never surfaces here.
    public static func from(_ error: Error) -> SyncMessage {
        switch error {
        case let e as APIError:
            switch e {
            case .transport: return .networkUnreachable
            case .rateLimited: return .rateLimited
            case .quotaExceeded: return .quotaExceeded
            case .deviceRevoked: return .deviceRevoked
            case .badSignature: return .verificationRejected
            case .unexpected: return .other(code: nil, detail: "服务器返回了未知错误。")
            case .unauthorized: return .other(code: "unauthorized", detail: "会话已过期，重新解锁后会自动续期。")
            default:
                return .other(code: errorCodeName(e), detail: "稍后自动重试。")
            }
        default:
            return .networkUnreachable
        }
    }

    private static func errorCodeName(_ e: APIError) -> String? {
        switch e {
        case .invalidJSON: return "invalid_json"
        case .invalidField: return "invalid_field"
        case .forbidden: return "forbidden"
        case .vaultFrozen: return "vault_frozen"
        case .notFound: return "not_found"
        case .revisionConflict: return "revision_conflict"
        case .bodyTooLarge: return "body_too_large"
        case .requestBodyTooLarge: return "body_too_large"
        case .powRequired: return "pow_required"
        case .deleteChallengeRequired: return "delete_challenge_required"
        case .cursorStale: return "cursor_stale"
        case .approvalNotPending: return "approval_not_pending"
        case .pairExpired: return "pair_expired"
        case .unexpected(_, let code): return code
        default: return nil
        }
    }
}
