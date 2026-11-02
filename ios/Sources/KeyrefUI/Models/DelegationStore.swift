// Auto-approval delegation state (design v0.8 §14.8, docs/ios-ui.md): the
// owner-signed policy the decider evaluates, loaded from
// `GET /v1/delegation` and written back one strictly-greater revision at
// a time. Nothing here is optimistic — a failed save leaves the shown
// state exactly as it was, because the revision the server holds is the
// only thing the next attempt can be built on.
import Foundation
import KeyrefCore

@Observable
@MainActor
public final class DelegationStore {
    let backend: any AppBackend
    let haptics: any Haptics

    /// nil = 服务器上从未有过委托（revision 0）。Installed-but-empty is a
    /// completed withdrawal and comes back as a non-nil state.
    public private(set) var state: DelegationState?
    public private(set) var loading = false
    public private(set) var saving = false
    /// Last failure in plain Chinese; cleared on the next successful load
    /// or save. Never replaced by an optimistic success.
    public private(set) var lastError: String?
    public var toast: String?

    public init(backend: any AppBackend, haptics: any Haptics) {
        self.backend = backend
        self.haptics = haptics
    }

    // MARK: derived

    public var isActive: Bool { state?.isActive == true }

    /// The one-word status the settings row shows.
    public var statusLabel: String { isActive ? "已开启" : "未开启" }

    /// Next revision to PUT: one past whatever the server already has.
    public var nextRevision: UInt64 { (state?.revision ?? 0) + 1 }

    // MARK: load

    public func refresh() async {
        loading = true
        state = await backend.loadDelegation()
        loading = false
        lastError = nil
    }

    // MARK: save / withdraw

    /// Signs and PUTs `policy` at `state.revision + 1`. Returns true only
    /// after the server accepted it; on any failure `state` is untouched
    /// and `lastError` explains what went wrong.
    @discardableResult
    public func save(_ policy: KeyrefDelegationPolicy) async -> Bool {
        guard !saving else { return false }
        saving = true
        defer { saving = false }
        do {
            try policy.validate()
        } catch {
            haptics.fire(.error)
            lastError = "策略里有不允许的取值：发信号码要 1–64 字节，CLI 设备要是 32 位小写十六进制，上限不能是负数。"
            return false
        }
        do {
            let revision = nextRevision
            try await backend.putDelegation(revision: revision, policy: policy)
            // The server already accepted exactly this (revision, policy)
            // pair — recording it is a fact, not an optimistic guess. A
            // failed PUT never reaches this line, so the shown state
            // stays what the server still holds.
            state = DelegationState(revision: revision, policy: policy)
            haptics.fire(.success)
            lastError = nil
            toast = policy.isEmpty ? "委托已撤回" : "委托已保存"
            return true
        } catch {
            haptics.fire(.error)
            lastError = Self.message(for: error)
            return false
        }
    }

    /// 撤回委托 = 签署新的空策略 `{"v":1}`（design §14.8）：没有 sender
    /// 白名单，决策器从此批不了任何东西。
    @discardableResult
    public func withdraw() async -> Bool {
        await save(.revocation)
    }

    private static func message(for error: Error) -> String {
        switch error {
        case APIError.revisionConflict:
            return "服务器上已经有更新的委托版本。重新加载后再改一次。"
        case APIError.badSignature:
            return "签名没有通过服务器校验，委托没有改动。"
        case APIError.forbidden, APIError.unauthorized:
            return "这台设备没有签署委托的权限，委托没有改动。"
        case APIError.deviceRevoked:
            return "这台设备已被撤销，委托没有改动。"
        case APIError.vaultFrozen:
            return "保险库处于冻结状态，暂时不能改委托。"
        case APIError.quotaExceeded:
            return "免费额度已用尽，暂时不能改委托。"
        default:
            return "保存没有完成，委托没有改动。请重试。"
        }
    }
}
