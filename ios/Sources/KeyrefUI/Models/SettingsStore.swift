// Settings tab state (docs/ios-ui.md §2.14–§2.17): origin display (S10) and
// its change/migration flow, plan and quota (S12/S13), auto-lock, the VMK /
// recovery-code rotations (§8.4) and the two-step vault delete (§2.16).
import Foundation
import KeyrefCore

/// 自动锁定间隔（§9.5：默认 1 分钟，设置里可调）。
public enum AutoLockInterval: String, CaseIterable, Equatable, Sendable {
    case immediate
    case oneMinute
    case fiveMinutes

    public var label: String {
        switch self {
        case .immediate: return "立即"
        case .oneMinute: return "1 分钟"
        case .fiveMinutes: return "5 分钟"
        }
    }

    public var seconds: TimeInterval {
        switch self {
        case .immediate: return 0
        case .oneMinute: return 60
        case .fiveMinutes: return 300
        }
    }
}

@Observable
@MainActor
public final class SettingsStore {
    let backend: any AppBackend
    let haptics: any Haptics

    public var autoLock: AutoLockInterval
    public private(set) var account: AccountSnapshot?
    public var toast: String?

    // 服务器修改（§2.15）
    public var newOriginText = ""
    public private(set) var migrating = false
    public private(set) var migrationStep: MigrationStep?
    public private(set) var migrationFailed: String?

    // 删除保险库（§2.16 两步）
    public var deleteConfirmText = ""
    public private(set) var deleting = false
    public private(set) var deleteFailed: String?
    /// 绝不显示「已删除」，除非服务器确认成功（§2.16）。
    public private(set) var deleteConfirmed = false

    // 轮换 VMK 与恢复码 / 怀疑恢复码泄露（§8.4, S9）
    public private(set) var newRecoveryCode: String?
    public private(set) var rotating = false

    // v0.7（§6.7、§8.4）：iCloud 副本开关与轮换提醒。
    public var cloudBackupOn = true
    public var rotationReminderOn = false

    public init(backend: any AppBackend, haptics: any Haptics,
                autoLock: AutoLockInterval = .oneMinute) {
        self.backend = backend
        self.haptics = haptics
        self.autoLock = autoLock
    }

    public var originDisplay: String { backend.origin.absoluteString }

    /// S10: 官方托管 / 自托管 origin 归属。
    public var hostedBadge: String {
        let hosted: Bool
        if let account {
            hosted = account.isHosted
        } else {
            hosted = backend.origin.host?.hasSuffix("keyref.app") ?? false
        }
        return hosted ? "官方托管 · 只保存密文，受免费档配额约束"
                      : "自托管 · 密文送到你指定的服务器，端到端加密不变"
    }

    public var planLabel: String {
        account?.plan == "free" || account == nil ? "免费档" : (account?.plan ?? "免费档")
    }

    // MARK: origin edit (§2.15)

    public static func isValidOrigin(_ text: String) -> Bool {
        guard let url = URL(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased() else { return false }
        return scheme == "https" && url.host != nil
    }

    /// 正式构建拒绝 http:// 与自签证书（§10.4）。
    public var originInlineError: String? {
        let text = newOriginText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        guard let url = URL(string: text), url.host != nil else {
            return "不是一个有效的地址。"
        }
        if url.scheme?.lowercased() != "https" {
            return "正式版只接受系统信任的 HTTPS。"
        }
        return nil
    }

    public func applyOrigin() async {
        guard let url = URL(string: newOriginText.trimmingCharacters(in: .whitespacesAndNewlines)),
              Self.isValidOrigin(newOriginText) else { return }
        migrating = true
        migrationFailed = nil
        defer { migrating = false }
        do {
            try await backend.switchOrigin(to: url) { [weak self] step in
                Task { @MainActor in
                    self?.migrationStep = step
                }
            }
            migrationStep = nil
            toast = "已迁移"
        } catch {
            migrationFailed = "迁移没有完成，旧服务器上的数据没有变化。请重试。"
        }
    }

    // MARK: account / quota (S12/S13)

    public func refreshAccount() async {
        account = await backend.fetchAccountSnapshot()
    }

    // MARK: rotations (§8.4)

    /// 「轮换 VMK 与恢复码」— 只换包裹层，条目密文不动。
    @discardableResult
    public func rotateVMKAndRecovery(authenticator: any BiometricAuthenticator) async -> Bool {
        await rotateRecovery(full: false, reason: "轮换主密钥包裹层", authenticator: authenticator)
    }

    /// 「怀疑恢复码泄露」— 轮换全部条目密钥并重加密（B5）。
    @discardableResult
    public func rotateRecoveryCodeFull(authenticator: any BiometricAuthenticator) async -> Bool {
        await rotateRecovery(full: true, reason: "替换恢复码并轮换全部条目密钥", authenticator: authenticator)
    }

    func rotateRecovery(full: Bool, reason: String,
                        authenticator: any BiometricAuthenticator) async -> Bool {
        let result = await authenticator.authenticate(reason: reason)
        guard case .success = result else {
            haptics.fire(.warning)
            return false
        }
        rotating = true
        defer { rotating = false }
        do {
            let code = full ? try await backend.rotateRecoveryCodeFull()
                            : try await backend.rotateVMKAndRecovery()
            newRecoveryCode = code
            haptics.fire(.success)
            return true
        } catch {
            haptics.fire(.error)
            toast = "轮换没有完成，请重试。"
            return false
        }
    }

    // MARK: delete vault (§2.16)

    public var deleteConfirmValid: Bool {
        // 手动输入「删除」两个字（不可粘贴）。
        deleteConfirmText == "删除"
    }

    /// Returns true only when the server confirmed success (§2.16 失败态).
    @discardableResult
    public func deleteVault(authenticator: any BiometricAuthenticator) async -> Bool {
        guard deleteConfirmValid else { return false }
        haptics.fire(.heavyImpact)
        let result = await authenticator.authenticate(reason: "删除整个保险库")
        guard case .success = result else {
            haptics.fire(.warning)
            return false
        }
        deleting = true
        deleteFailed = nil
        defer { deleting = false }
        do {
            try await backend.deleteVault()
            deleteConfirmed = true
            haptics.fire(.success)
            return true
        } catch {
            // 「删除没有完成，数据还在。请重试。」
            deleteFailed = "删除没有完成，数据还在。请重试。"
            haptics.fire(.error)
            return false
        }
    }
}
