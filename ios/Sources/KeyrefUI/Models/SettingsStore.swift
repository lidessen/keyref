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

    // v0.7（§6.7、§8.4）：iCloud 副本开关与轮换提醒。两个都是用户偏好
    // （不是密钥材料），UserDefaults 持久化——否则重启后开关回到默认值，
    // 与 backend 实际行为脱节。
    public var cloudBackupOn = UserDefaults.standard.object(
        forKey: SettingsStore.PrefKeys.cloudBackupOn) as? Bool ?? true {
        didSet { UserDefaults.standard.set(cloudBackupOn, forKey: SettingsStore.PrefKeys.cloudBackupOn) }
    }
    public var rotationReminderOn = UserDefaults.standard.object(
        forKey: SettingsStore.PrefKeys.rotationReminderOn) as? Bool ?? false {
        didSet {
            UserDefaults.standard.set(rotationReminderOn, forKey: SettingsStore.PrefKeys.rotationReminderOn)
            if rotationReminderOn, !oldValue {
                UserDefaults.standard.set(Self.nowMillis(), forKey: SettingsStore.PrefKeys.rotationEnabledAt)
            }
        }
    }

    enum PrefKeys {
        static let cloudBackupOn = "settings.cloudBackupOn"
        static let rotationReminderOn = "settings.rotationReminderOn"
        static let lastRotationAt = "settings.lastRotationAt"
        static let rotationEnabledAt = "settings.rotationEnabledAt"
    }

    public static func nowMillis() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    /// §8.4：一轮轮换（条目密钥或恢复码全套）成功完成后记录时间——90 天
    /// 提醒与 RotationPolicy.due 的基准。
    public func markRotationCompleted() {
        UserDefaults.standard.set(Self.nowMillis(), forKey: PrefKeys.lastRotationAt)
    }

    /// §8.4 90 天提醒：解锁时检查一次。开了提醒且到期 → toast 提示并把
    /// 基准推进到当前（下一次提醒在 90 天后）。
    public func consumeRotationReminder(now: Int64 = SettingsStore.nowMillis()) {
        guard rotationReminderOn else { return }
        let last = UserDefaults.standard.object(forKey: PrefKeys.lastRotationAt) as? Int64
        let enabledAt = UserDefaults.standard.object(forKey: PrefKeys.rotationEnabledAt) as? Int64
        guard RotationPolicy.due(lastRotationAtMillis: last, enabledAtMillis: enabledAt,
                                 nowMillis: now) else { return }
        toast = "同步条目的密钥已超过 90 天未轮换，建议去「设置 → 轮换条目密钥」。"
        UserDefaults.standard.set(now, forKey: PrefKeys.lastRotationAt)
    }

    public init(backend: any AppBackend, haptics: any Haptics,
                autoLock: AutoLockInterval = .oneMinute) {
        self.backend = backend
        self.haptics = haptics
        self.autoLock = autoLock
        // 持久化的开关值在启动时推给 backend（backend 默认 true）——否则
        // 重启后开关为关，快照仍会上传。AppModel 在任何上传之前构造本对象。
        backend.setCloudBackupEnabled(cloudBackupOn)
    }

    public var originDisplay: String { backend.origin.absoluteString }

    /// S10: 官方托管 / 自托管 origin 归属。
    public var hostedBadge: String {
        isHosted ? "官方托管 · 只保存密文，受免费档配额约束"
                 : "自托管 · 密文送到你指定的服务器，端到端加密不变"
    }

    /// 只给窄格子用的短标签（摘要卡的「托管」一栏放不下长句）。
    public var hostedShortBadge: String {
        isHosted ? "官方托管" : "自托管"
    }

    public var isHosted: Bool {
        if let account { return account.isHosted }
        return backend.origin.host?.hasSuffix("keyref.app") ?? false
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
            // B5 轮换了全部条目密钥——90 天提醒的基准从现在起算。只换包裹
            // 层（VMK）不动条目密钥，不计入。
            if full { markRotationCompleted() }
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
