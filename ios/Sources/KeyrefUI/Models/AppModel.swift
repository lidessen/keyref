// Root app state (docs/ios-ui.md §1, §2.3): the phase machine that decides
// between onboarding (S1), the self-drawn lock screen (S2/S3/S4) and the
// unlocked tab view — plus automatic locking on background (§9.5).
import Foundation
import SwiftUI
import KeyrefCore

public enum AppPhase: Equatable, Sendable {
    case booting
    case onboarding   // S1: 未创建保险库
    case locked
    case unlocked
}

/// What the lock screen renders. S3 and S4 are two different failure faces
/// and must look different (§2.3).
public enum LockDisplay: Equatable, Sendable {
    /// S2: 已锁定，等待 Face ID。
    case waiting
    /// S3: Face ID 没有识别成功，再试一次即可。
    case biometricFailed(attempts: Int)
    /// S4: 本机包裹已失效 — only the recovery-code rebuild path.
    case wrapInvalid
}

@Observable
@MainActor
public final class AppModel {
    public let backend: any AppBackend
    public let authenticator: any BiometricAuthenticator
    public let haptics: any Haptics
    public let clipboard: any Clipboard
    public let systemOpener: any SystemOpener

    public private(set) var phase: AppPhase = .booting
    public private(set) var lockDisplay: LockDisplay = .waiting
    /// S4 lock screen → 2.13 本机重建流程入口。
    public var showRecoveryFromLock = false
    /// Tab selection (drives cross-tab deep links, e.g. S11 → 2.15).
    public var selectedTab = 0
    /// 配对核对页「先迁移服务器」→ 请求打开设置的服务器页（2.15）。
    public var requestServerMigration = false
    private var biometricAttempts = 0
    private var backgroundedAt: Date?

    public let items: ItemsStore
    public let devices: DevicesStore
    public let audit: AuditStore
    public let settings: SettingsStore
    /// 审批收件箱（Phase 2, §8.3）：前台轮询 + 待审批角标。
    public let approvals: ApprovalsStore
    /// APNs 注册状态机（Phase 2, §13）：解锁且已配对后注册；推送响应经
    /// AppDelegate 汇聚到 handleApprovalPush。App 注入真机驱动；测试/预览
    /// 注入 fake 或 nil（不注册，轮询兜底）。
    public let push: PushRegistrationStore

    public init(backend: any AppBackend,
                authenticator: any BiometricAuthenticator,
                haptics: any Haptics = NoHaptics(),
                clipboard: any Clipboard = NoClipboard(),
                systemOpener: any SystemOpener = NoSystemOpener(),
                pushDriver: (any PushRegistrationDriver)? = nil,
                pushEnv: String = "sandbox",
                autoLock: AutoLockInterval = .oneMinute) {
        self.backend = backend
        self.authenticator = authenticator
        self.haptics = haptics
        self.clipboard = clipboard
        self.systemOpener = systemOpener
        self.items = ItemsStore(backend: backend, haptics: haptics)
        self.devices = DevicesStore(backend: backend, haptics: haptics)
        self.audit = AuditStore(backend: backend, haptics: haptics)
        self.settings = SettingsStore(backend: backend, haptics: haptics, autoLock: autoLock)
        self.approvals = ApprovalsStore(backend: backend, haptics: haptics)
        self.push = PushRegistrationStore(backend: backend, driver: pushDriver, env: pushEnv)
    }

    /// Boots the app: reads local state and picks the entry face.
    public func boot() async {
        await backend.loadLocalState()
        if backend.hasVault {
            phase = .locked
            lockDisplay = backend.localWrapInvalid ? .wrapInvalid : .waiting
        } else {
            phase = .onboarding
        }
    }

    /// Refresh every store after unlock. Called once per unlock.
    public func refreshAfterUnlock() async {
        await items.refresh()
        await devices.refresh()
        await settings.refreshAccount()
        await approvals.refresh()
    }

    // MARK: unlock (S2 → S3/S4)

    public func attemptUnlock() async {
        guard phase == .locked else { return }
        let result = await authenticator.authenticate(reason: "解锁 keyref 保险库")
        switch result {
        case .failure(.cancelled), .failure(.notAvailable):
            // The system dialog was dismissed — the self-drawn screen stays.
            lockDisplay = .waiting
            return
        case .failure(.failed), .failure(.other):
            biometricAttempts += 1
            lockDisplay = .biometricFailed(attempts: biometricAttempts)
            haptics.fire(.warning)
        case .success:
            do {
                try await backend.unlockAfterBiometrics()
                phase = .unlocked
                lockDisplay = .waiting
                biometricAttempts = 0
                haptics.fire(.success)
                await refreshAfterUnlock()
                // Fire-and-forget first sync; failures surface in the banner.
                await items.syncNow()
                // 解锁后开始前台审批轮询（§8.3；只在 App 活跃时进行）。
                approvals.setActive(true)
                // APNs：解锁且已配对后注册（§13）；未配对不注册，失败静默，
                // 前台轮询兜底不受影响。
                await push.unlockDidComplete(paired: backend.hasVault)
                // 冷启动 tap 的挂起推送：解锁后立即消费（刷新待审批）。
                await consumePendingPushRefresh()
            } catch LockError.wrapInvalid {
                lockDisplay = .wrapInvalid
            } catch {
                lockDisplay = .wrapInvalid
            }
        }
    }

    // MARK: locking (§9.5: 默认进后台 1 分钟即锁定)

    public func handleScenePhase(_ scenePhase: ScenePhase, now: Date = Date()) {
        switch scenePhase {
        case .background:
            backgroundedAt = now
            approvals.setActive(false)   // 轮询只在 App 活跃时进行（§8.3）
        case .active:
            if let backgroundedAt, phase == .unlocked {
                if now.timeIntervalSince(backgroundedAt) >= settings.autoLock.seconds {
                    lock()
                }
            }
            backgroundedAt = nil
            if phase == .unlocked {
                approvals.setActive(true)
            }
        case .inactive:
            approvals.setActive(false)
        default:
            break
        }
    }

    public func lock() {
        guard phase == .unlocked else { return }
        backend.lock()
        phase = .locked
        lockDisplay = backend.localWrapInvalid ? .wrapInvalid : .waiting
        approvals.setActive(false)
    }

    /// §3.4: 拷贝只存在于明文层 — local-only clipboard, 90-second expiry,
    /// success haptic and the toast copy.
    public func backendCopyPlaintext(_ text: String) {
        clipboard.copy(text, expiresInSeconds: 90)
        haptics.fire(.success)
        items.toast = "已拷贝，90 秒后自动清除"
    }

    /// §3.2 降级路径：相机权限被拒时通往系统设置。
    public func openSystemSettings() {
        systemOpener.openAppSettings()
    }

    /// After a completed delete (2.16) or a fresh boot without a vault.
    public func enterOnboarding() {
        phase = .onboarding
        lockDisplay = .waiting
        biometricAttempts = 0
    }

    /// Test/preview seam: jump straight to a phase.
    func forcePhase(_ p: AppPhase) {
        phase = p
        if p == .locked { lockDisplay = backend.localWrapInvalid ? .wrapInvalid : .waiting }
    }

    /// A vault now exists (creation or recovery completed).
    public func vaultBecameReady(unlock: Bool) async {
        await backend.loadLocalState()
        if unlock {
            phase = .unlocked
            await refreshAfterUnlock()
            await items.syncNow()
            approvals.setActive(true)
            // APNs：配对完成后的首次解锁（创建 / 恢复 / 加入完成的当下，
            // 不在欢迎页弹权限，§13）。
            await push.unlockDidComplete(paired: backend.hasVault)
            await consumePendingPushRefresh()
        } else {
            phase = .locked
            lockDisplay = .waiting
        }
    }

    // MARK: APNs 推送响应（Phase 2, §13）

    /// 推送 tap 冷/热启动时暂存的 approval_id（解锁后立即消费）。
    public private(set) var pendingPushApprovalID: String?

    /// 审批推送到达的汇聚点（前台 willPresent 与后台 tap 的 AppDelegate
    /// 回调都走这里；契约 payload = {"aps":{...},"approval_id":"<id>"}）。
    /// 已解锁：立即触发待审批刷新（与 3 秒轮询互斥防抖）；未解锁：先暂存
    /// approval_id，解锁后立即刷新——轮询兜底路径不受影响。
    public func handleApprovalPush(approvalID: String?) async {
        if let approvalID, !approvalID.isEmpty {
            pendingPushApprovalID = approvalID
        }
        guard phase == .unlocked else { return }
        await consumePendingPushRefresh()
    }

    /// 消费挂起的推送刷新：清掉暂存并立即刷新待审批。
    private func consumePendingPushRefresh() async {
        guard pendingPushApprovalID != nil else { return }
        pendingPushApprovalID = nil
        await approvals.triggerRefresh()
    }
}
