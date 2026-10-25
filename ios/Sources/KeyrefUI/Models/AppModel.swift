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

    public init(backend: any AppBackend,
                authenticator: any BiometricAuthenticator,
                haptics: any Haptics = NoHaptics(),
                clipboard: any Clipboard = NoClipboard(),
                systemOpener: any SystemOpener = NoSystemOpener(),
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
        case .active:
            if let backgroundedAt, phase == .unlocked {
                if now.timeIntervalSince(backgroundedAt) >= settings.autoLock.seconds {
                    lock()
                }
            }
            backgroundedAt = nil
        default:
            break
        }
    }

    public func lock() {
        guard phase == .unlocked else { return }
        backend.lock()
        phase = .locked
        lockDisplay = backend.localWrapInvalid ? .wrapInvalid : .waiting
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
        } else {
            phase = .locked
            lockDisplay = .waiting
        }
    }
}
