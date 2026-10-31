// APNs 客户端注册状态机（Phase 2, design §13）：解锁且已配对（本地已有
// vault）后才申请通知权限并注册远程通知；AppDelegate 的注册回调回灌到
// 这里。模拟器、拒绝授权、上传失败都只记日志——前台 3 秒轮询是设计的
// 兜底路径（§8.3），任何注册失败都不得破坏它。平台接缝注入：真机 =
// LivePushRegistrationDriver（iOS 专属）；macOS `swift test` / 预览注入
// fake 或 nil。
import Foundation
import KeyrefCore

/// 平台注册接缝。真机实现 = LivePushRegistrationDriver；测试注入 fake。
@MainActor
public protocol PushRegistrationDriver: AnyObject {
    /// 申请 alert 通知权限（沿用现有通知权限逻辑：S14 的
    /// LiveNotificationScheduler 同款 UNUserNotificationCenter alert）。
    /// false = 被拒或出错——轮询兜底，不再打扰用户。
    func requestAlertAuthorization() async -> Bool
    /// 向系统申请 APNs token；token 由 AppDelegate 的
    /// didRegisterForRemoteNotificationsWithDeviceToken 回调送达状态机。
    func registerForRemoteNotifications() async
}

#if os(iOS)
import UIKit
import UserNotifications

/// 真机驱动。模拟器上系统回调会带 "unsupported" / "no valid
/// aps-environment" 失败——状态机按失败记录，下次解锁重试，轮询兜底照常。
@MainActor
public final class LivePushRegistrationDriver: PushRegistrationDriver {
    public init() {}

    public func requestAlertAuthorization() async -> Bool {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        switch settings.authorizationStatus {
        case .authorized, .provisional, .ephemeral:
            return true
        case .notDetermined:
            // 只在这一刻弹系统权限框（配对完成后的首次解锁）；之后每次
            // 解锁走这里都直接读状态，不再打扰。出错按被拒处理（轮询兜底）。
            let granted = (try? await center.requestAuthorization(options: [.alert])) ?? false
            return granted
        default:
            return false  // .denied：轮询兜底
        }
    }

    public func registerForRemoteNotifications() {
        UIApplication.shared.registerForRemoteNotifications()
    }
}
#endif

/// 注册状态机：
///
///     idle ──解锁且已配对──> 权限申请 ──granted──> requesting（已发出系统注册）
///                              └─denied──> denied（轮询兜底；用户在设置里
///                                          授权后下次解锁自愈）
///     requesting ──didRegister──> 上传 token ──204──> uploaded（只注册一次）
///                                   └─失败──> failed（下次解锁重试）
///     requesting ──didFail──> failed（模拟器 / 无凭据的常规路径，记日志）
///     未配对：停在 idle，不注册。
///
/// 系统可能在任何时刻重发 token（轮换、启动时缓存回调）：deviceToken 到达
/// 始终接受并尝试上传，上传成功与否只取决于会话是否有效（LiveBackend 检查）。
@Observable
@MainActor
public final class PushRegistrationStore {
    public enum State: Equatable, Sendable {
        case idle        // 未解锁 / 未配对：不注册
        case requesting  // 已发出系统注册，等待 AppDelegate 回调
        case uploaded    // token 已被服务器确认（204）：不再重复注册
        case denied      // 通知权限被拒：轮询兜底，下次解锁静默重查
        case failed      // 注册回调失败或上传失败：下次解锁重试
    }

    public private(set) var state: State = .idle
    /// registerForRemoteNotifications 的调用次数（「已配对只注册一次」的断言面）。
    public private(set) var registerCalls = 0
    public private(set) var lastTokenHex: String?
    public private(set) var lastError: String?

    private let backend: any AppBackend
    private let driver: (any PushRegistrationDriver)?
    /// APNs 环境（契约："sandbox" | "production"；Debug 构建 = sandbox）。
    private let env: String

    public init(backend: any AppBackend,
                driver: (any PushRegistrationDriver)? = nil,
                env: String = "sandbox") {
        self.backend = backend
        self.driver = driver
        self.env = env
    }

    // MARK: 解锁后的触发点（配对完成后的首次解锁与此后每次解锁）

    /// `paired` = 本地已有 vault（已与服务器配对）。未配对不注册；进行中
    /// （requesting）与已上传（uploaded）不重复；denied / failed / idle
    /// （重新）走注册流程。欢迎页（未配对）永远不会走到弹权限这一步。
    public func unlockDidComplete(paired: Bool) async {
        #if DEBUG
        if KeyrefUITestHooks.skipPushRegistration { return }
        #endif
        guard paired else {
            state = .idle   // 未配对：不注册
            return
        }
        switch state {
        case .requesting, .uploaded:
            return  // 进行中 / 只注册一次
        case .idle, .denied, .failed:
            break   // 首次注册 / 被拒后重查 / 失败后重试
        }
        guard let driver else { return }  // 平台不支持（macOS 测试/预览）：轮询兜底
        guard await driver.requestAlertAuthorization() else {
            state = .denied
            lastError = "通知权限被拒：审批推送不可用，前台轮询兜底。"
            return
        }
        await driver.registerForRemoteNotifications()
        registerCalls += 1
        state = .requesting
    }

    // MARK: AppDelegate 回调

    /// didRegisterForRemoteNotificationsWithDeviceToken → hex → 上传。
    /// 仅会话有效时 backend 才真正发请求（LiveBackend 检查）；204 = uploaded，
    /// 否则静默记 failed——下次解锁后的注册重试，轮询兜底不受影响。
    public func deviceTokenDidArrive(_ token: Data) async {
        let hex = token.map { String(format: "%02x", $0) }.joined()
        lastTokenHex = hex
        if await backend.putPushToken(token: hex, env: env) {
            state = .uploaded
            lastError = nil
        } else {
            state = .failed
            lastError = "push token upload failed; will retry on next unlock"
        }
    }

    /// didFailToRegisterForRemoteNotificationsWithError：模拟器与未配置
    /// APNs 凭据时的常规路径——记日志即可，前台轮询兜底照常；下次解锁重试。
    public func registrationDidFail(_ message: String) {
        guard state == .requesting else { return }
        state = .failed
        lastError = message
    }
}
