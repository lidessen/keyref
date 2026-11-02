// keyref iOS app entry: builds the live dependency graph (Keychain-backed
// KeyStore, real LocalAuthentication, local-only clipboard) and hands it to
// the KeyrefUI root view. All product behaviour lives in the KeyrefUI target.
// Phase 2 (§13): the AppDelegate adapts APNs callbacks onto the KeyrefUI
// state machines — device token → PushRegistrationStore, 审批推送 →
// AppModel.handleApprovalPush.
import SwiftUI
import UIKit
import UserNotifications
import os.log
import KeyrefCore
import KeyrefUI

/// APNs 回调汇聚点（UIApplicationDelegateAdaptor）：
/// - didRegisterForRemoteNotificationsWithDeviceToken → hex → 注册状态机
///   上传（仅会话有效时；失败静默，下次解锁重试）。
/// - didFailToRegisterForRemoteNotificationsWithError → 记日志（模拟器 /
///   拒绝授权的常规路径），前台 3 秒轮询兜底照常。
/// - 审批推送（payload {"aps":{...},"approval_id":"<id>"}）→ 立即触发
///   待审批刷新：前台经 willPresent 展示，后台 tap 冷/热启动先暂存、
///   解锁后消费。
@MainActor
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    /// KeyrefApp 装配的根模型（回调都在主线程到达）。SwiftUI 可能多次调用
    /// App.init；只有首个 @State 实例存活，因此只接受首次装配。
    private static weak var wiredModel: AppModel?

    /// 装配点（App.init 调用一次；多次调用以首个 @State 实例为准）。
    static func wire(model: AppModel) {
        guard wiredModel == nil else { return }
        wiredModel = model
    }

    private var model: AppModel? { Self.wiredModel }

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    // MARK: 注册回调（§13 注册状态机）

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { await model?.push.deviceTokenDidArrive(deviceToken) }
    }

    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        // 模拟器 / 无 APNs 凭据的常规路径：只记日志，轮询兜底不受影响。
        model?.push.registrationDidFail(error.localizedDescription)
    }

    // MARK: 审批推送响应（Phase 2, §13）

    /// 静默投递 / 后台到达（content-available）：同步取 approval_id 并立即
    /// 应答，再回主线程触发刷新。
    func application(_ application: UIApplication,
                     didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                     fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        let approvalID = Self.approvalID(in: userInfo)
        let messageID = Self.messageID(in: userInfo)
        completionHandler(.noData)
        Task { @MainActor in
            await Self.routeApprovalPush(approvalID)
            await Self.routeMessagePush(messageID)
        }
    }

    // UNUserNotificationCenterDelegate 的要求在 SDK 里是 nonisolated async 且
    // 参数类型非 Sendable——用同步回调形式（nonisolated）实现：同步取
    // approval_id 并立即应答展示，再回主线程触发刷新。

    /// 前台到达：展示 banner 并立即刷新待审批。
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        let approvalID = Self.approvalID(in: notification.request.content.userInfo)
        let messageID = Self.messageID(in: notification.request.content.userInfo)
        completionHandler([.banner, .list, .sound])
        Task { @MainActor in
            await Self.routeApprovalPush(approvalID)
            await Self.routeMessagePush(messageID)
        }
    }

    /// 通知中心 tap（热启动）。
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let approvalID = Self.approvalID(in: response.notification.request.content.userInfo)
        let messageID = Self.messageID(in: response.notification.request.content.userInfo)
        completionHandler()
        Task { @MainActor in
            await Self.routeApprovalPush(approvalID)
            await Self.routeMessagePush(messageID)
        }
    }

    /// 契约：payload = {"aps":{...},"approval_id":"<id>"}。无 approval_id
    /// 的推送不触发刷新。
    private nonisolated static func approvalID(in userInfo: [AnyHashable: Any]) -> String? {
        let id = userInfo["approval_id"] as? String
            ?? (userInfo["aps"] as? [AnyHashable: Any])?["approval_id"] as? String
        guard let id, !id.isEmpty else { return nil }
        return id
    }

    /// 已解锁：立即触发待审批刷新（与 3 秒轮询互斥防抖）；未解锁：暂存
    /// approval_id，解锁后立即消费——轮询兜底路径不受影响。
    private static func routeApprovalPush(_ approvalID: String?) async {
        guard let approvalID else { return }
        await wiredModel?.handleApprovalPush(approvalID: approvalID)
    }

    /// 契约：payload = {"aps":{...},"message_id":"<id>"}（v0.8 §14.4）。
    /// 正文固定为「收到新的验证码」，不带发信号码与短信内容——锁屏是
    /// 半公开表面（B9），所以这里只用来触发刷新。
    private nonisolated static func messageID(in userInfo: [AnyHashable: Any]) -> String? {
        let id = userInfo["message_id"] as? String
            ?? (userInfo["aps"] as? [AnyHashable: Any])?["message_id"] as? String
        guard let id, !id.isEmpty else { return nil }
        return id
    }

    /// 验证码到了：刷新收件箱（未解锁时不拉——消息要本机的隔区密钥才解得开）。
    private static func routeMessagePush(_ messageID: String?) async {
        guard messageID != nil else { return }
        await wiredModel?.handleMessagePush()
    }
}

@main
struct KeyrefApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var app: AppModel

    /// APNs 环境（部署配置）：Debug 构建走 sandbox，发布构建走 production。
    private static var pushEnv: String {
        #if DEBUG
        "sandbox"
        #else
        "production"
        #endif
    }

    init() {
        #if DEBUG
        Self.applyDebugResetIfRequested()
        KeyrefUITestHooks.assumePrerequisitesSatisfied =
            ProcessInfo.processInfo.arguments.contains("-keyref-assume-prerequisites")
        KeyrefUITestHooks.skipPushRegistration =
            ProcessInfo.processInfo.arguments.contains("-keyref-skip-push")
        KeyrefUITestHooks.forceNoCamera =
            ProcessInfo.processInfo.arguments.contains("-keyref-force-no-camera")
        #endif
        // §6.6：仅本机条目的 secret 密文落 SQLite（Application Support 下，
        // 内容全部是密文）；打不开时退回内存实现（本次运行内有效，见
        // LocalSecretStore.swift 的降级说明）——绝不阻塞启动。降级必须
        // 可观测：静默退回内存会让「以为已保存」的仅本机条目在退出后消失。
        let localSecrets: LocalSecretStore
        do {
            let support = FileManager.default.urls(for: .applicationSupportDirectory,
                                                   in: .userDomainMask)[0]
                .appendingPathComponent("Keyref", isDirectory: true)
            localSecrets = try SQLiteLocalSecretStore(
                fileURL: support.appendingPathComponent("local-secrets.sqlite"))
        } catch {
            os_log(.fault, "local secret store unavailable, falling back to in-memory (data will not persist this run): %{public}s",
                   String(describing: error))
            localSecrets = InMemoryLocalSecretStore()
        }
        var origin = URL(string: "https://sync.keyref.app")!
        #if DEBUG
        // UI-test / local-development override (release builds ignore it):
        // `-keyref-origin http://127.0.0.1:<port>` points the app at a
        // local self-hosted server. ATS allows loopback cleartext.
        if let override = Self.debugOriginOverride() { origin = override }
        #endif
        let backend = LiveBackend(
            keyStore: KeychainKeyStore(service: "app.keyref.ios"),
            stateStore: UIStateStore(),
            origin: origin,
            localSecrets: localSecrets,
            // §6.7：iCloud 整文件副本（CloudKit；无 iCloud 账号时按设计
            // 降级为「副本不可用」，本地功能不受影响）。
            snapshotStore: CloudKitSnapshotStore(),
            // §8.4 到期预警通知（7 天 / 1 天前）。
            notifications: LiveNotificationScheduler())
        var authenticator: any BiometricAuthenticator = LiveBiometricAuthenticator()
        #if DEBUG
        // UI-test hook: the simulator has no enrolled Face ID, so pairing /
        // revocation / unlock would block on the system dialog. Compiled out
        // of release builds.
        if ProcessInfo.processInfo.arguments.contains("-keyref-auto-auth") {
            authenticator = UITestAuthenticator()
        }
        #endif
        let model = AppModel(
            backend: backend,
            authenticator: authenticator,
            haptics: LiveHaptics(),
            clipboard: LiveClipboard(),
            systemOpener: LiveSystemOpener(),
            pushDriver: LivePushRegistrationDriver(),
            pushEnv: Self.pushEnv)
        #if DEBUG
        // UI-test hook: start on a given tab (the floating glass tab bar
        // does not accept XCUITest taps in the simulator).
        let args = ProcessInfo.processInfo.arguments
        if let idx = args.firstIndex(of: "-keyref-initial-tab"), idx + 1 < args.count,
           let tab = Int(args[idx + 1]), (0...3).contains(tab) {
            model.selectedTab = tab
        }
        #endif
        _app = State(initialValue: model)
        AppDelegate.wire(model: model)
    }

    var body: some Scene {
        WindowGroup {
            RootView(app: app)
        }
    }

    #if DEBUG
    /// UI-test hooks, compiled out of release builds.
    /// `-keyref-reset` clears every Keychain slot, the app's UserDefaults
    /// and the local secret database so a test starts at the welcome
    /// screen. `-keyref-origin <url>` points the app at a local server.
    private static func applyDebugResetIfRequested() {
        guard ProcessInfo.processInfo.arguments.contains("-keyref-reset") else { return }
        try? KeychainKeyStore(service: "app.keyref.ios").removeAll()
        if let bundle = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: bundle)
        }
        if let support = FileManager.default.urls(for: .applicationSupportDirectory,
                                                  in: .userDomainMask).first {
            try? FileManager.default.removeItem(
                at: support.appendingPathComponent("Keyref", isDirectory: true))
        }
    }

    /// DEBUG-only authenticator for UI automation (no system dialog).
    private struct UITestAuthenticator: BiometricAuthenticator {
        func availability() -> BiometryAvailability { .available }
        func authenticate(reason: String) async -> Result<Void, BiometricError> { .success(()) }
    }

    private static func debugOriginOverride() -> URL? {
        let args = ProcessInfo.processInfo.arguments
        guard let idx = args.firstIndex(of: "-keyref-origin"), idx + 1 < args.count,
              let url = URL(string: args[idx + 1]),
              url.scheme == "http" || url.scheme == "https" else { return nil }
        return url
    }
    #endif
}
