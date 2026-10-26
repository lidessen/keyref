// keyref iOS app entry: builds the live dependency graph (Keychain-backed
// KeyStore, real LocalAuthentication, local-only clipboard) and hands it to
// the KeyrefUI root view. All product behaviour lives in the KeyrefUI target.
// Phase 2 (§13): the AppDelegate adapts APNs callbacks onto the KeyrefUI
// state machines — device token → PushRegistrationStore, 审批推送 →
// AppModel.handleApprovalPush.
import SwiftUI
import UIKit
import UserNotifications
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
        completionHandler(.noData)
        Task { @MainActor in
            await Self.routeApprovalPush(approvalID)
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
        completionHandler([.banner, .list, .sound])
        Task { @MainActor in
            await Self.routeApprovalPush(approvalID)
        }
    }

    /// 通知中心 tap（热启动）。
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let approvalID = Self.approvalID(in: response.notification.request.content.userInfo)
        completionHandler()
        Task { @MainActor in
            await Self.routeApprovalPush(approvalID)
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
        // §6.6：仅本机条目的 secret 密文落 SQLite（Application Support 下，
        // 内容全部是密文）；打不开时退回内存实现（本次运行内有效，见
        // LocalSecretStore.swift 的降级说明）——绝不阻塞启动。
        let localSecrets: LocalSecretStore
        do {
            let support = FileManager.default.urls(for: .applicationSupportDirectory,
                                                   in: .userDomainMask)[0]
                .appendingPathComponent("Keyref", isDirectory: true)
            localSecrets = try SQLiteLocalSecretStore(
                fileURL: support.appendingPathComponent("local-secrets.sqlite"))
        } catch {
            localSecrets = InMemoryLocalSecretStore()
        }
        let backend = LiveBackend(
            keyStore: KeychainKeyStore(service: "app.keyref.ios"),
            stateStore: UIStateStore(),
            origin: URL(string: "https://sync.keyref.app")!,
            localSecrets: localSecrets,
            // §6.7：iCloud 整文件副本（CloudKit；无 iCloud 账号时按设计
            // 降级为「副本不可用」，本地功能不受影响）。
            snapshotStore: CloudKitSnapshotStore(),
            // §8.4 到期预警通知（7 天 / 1 天前）。
            notifications: LiveNotificationScheduler())
        _app = State(initialValue: AppModel(
            backend: backend,
            authenticator: LiveBiometricAuthenticator(),
            haptics: LiveHaptics(),
            clipboard: LiveClipboard(),
            systemOpener: LiveSystemOpener(),
            pushDriver: LivePushRegistrationDriver(),
            pushEnv: Self.pushEnv))
        AppDelegate.wire(model: app)
    }

    var body: some Scene {
        WindowGroup {
            RootView(app: app)
                .tint(.orange)
        }
    }
}
