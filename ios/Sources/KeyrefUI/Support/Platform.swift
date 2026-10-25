// Platform services behind injectable protocols (docs/ios-ui.md §3.4, §3.7):
// haptics only mark irreversible moments and check results, clipboard copies
// plaintext locally only with a 90-second expiry, and recovery codes are
// never copyable. iOS-only frameworks are guarded so the target also builds
// on macOS for `swift test`.
import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - haptics (§3.7)

public enum HapticKind: Equatable, Sendable {
    case success        // 解锁成功、回填校验通过、配对完成、接管完成
    case warning        // Face ID 失败、保存命中默认拒绝名单、S11 警示卡出现
    case error          // 删除失败、接管不可回退点之后的失败
    case heavyImpact    // 撤销与删库的最终按钮按下
    case lightImpact    // 明文展开、勾选授予条目
}

public protocol Haptics: Sendable {
    func fire(_ kind: HapticKind)
}

public final class LiveHaptics: Haptics, @unchecked Sendable {
    public init() {}

    public func fire(_ kind: HapticKind) {
        #if os(iOS)
        switch kind {
        case .success: UINotificationFeedbackGenerator().notificationOccurred(.success)
        case .warning: UINotificationFeedbackGenerator().notificationOccurred(.warning)
        case .error: UINotificationFeedbackGenerator().notificationOccurred(.error)
        case .heavyImpact: UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
        case .lightImpact: UIImpactFeedbackGenerator(style: .light).impactOccurred()
        }
        #else
        _ = kind
        #endif
    }
}

/// No-op for tests and previews.
public final class NoHaptics: Haptics, @unchecked Sendable {
    public init() {}
    public func fire(_ kind: HapticKind) { _ = kind }
}

// MARK: - clipboard (§3.4)

/// Plaintext may be copied — local device only, 90-second expiry. The copy
/// button exists only inside the Face ID–gated plaintext layer, so there is
/// no path around the check. Recovery codes never reach this interface.
public protocol Clipboard: Sendable {
    /// Writes text local-only with the given expiry; returns when done.
    func copy(_ text: String, expiresInSeconds: TimeInterval)
}

public final class LiveClipboard: Clipboard, @unchecked Sendable {
    public init() {}

    public func copy(_ text: String, expiresInSeconds: TimeInterval) {
        #if os(iOS)
        UIPasteboard.general.setItems(
            [[UTTypePlainText: text]],
            options: [.localOnly: true,
                      .expirationDate: Date().addingTimeInterval(expiresInSeconds)])
        #else
        _ = text
        _ = expiresInSeconds
        #endif
    }

    #if os(iOS)
    private let UTTypePlainText = "public.utf8-plain-text"
    #endif
}

public final class NoClipboard: Clipboard, @unchecked Sendable {
    public init() {}
    public func copy(_ text: String, expiresInSeconds: TimeInterval) {
        _ = text; _ = expiresInSeconds
    }
}

// MARK: - system surfaces

public protocol SystemOpener: Sendable {
    /// Opens the app's own Settings page (camera permission recovery, §3.2).
    func openAppSettings()
}

public final class LiveSystemOpener: SystemOpener, @unchecked Sendable {
    public init() {}
    public func openAppSettings() {
        #if os(iOS)
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        Task { @MainActor in
            await UIApplication.shared.open(url)
        }
        #endif
    }
}

public final class NoSystemOpener: SystemOpener, @unchecked Sendable {
    public init() {}
    public func openAppSettings() {}
}

// MARK: - local notifications (S14, design §8.4)

/// S14 lands as a local notification 7 days and 1 day before a `use` grant
/// expires (design §8.4: 到期预警是产品的一部分).
public protocol NotificationScheduler: Sendable {
    func scheduleExpiryNotices(deviceLabel: String, itemRef: String,
                               expiresAt: Date)
    func cancelExpiryNotices(itemRef: String, deviceID: String)
}

public final class LiveNotificationScheduler: NotificationScheduler, @unchecked Sendable {
    public init() {}
    public func scheduleExpiryNotices(deviceLabel: String, itemRef: String,
                                      expiresAt: Date) {
        #if os(iOS)
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert]) { _, _ in }
        for (days, body) in [(7, "7 天后到期"), (1, "明天到期")] {
            let fire = expiresAt.addingTimeInterval(-Double(days) * 86_400)
            guard fire > Date() else { continue }
            let content = UNMutableNotificationContent()
            content.title = "授权即将到期"
            content.body = "「\(itemRef)」对 \(deviceLabel) 的授权\(body)。"
            let comps = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute], from: fire)
            let trigger = UNCalendarNotificationTrigger(dateMatching: comps, repeats: false)
            let request = UNNotificationRequest(
                identifier: "expiry-\(itemRef)-\(deviceLabel)-\(days)d",
                content: content, trigger: trigger)
            center.add(request)
        }
        #else
        _ = deviceLabel; _ = itemRef; _ = expiresAt
        #endif
    }

    public func cancelExpiryNotices(itemRef: String, deviceID: String) {
        #if os(iOS)
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [
            "expiry-\(itemRef)-\(deviceID)-7d",
            "expiry-\(itemRef)-\(deviceID)-1d",
        ])
        #else
        _ = itemRef; _ = deviceID
        #endif
    }
}

public final class NoNotificationScheduler: NotificationScheduler, @unchecked Sendable {
    public init() {}
    public func scheduleExpiryNotices(deviceLabel: String, itemRef: String, expiresAt: Date) {
        _ = deviceLabel; _ = itemRef; _ = expiresAt
    }
    public func cancelExpiryNotices(itemRef: String, deviceID: String) {
        _ = itemRef; _ = deviceID
    }
}
