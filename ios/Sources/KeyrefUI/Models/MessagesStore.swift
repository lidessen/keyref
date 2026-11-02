// SMS inbox state (design v0.8 §14.4, docs/ios-ui.md): the decrypted
// messages pulled from `GET /v1/messages`, grouped by source device, with
// the per-message and clear-all deletes. Every row here already opened with
// this device's key — an envelope sealed before this device paired is
// skipped rather than shown as garbage (§14.3, 24h TTL).
import Foundation
import KeyrefCore

/// One decrypted message ready for the inbox.
public struct MessageInboxEntry: Identifiable, Equatable, Sendable {
    public var messageID: String
    public var sourceDeviceID: String
    /// Plaintext device label from the signed directory (§6.4, §14.4).
    public var sourceLabel: String
    /// The SMS sender as the phone reported it — a reference signal, never
    /// a credential (B9: it can be forged).
    public var sender: String
    /// Full SMS body; the verification code is inside it and the agent
    /// reads it from there (§14.5).
    public var body: String
    public var sim: String
    /// Sender-reported arrival time — display only (§6.29).
    public var receivedAt: Int64
    /// Server `created_at`: the ordering and expiry basis.
    public var createdAt: Int64
    public var expiresAt: Int64
    public var status: String

    public var id: String { messageID }
    public var isActive: Bool { status == "active" }

    /// Remaining lifetime in seconds (0 once expired).
    public func remainingSeconds(now: Date = Date()) -> Int {
        max(0, Int((Double(expiresAt) / 1000 - now.timeIntervalSince1970).rounded()))
    }

    /// 「剩余 N 小时 / N 分钟」（§14.4）. The server already stops serving
    /// expired rows; this is the display-side fallback.
    public func remainingLabel(now: Date = Date()) -> String {
        let s = remainingSeconds(now: now)
        if s <= 0 { return "已过期" }
        if s >= 3600 { return "剩余 \(s / 3600) 小时" }
        return "剩余 \(max(1, s / 60)) 分钟"
    }

    public init(messageID: String, sourceDeviceID: String, sourceLabel: String,
                sender: String, body: String, sim: String = "",
                receivedAt: Int64, createdAt: Int64, expiresAt: Int64,
                status: String = "active") {
        self.messageID = messageID
        self.sourceDeviceID = sourceDeviceID
        self.sourceLabel = sourceLabel
        self.sender = sender
        self.body = body
        self.sim = sim
        self.receivedAt = receivedAt
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.status = status
    }
}

@Observable
@MainActor
public final class MessagesStore {
    /// Newest first (server `created_at`, §6.29).
    public private(set) var entries: [MessageInboxEntry] = []
    public private(set) var loaded = false
    public private(set) var loading = false
    public var toast: String?

    let backend: any AppBackend
    let haptics: any Haptics

    public init(backend: any AppBackend, haptics: any Haptics) {
        self.backend = backend
        self.haptics = haptics
    }

    /// Device labels, in first-appearance order — the inbox groups by them
    /// (§14.4: the plaintext label answers "哪一台手机").
    public var sourceLabels: [String] {
        var seen = Set<String>()
        return entries.compactMap { seen.insert($0.sourceLabel).inserted ? $0.sourceLabel : nil }
    }

    public func entries(from label: String) -> [MessageInboxEntry] {
        entries.filter { $0.sourceLabel == label }
    }

    public func refresh() async {
        guard !loading else { return }
        loading = true
        defer { loading = false }
        entries = await backend.loadMessages()
        loaded = true
    }

    public func delete(_ entry: MessageInboxEntry) async {
        do {
            try await backend.deleteMessage(messageID: entry.messageID)
            entries.removeAll { $0.messageID == entry.messageID }
            haptics.fire(.lightImpact)
        } catch {
            toast = "删除失败，稍后重试。"
        }
    }

    public func clear() async {
        do {
            try await backend.clearMessages()
            entries.removeAll()
            haptics.fire(.warning)
        } catch {
            toast = "清空失败，稍后重试。"
        }
    }
}
