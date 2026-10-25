// Approval inbox state (Phase 2, docs/design.md §8.3, docs/ios-ui.md §5):
// foreground polling of GET /v1/approvals?status=pending at a ≥2 s interval
// (APNs 同批在 Phase 2 上线前轮询兜底，§13；审批轮询不计入每日请求配额，
// §8.3), the decrypted + signature-verified entries, the S8 empty copy, and
// the same-page approve (Face ID) / deny decision.
import Foundation
import KeyrefCore

/// One pending approval ready for display. `valid == false` marks a request
/// that could not be decrypted or whose CLI signature failed against the
/// device directory — it renders as invalid and can be ignored (§8.3).
public struct ApprovalInboxEntry: Identifiable, Equatable, Sendable {
    public var approvalID: String
    public var cliDeviceID: String
    public var cliDeviceLabel: String
    public var itemID: String
    public var itemName: String
    public var itemRef: String
    /// argv 原文，含 {{keyref:REF}} 占位符与 --allow-argv / --reply 模式（§8.3、§7.1）。
    public var argv: [String]
    public var refs: [String]
    public var injection: String
    public var hosts: [String]
    public var createdAt: Int64
    public var expiresAt: Int64
    public var valid: Bool

    public init(approvalID: String, cliDeviceID: String, cliDeviceLabel: String,
                itemID: String, itemName: String, itemRef: String, argv: [String],
                refs: [String], injection: String, hosts: [String],
                createdAt: Int64, expiresAt: Int64, valid: Bool) {
        self.approvalID = approvalID
        self.cliDeviceID = cliDeviceID
        self.cliDeviceLabel = cliDeviceLabel
        self.itemID = itemID
        self.itemName = itemName
        self.itemRef = itemRef
        self.argv = argv
        self.refs = refs
        self.injection = injection
        self.hosts = hosts
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.valid = valid
    }

    public var id: String { approvalID }

    /// 注入方式（env / fd / stdin / argv）的展示名。
    public var injectionLabel: String {
        switch injection {
        case "env": return "环境变量"
        case "fd": return "文件描述符"
        case "stdin": return "标准输入"
        case "argv": return "进程参数"
        default: return injection
        }
    }

    public static func invalid(_ pending: PendingApproval, cliDeviceLabel: String) -> ApprovalInboxEntry {
        ApprovalInboxEntry(approvalID: pending.approvalID,
                           cliDeviceID: pending.cliDeviceID,
                           cliDeviceLabel: cliDeviceLabel,
                           itemID: pending.itemID, itemName: "无效的审批请求",
                           itemRef: "", argv: [], refs: [], injection: "", hosts: [],
                           createdAt: pending.createdAt, expiresAt: pending.expiresAt,
                           valid: false)
    }
}

@Observable
@MainActor
public final class ApprovalsStore {
    /// 轮询间隔 ≥2 秒（§8.3：服务器对更快的轮询直接 429）。Phase 2 没有任何
    /// 假推送——只有这条前台轮询；APNs 是它同批上线的另一个话题，不是这里的
    /// 占位。
    public static let pollInterval: Duration = .seconds(3)

    let backend: any AppBackend
    let haptics: any Haptics

    public private(set) var entries: [ApprovalInboxEntry] = []
    /// 本机忽略的无效请求 id（服务器侧等它自然过期）。
    public private(set) var ignored: Set<String> = []
    public private(set) var lastError: String?
    public private(set) var active = false
    public private(set) var lastRefreshAt: Date?
    public var toast: String?

    private var pollTask: Task<Void, Never>?
    /// 推送触发的进行中刷新（triggerRefresh 的互斥防抖句柄，§13）。
    private var immediateRefreshTask: Task<Void, Never>?

    public init(backend: any AppBackend, haptics: any Haptics) {
        self.backend = backend
        self.haptics = haptics
    }

    // MARK: visibility (轮询只在 App 活跃时进行)

    public func setActive(_ active: Bool) {
        guard self.active != active else { return }
        self.active = active
        if active {
            pollTask?.cancel()
            pollTask = Task { [weak self] in
                await self?.pollLoop()
            }
        } else {
            pollTask?.cancel()
            pollTask = nil
        }
    }

    private func pollLoop(initialDelay: Duration = .zero) async {
        if initialDelay > .zero {
            try? await Task.sleep(for: initialDelay)
            if Task.isCancelled { return }
        }
        while !Task.isCancelled {
            await refresh()
            try? await Task.sleep(for: Self.pollInterval)
        }
    }

    // MARK: push-triggered immediate refresh (Phase 2, §13)

    /// APNs 审批推送到达时的立即刷新，与既有 3 秒轮询互斥防抖：
    /// - 并发触发合并为一次（进行中的刷新不叠加，后来者等它完成）；
    /// - 刷新期间挂起轮询周期，刷新完成后把节拍重置为本次刷新（下一个
    ///   3 秒周期从这里起算）——不会出现「推送刷新 + 轮询刷新」背靠背。
    /// 未激活（轮询没开）时也照常立即刷新；不改变 setActive 的语义。
    public func triggerRefresh() async {
        if let inFlight = immediateRefreshTask {
            await inFlight.value   // 防抖：进行中的刷新不叠加
            return
        }
        pollTask?.cancel()         // 与轮询互斥：挂起既有周期
        let task = Task { [weak self] in _ = await self?.refresh() }
        immediateRefreshTask = task
        _ = await task.value
        immediateRefreshTask = nil
        if active {
            pollTask = Task { [weak self] in
                await self?.pollLoop(initialDelay: Self.pollInterval)
            }
        }
    }

    // MARK: badge & derived

    /// 设备 Tab 的角标数：有效、未忽略、未过期的待审批数。
    public var badgeCount: Int {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        return entries.filter {
            $0.valid && !ignored.contains($0.approvalID) && $0.expiresAt > now
        }.count
    }

    public var displayEntries: [ApprovalInboxEntry] {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        return entries
            .filter { !ignored.contains($0.approvalID) && $0.expiresAt > now }
            .sorted { $0.createdAt < $1.createdAt }
    }

    public func entry(id: String) -> ApprovalInboxEntry? {
        displayEntries.first { $0.approvalID == id }
    }

    // MARK: load

    @discardableResult
    public func refresh() async -> [ApprovalInboxEntry] {
        entries = await backend.loadPendingApprovals()
        lastRefreshAt = Date()
        return entries
    }

    /// 忽略一条无效请求：仅本机隐藏，不提交任何决定（可忽略，§8.3）。
    public func ignore(_ entry: ApprovalInboxEntry) {
        ignored.insert(entry.approvalID)
    }

    // MARK: decision (拒绝同页；批准需 Face ID, §8.3 / ios-ui §5)

    /// Returns true when the decision was submitted. Approve runs Face ID
    /// first; deny needs no key material and goes straight through.
    public func decide(_ entry: ApprovalInboxEntry, approve: Bool,
                       authenticator: any BiometricAuthenticator) async -> Bool {
        if approve {
            let auth = await authenticator.authenticate(reason: "批准这条执行请求")
            guard case .success = auth else {
                haptics.fire(.warning)
                return false
            }
        }
        do {
            try await backend.decideApproval(approvalID: entry.approvalID, approve: approve)
            haptics.fire(.success)
            toast = approve ? "已批准" : "已拒绝"
            await refresh()
            return true
        } catch APIError.approvalNotPending {
            haptics.fire(.error)
            toast = "这个请求已经被处理。"
            await refresh()
            return false
        } catch {
            haptics.fire(.error)
            toast = approve ? "批准没有完成，请重试。" : "拒绝没有完成，请重试。"
            return false
        }
    }
}
