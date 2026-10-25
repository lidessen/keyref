// Items tab state (docs/ios-ui.md §2.4–§2.6): the decrypted list, the sync
// indicator with its three states, the S6 failure banner with its error-code
// copy mapping, and the new/edit item view model including the §7.3 deny
// list confirmation and the §7.4 paste-leak save check.
import Foundation
import KeyrefCore

public enum SyncDot: Equatable, Sendable {
    case idle
    case syncing
    case offline
    case failed
}

@Observable
@MainActor
public final class ItemsStore {
    let backend: any AppBackend
    let haptics: any Haptics

    public private(set) var rows: [ItemRow] = []
    public var searchText = ""
    public private(set) var syncDot: SyncDot = .idle
    public private(set) var syncFailure: SyncMessage?
    public private(set) var failureAt: Date?
    public private(set) var overQuota = false       // S12
    public private(set) var isFrozen = false        // S13
    public var toast: String?
    /// 底部玻璃胶囊（§3.8 tabViewBottomAccessory）点按 → 列表顶部展开失败
    /// 详情（S6 的展开逻辑保留，只是入口从横幅换成了胶囊）。
    public var showFailureDetail = false

    public init(backend: any AppBackend, haptics: any Haptics) {
        self.backend = backend
        self.haptics = haptics
    }

    public var filtered: [ItemRow] {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return rows }
        // 本地匹配名称 / ref / 描述（服务器没有搜索，§2.2）。
        return rows.filter {
            $0.name.localizedCaseInsensitiveContains(q)
                || $0.ref.localizedCaseInsensitiveContains(q)
                || $0.itemDescription.localizedCaseInsensitiveContains(q)
        }
    }

    public func refresh() async {
        rows = await backend.loadItems()
    }

    public func syncNow() async {
        syncDot = .syncing
        do {
            _ = try await backend.syncNow()
            syncDot = .idle
            syncFailure = nil
            await refresh()
            await refreshAccountState()
        } catch {
            let message = SyncMessage.from(error)
            syncDot = message.isTerminal ? .failed : .offline
            syncFailure = message
            failureAt = Date()
            if case .quotaExceeded = message { overQuota = true }
            await refresh()
        }
    }

    func refreshAccountState() async {
        if let snapshot = await backend.fetchAccount() {
            overQuota = snapshot.isOverQuota
            isFrozen = snapshot.isFrozen
        }
    }

    public func clearFailure() {
        syncFailure = nil
        syncDot = .idle
    }

    // MARK: mutations (§2.5, §2.6)

    @discardableResult
    public func delete(itemID: String) async -> Bool {
        do {
            try await backend.deleteItem(id: itemID)
            await refresh()
            toast = "已删除"
            return true
        } catch {
            haptics.fire(.error)
            toast = "删除没有完成，请重试。"
            return false
        }
    }

    @discardableResult
    public func rotate(itemID: String, newValue: String) async -> Bool {
        do {
            try await backend.rotateItem(id: itemID, newValue: newValue)
            await refresh()
            toast = "已轮换并同步"
            return true
        } catch let e as APIError {
            haptics.fire(.error)
            if case .quotaExceeded = e {
                toast = "免费额度已用尽，不能新增或修改。仍可查看和删除。"
            } else {
                toast = "轮换没有完成，请重试。"
            }
            return false
        } catch {
            haptics.fire(.error)
            toast = "轮换没有完成，请重试。"
            return false
        }
    }

    /// Reveal needs Face ID every single time (§3.1: 不设会话级宽限).
    public func reveal(itemID: String, authenticator: any BiometricAuthenticator) async -> String? {
        let result = await authenticator.authenticate(reason: "查看明文")
        guard case .success = result else {
            haptics.fire(.warning)
            return nil
        }
        return try? backend.revealSecret(itemID)
    }
}

extension SyncMessage {
    /// Non-retryable failures keep the dot red and the banner up (§2.4).
    var isTerminal: Bool {
        switch self {
        case .verificationRejected, .quotaExceeded, .deviceRevoked: return true
        default: return false
        }
    }
}

// MARK: - item editor (§2.6)

/// View model for 新建/编辑条目. Validation is pure and testable: ref syntax
/// and uniqueness, the §7.3 deny-list confirmation, and the §7.4 paste-leak
/// check that meta must pass before it reaches agent context.
@Observable
@MainActor
public final class ItemEditorModel {
    public enum Mode: Equatable, Sendable {
        case create
        case edit(existing: ItemRow)
    }

    public let mode: Mode
    public var ref: String = ""
    public var name: String = ""
    public var itemDescription: String = ""
    public var type: String = "api_key"
    public var value: String = ""
    /// 策略区 Phase 1 基础编辑（§13）。
    public var denyShells: Bool = true
    public var allowCommandsText: String = ""
    public var allowedHostsText: String = ""
    public var allowArgv: Bool = false
    public var injectable: Bool = false

    /// Set while the allowArgv alert or the deny-list confirmation is up.
    public var pendingAllowArgvAlert = false
    public var pendingDenyListWarning: String?
    public var pendingLeakWarning: [LeakFinding]?
    public var saving = false
    public var errorMessage: String?
    /// 精细编辑（§13）的命令搜索词。
    public var commandSearch = ""
    /// 精细编辑的输入框暂存值（添加一条即清空）。
    public var newCommandInput = ""
    public var newHostInput = ""

    public struct LeakFinding: Equatable, Sendable {
        public var field: String   // "名称" | "描述"
        public var kind: String    // 原文 / Base64 / hex / URL
    }

    let backend: any AppBackend
    let haptics: any Haptics
    let existingRefs: [String: String]  // ref → item name

    public init(mode: Mode, backend: any AppBackend, haptics: any Haptics,
                existingRefs: [String: String]) {
        self.mode = mode
        self.backend = backend
        self.haptics = haptics
        self.existingRefs = existingRefs
        if case .edit(let row) = mode {
            name = row.name
            itemDescription = row.itemDescription
            denyShells = row.policy.commandPolicy == "deny-shells"
            allowCommandsText = row.policy.allowCommands.joined(separator: ", ")
            allowedHostsText = row.policy.allowedHosts.joined(separator: ", ")
            allowArgv = row.policy.allowArgv
            injectable = row.injectable
        }
    }

    // MARK: validation

    public var isCreate: Bool { mode == .create }

    public var refIsValid: Bool {
        if !isCreate { return true }  // 编辑页只读展示（§2.6）
        return RefValidation.isValid(ref)
    }

    // MARK: allowCommands / allowedHosts 精细编辑（Phase 2, §13）

    /// 命令搜索的建议池：默认拒绝名单 + 常见白名单候选（§13 命令搜索）。
    public static var commandSuggestions: [String] {
        DefaultDeny.commands.union(["curl", "gh", "git", "aws", "kubectl", "openai"])
            .sorted()
    }

    /// 当前搜索词命中的建议（输入即搜；命中默认拒绝名单的项在 UI 里警示）。
    public func commandSearchResults() -> [String] {
        let q = commandSearch.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return [] }
        return Self.commandSuggestions.filter { $0.contains(q) && !allowCommands.contains($0) }
    }

    /// 添加一条 allowCommands（argv0）。返回结果供 UI 决定是否提示；命中
    /// 默认拒绝名单时发 warning 触感（§3.7），保存前的确认弹窗仍在
    /// save(force:) 管线里（§2.6 既有行为不动）。
    @discardableResult
    public func addAllowCommand(_ raw: String) -> AddResult {
        let token = raw.trimmingCharacters(in: .whitespaces).lowercased()
        guard !token.isEmpty,
              !token.contains(where: { $0 == "," || $0 == "，" || $0.isWhitespace }),
              !token.hasPrefix("-") else {
            return .invalid
        }
        var list = allowCommands
        guard !list.contains(token) else { return .duplicate }
        list.append(token)
        allowCommandsText = list.joined(separator: ", ")
        if DefaultDeny.isDenied(token) {
            haptics.fire(.warning)
        }
        return .added
    }

    public func removeAllowCommand(_ name: String) {
        allowCommandsText = allowCommands.filter { $0 != name }.joined(separator: ", ")
    }

    /// 全部落到默认拒绝名单上的 allowCommands（红色警示卡的触发条件，§13：
    /// 解释器一旦放行脱敏器会失明，建议配合 approval）。
    public var denyListHits: [String] {
        allowCommands.filter { DefaultDeny.isDenied($0) }
    }

    /// 参数检查主机名合法性：无 scheme / 路径 / 端口 / 空格的点分域名。
    public static func isValidHost(_ raw: String) -> Bool {
        let h = raw.lowercased().trimmingCharacters(in: .whitespaces)
        guard !h.isEmpty, h.count <= 253 else { return false }
        if h.contains("://") || h.contains("/") || h.contains(":") || h.contains(" ")
            || h.contains("?") || h.contains("#") {
            return false
        }
        for ch in h {
            if ("a"..."z").contains(ch) || ("0"..."9").contains(ch) || ch == "." || ch == "-" {
                continue
            }
            return false
        }
        let labels = h.split(separator: ".", omittingEmptySubsequences: false)
        return !labels.isEmpty && labels.allSatisfy { !$0.isEmpty }
    }

    @discardableResult
    public func addAllowedHost(_ raw: String) -> AddResult {
        let host = raw.trimmingCharacters(in: .whitespaces).lowercased()
        guard Self.isValidHost(host) else { return .invalid }
        var list = allowedHosts
        guard !list.contains(host) else { return .duplicate }
        list.append(host)
        allowedHostsText = list.joined(separator: ", ")
        return .added
    }

    public func removeAllowedHost(_ host: String) {
        allowedHostsText = allowedHosts.filter { $0 != host }.joined(separator: ", ")
    }

    public enum AddResult: Equatable, Sendable {
        case added
        case duplicate
        case invalid
    }

    public var refConflictName: String? {
        guard isCreate, RefValidation.isValid(ref) else { return nil }
        return existingRefs[ref.lowercased()]
    }

    /// 唯一性错误文案（§2.6）。
    public var refConflictMessage: String? {
        guard let conflict = refConflictName else { return nil }
        return "这个 ref 已被「\(conflict)」使用"
    }

    var allowCommands: [String] {
        allowCommandsText
            .split(whereSeparator: { $0 == "," || $0 == "，" || $0 == " " || $0.isNewline })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    var allowedHosts: [String] {
        allowedHostsText
            .split(whereSeparator: { $0 == "," || $0 == "，" || $0 == " " || $0.isNewline })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// The first newly-typed allowCommands name that sits on the §7.3
    /// default-deny list (triggers the one-time save-time confirmation).
    public func denyListHit() -> String? {
        allowCommands.first { DefaultDeny.isDenied($0) }
    }

    /// §12.1 流程 3: 名称与描述和条目值及常见编码比对。
    public func leakFindings() -> [LeakFinding] {
        guard isCreate || !value.isEmpty else { return [] }
        var out: [LeakFinding] = []
        if let kind = SecretLeak.leakKind(secret: value, in: name) {
            out.append(LeakFinding(field: "名称", kind: kind))
        }
        if let kind = SecretLeak.leakKind(secret: value, in: itemDescription) {
            out.append(LeakFinding(field: "描述", kind: kind))
        }
        return out
    }

    public var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty
            && (isCreate ? refIsValid && value.isEmpty == false : true)
    }

    public var policy: ItemPolicy {
        ItemPolicy(sensitivity: "standard",
                   commandPolicy: denyShells ? "deny-shells" : "allow-all",
                   allowCommands: allowCommands,
                   allowedHosts: allowedHosts,
                   allowArgv: allowArgv)
    }

    public var editDraft: ItemEditDraft {
        ItemEditDraft(name: name, itemDescription: itemDescription,
                      value: value, policy: policy, injectable: injectable)
    }

    public var createDraft: ItemDraft {
        ItemDraft(ref: ref.lowercased(), name: name,
                  itemDescription: itemDescription, type: type,
                  value: value, policy: policy, injectable: injectable)
    }

    // MARK: save pipeline
    //
    // deny-list hit → confirm → leak check → confirm (可强制保存) → backend.

    public enum SaveOutcome: Equatable, Sendable {
        case saved
        case needsDenyListConfirmation(name: String)
        case needsLeakConfirmation([LeakFinding])
        case failed(String)
    }

    public func save(force: Bool) async -> SaveOutcome {
        guard canSave else {
            return .failed("还有必填项没有填完。")
        }
        if !force, let hit = denyListHit() {
            haptics.fire(.warning)
            return .needsDenyListConfirmation(name: hit)
        }
        let leaks = leakFindings()
        if !force, !leaks.isEmpty {
            haptics.fire(.warning)
            return .needsLeakConfirmation(leaks)
        }
        saving = true
        defer { saving = false }
        do {
            switch mode {
            case .create:
                try await backend.createItem(createDraft)
            case .edit(let row):
                try await backend.updateItem(id: row.id, editDraft)
            }
            return .saved
        } catch let e as APIError {
            if case .quotaExceeded = e {
                return .failed("免费额度已用尽，不能新增或修改。仍可查看和删除。")
            }
            if case .revisionConflict = e {
                return .failed("服务器上已有更新的版本，刷新后再试。")
            }
            return .failed("保存没有完成，请重试。")
        } catch {
            return .failed("保存没有完成，请重试。")
        }
    }
}
