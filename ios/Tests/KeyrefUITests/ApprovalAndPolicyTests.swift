// Approval store tests (Phase 2, §8.3 / ios-ui §5): badge counting, the
// S8 copy, invalid-request handling (显示为无效并可忽略), the Face ID-gated
// approve / straight deny decision, and the polling floor. Plus the
// allowCommands / allowedHosts fine-editing tests (§13): list add/remove,
// the command search, host validation and the red warning-card trigger.
import XCTest
import KeyrefCore

@testable import KeyrefUI

@MainActor
final class ApprovalAndPolicyTests: XCTestCase {

    private func makeStore() -> (ApprovalsStore, MemoryBackend) {
        let backend = MemoryBackend().seedVault(itemCount: 2)
        backend.unlocked = true
        let store = ApprovalsStore(backend: backend, haptics: NoHaptics())
        return (store, backend)
    }

    private func entry(id: String, valid: Bool = true, expiresIn: Int64 = 120_000) -> ApprovalInboxEntry {
        ApprovalInboxEntry(approvalID: id, cliDeviceID: "dev-\(id)",
                           cliDeviceLabel: "build-bot", itemID: "item-\(id)",
                           itemName: "OpenAI 生产密钥", itemRef: "openai-prod",
                           argv: ["curl", "--reply", "Password:=wifi-home",
                                  "{{keyref:openai-prod}}"],
                           refs: ["openai-prod"], injection: "env",
                           hosts: ["api.openai.com"],
                           createdAt: 1, expiresAt: Int64(Date().timeIntervalSince1970 * 1000) + expiresIn,
                           valid: valid)
    }

    // MARK: badge & display

    func testBadgeCountsOnlyValidUnignoredUnexpired() async {
        let (store, backend) = makeStore()
        backend.approvalEntries = [
            entry(id: "a"),
            entry(id: "b", valid: false),                      // 验不过：无效
            entry(id: "c", expiresIn: -1),                     // 已过期
        ]
        await store.refresh()
        XCTAssertEqual(store.badgeCount, 1)
        XCTAssertEqual(store.displayEntries.count, 2)  // 无效仍显示（可忽略），过期消失
        store.ignore(store.displayEntries.first { !$0.valid }!)
        XCTAssertEqual(store.displayEntries.count, 1)
        XCTAssertEqual(store.displayEntries.first?.approvalID, "a")
    }

    func testEntryCarriesArgvPlaceholderAndReplyPattern() async {
        let (store, backend) = makeStore()
        backend.approvalEntries = [entry(id: "a")]
        await store.refresh()
        let argv = store.displayEntries[0].argv.joined(separator: " ")
        // §7.1 / §8.3：审批界面显示完整 --reply 模式与占位符原文。
        XCTAssertTrue(argv.contains("--reply"))
        XCTAssertTrue(argv.contains("Password:=wifi-home"))
        XCTAssertTrue(argv.contains("{{keyref:openai-prod}}"))
        XCTAssertEqual(store.displayEntries[0].injectionLabel, "环境变量")
    }

    // MARK: decisions

    func testApproveRequiresFaceIDAndRecordsDecision() async {
        let (store, backend) = makeStore()
        backend.approvalEntries = [entry(id: "a")]
        await store.refresh()
        let auth = MockBiometricAuthenticator(queue: [.failure(.cancelled)])
        let ok = await store.decide(store.displayEntries[0], approve: true, authenticator: auth)
        XCTAssertFalse(ok)
        XCTAssertTrue(backend.approvalDecisions.isEmpty)  // Face ID 未过：不提交

        let ok2 = await store.decide(store.displayEntries[0], approve: true,
                                     authenticator: MockBiometricAuthenticator())
        XCTAssertTrue(ok2)
        XCTAssertEqual(backend.approvalDecisions.count, 1)
        XCTAssertEqual(backend.approvalDecisions[0].approvalID, "a")
        XCTAssertTrue(backend.approvalDecisions[0].approve)
        XCTAssertTrue(backend.approvalEntries.isEmpty)  // 决定后从收件箱移除
    }

    func testDenyNeedsNoBiometricsAndHandlesConflict() async {
        let (store, backend) = makeStore()
        backend.approvalEntries = [entry(id: "a")]
        await store.refresh()
        let ok = await store.decide(store.displayEntries[0], approve: false,
                                    authenticator: MockBiometricAuthenticator())
        XCTAssertTrue(ok)
        XCTAssertEqual(backend.approvalDecisions.count, 1)
        XCTAssertEqual(backend.approvalDecisions[0].approvalID, "a")
        XCTAssertFalse(backend.approvalDecisions[0].approve)

        // approval_not_pending → 「这个请求已经被处理。」
        backend.approvalEntries = [entry(id: "z")]
        backend.decideApprovalError = APIError.approvalNotPending
        await store.refresh()
        let ok2 = await store.decide(store.displayEntries[0], approve: false,
                                     authenticator: MockBiometricAuthenticator())
        XCTAssertFalse(ok2)
        XCTAssertEqual(store.toast, "这个请求已经被处理。")
    }

    // MARK: polling floor

    func testPollIntervalIsAtLeastTwoSeconds() {
        // §8.3：轮询间隔 ≥2 秒，服务器对更快的轮询直接 429。
        let comps = ApprovalsStore.pollInterval.components
        let seconds = Double(comps.seconds) + Double(comps.attoseconds) / 1e18
        XCTAssertGreaterThanOrEqual(seconds, 2.0)
    }

    func testSetActiveTogglesWithoutPollingWork() async {
        let (store, _) = makeStore()
        store.setActive(true)
        // 活跃标志翻转即可；真实轮询的 HTTP 侧由 LiveBackend 集成测试覆盖。
        XCTAssertTrue(store.active)
        store.setActive(false)
        XCTAssertFalse(store.active)
    }

    // MARK: allowCommands / allowedHosts 精细编辑（§13）

    private func makeEditor() -> ItemEditorModel {
        ItemEditorModel(mode: .create, backend: MemoryBackend(), haptics: NoHaptics(),
                        existingRefs: [:])
    }

    func testAllowCommandAddRemoveAndValidation() {
        let editor = makeEditor()
        XCTAssertEqual(editor.addAllowCommand("curl"), .added)
        XCTAssertEqual(editor.allowCommands, ["curl"])
        XCTAssertEqual(editor.addAllowCommand("CURL"), .duplicate)   // 大小写归一
        XCTAssertEqual(editor.addAllowCommand(""), .invalid)
        XCTAssertEqual(editor.addAllowCommand("curl --x"), .invalid) // 不是单个 argv0
        XCTAssertEqual(editor.addAllowCommand("-flag"), .invalid)
        editor.removeAllowCommand("curl")
        XCTAssertTrue(editor.allowCommands.isEmpty)
    }

    func testDenyListHitsTriggerRedCardCondition() {
        let editor = makeEditor()
        XCTAssertTrue(editor.denyListHits.isEmpty)
        editor.addAllowCommand("curl")
        XCTAssertTrue(editor.denyListHits.isEmpty)
        editor.addAllowCommand("python3")
        editor.addAllowCommand("Node")
        XCTAssertEqual(editor.denyListHits, ["python3", "node"])
        // 建议池与搜索（§13 命令搜索）：未加过的候选才出现在建议里。
        editor.commandSearch = "py"
        XCTAssertFalse(editor.commandSearchResults().contains("python3"))  // 已在白名单
        editor.removeAllowCommand("python3")
        XCTAssertTrue(editor.commandSearchResults().contains("python3"))
        editor.addAllowCommand("python3")
        XCTAssertEqual(editor.denyListHits, ["node", "python3"])  // 插入顺序：node 先加
    }

    func testAllowedHostValidationAndEditing() {
        let editor = makeEditor()
        XCTAssertEqual(editor.addAllowedHost("api.openai.com"), .added)
        XCTAssertEqual(editor.addAllowedHost("api.openai.com"), .duplicate)
        XCTAssertEqual(editor.addAllowedHost("https://api.openai.com"), .invalid)  // 不是主机名
        XCTAssertEqual(editor.addAllowedHost("api.openai.com:443"), .invalid)      // 带端口
        XCTAssertEqual(editor.addAllowedHost("a b.example"), .invalid)
        XCTAssertEqual(editor.addAllowedHost("x..y"), .invalid)                    // 空标签
        editor.addAllowedHost("Api.Example.ORG")
        XCTAssertTrue(editor.allowedHosts.contains("api.example.org"))
        editor.removeAllowedHost("api.example.org")
        XCTAssertEqual(editor.allowedHosts, ["api.openai.com"])
        editor.removeAllowedHost("api.openai.com")
        XCTAssertTrue(editor.allowedHosts.isEmpty)
    }

    func testEditModeLoadsAndRemovesExistingPolicyLists() {
        let row = ItemRow(id: "x", ref: "openai-prod", name: "OpenAI 生产密钥",
                          itemDescription: "", type: "api_key", masked: "sk-****abcd",
                          policy: ItemPolicy(allowCommands: ["curl", "python3"],
                                             allowedHosts: ["api.openai.com"]),
                          injectable: false, createdAt: 0, updatedAt: 0, grants: [])
        let editor = ItemEditorModel(mode: .edit(existing: row), backend: MemoryBackend(),
                                     haptics: NoHaptics(), existingRefs: [:])
        XCTAssertEqual(editor.allowCommands, ["curl", "python3"])
        XCTAssertEqual(editor.allowedHosts, ["api.openai.com"])
        XCTAssertEqual(editor.denyListHits, ["python3"])
        editor.removeAllowCommand("python3")
        XCTAssertEqual(editor.denyListHits.isEmpty, true)
        // 保存仍走既有路径（§13: 保存走既有条目更新路径）。
        editor.name = "改名"
        editor.commandSearch = ""
        let draft = editor.editDraft
        XCTAssertEqual(draft.policy.allowCommands, ["curl"])
        XCTAssertEqual(draft.policy.allowedHosts, ["api.openai.com"])
    }

    func testSavePipelineStillAsksDenyListConfirmation() async {
        let backend = MemoryBackend()
        let editor = ItemEditorModel(mode: .create, backend: backend, haptics: NoHaptics(),
                                     existingRefs: [:])
        editor.ref = "new-ref"
        editor.name = "Python 工具"
        editor.value = "value-123456"
        XCTAssertEqual(editor.addAllowCommand("python3"), .added)
        // §2.6 的保存前确认保持不变：红色警示卡是常驻提示，确认弹窗仍在保存管线。
        let outcome = await editor.save(force: false)
        XCTAssertEqual(outcome, .needsDenyListConfirmation(name: "python3"))
        let forced = await editor.save(force: true)
        XCTAssertEqual(forced, .saved)
    }
}
