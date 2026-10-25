// APNs 注册与推送响应测试（Phase 2, §13）：注册状态机（未配对不注册、
// 已配对只注册一次、失败后可重试、拒绝授权走轮询兜底）与推送触发的
// 立即待审批刷新（triggerRefresh 与 3 秒轮询互斥防抖）。
import XCTest
import KeyrefCore

@testable import KeyrefUI

@MainActor
final class PushFlowTests: XCTestCase {

    /// 注册驱动的 fake：记录权限申请与系统注册调用。
    private final class FakeDriver: PushRegistrationDriver {
        var authResult = true
        private(set) var authCalls = 0
        private(set) var registerCalls = 0

        func requestAlertAuthorization() async -> Bool {
            authCalls += 1
            return authResult
        }

        func registerForRemoteNotifications() async {
            registerCalls += 1
        }
    }

    private func entry(id: String, createdAt: Int64 = 1, expiresIn: Int64 = 120_000) -> ApprovalInboxEntry {
        ApprovalInboxEntry(approvalID: id, cliDeviceID: "dev-\(id)",
                           cliDeviceLabel: "build-bot", itemID: "item-\(id)",
                           itemName: "OpenAI 生产密钥", itemRef: "openai-prod",
                           argv: ["curl", "{{keyref:openai-prod}}"],
                           refs: ["openai-prod"], injection: "env",
                           hosts: ["api.openai.com"],
                           createdAt: createdAt,
                           expiresAt: Int64(Date().timeIntervalSince1970 * 1000) + expiresIn,
                           valid: true)
    }

    // MARK: 注册状态机（§13）

    func testUnpairedDoesNotRegister() async {
        let backend = MemoryBackend()   // 未配对：没有 vault
        let driver = FakeDriver()
        let push = PushRegistrationStore(backend: backend, driver: driver, env: "sandbox")
        await push.unlockDidComplete(paired: false)
        XCTAssertEqual(push.state, .idle)
        XCTAssertEqual(driver.authCalls, 0)       // 不申请权限（欢迎页不弹窗）
        XCTAssertEqual(driver.registerCalls, 0)
        XCTAssertTrue(backend.pushTokenUploads.isEmpty)
    }

    func testPairedRegistersExactlyOnceAndUploadsToken() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        let driver = FakeDriver()
        let push = PushRegistrationStore(backend: backend, driver: driver, env: "sandbox")
        await push.unlockDidComplete(paired: true)
        await push.unlockDidComplete(paired: true)   // 重复触发（同一会话内再解锁）
        XCTAssertEqual(driver.registerCalls, 1)      // 已配对只注册一次
        XCTAssertEqual(driver.authCalls, 1)
        XCTAssertEqual(push.state, .requesting)

        await push.deviceTokenDidArrive(Data([0xde, 0xad, 0xbe, 0xef]))
        XCTAssertEqual(push.state, .uploaded)
        XCTAssertEqual(backend.pushTokenUploads.count, 1)
        XCTAssertEqual(backend.pushTokenUploads[0].token, "deadbeef")
        XCTAssertEqual(backend.pushTokenUploads[0].env, "sandbox")
        XCTAssertEqual(push.lastTokenHex, "deadbeef")

        await push.unlockDidComplete(paired: true)   // 已上传：不再注册
        XCTAssertEqual(driver.registerCalls, 1)
    }

    func testUploadFailureIsSilentAndRetriesNextUnlock() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        backend.putPushTokenResult = false           // 会话无效 / 服务器失败
        let driver = FakeDriver()
        let push = PushRegistrationStore(backend: backend, driver: driver, env: "sandbox")
        await push.unlockDidComplete(paired: true)
        await push.deviceTokenDidArrive(Data([0x01]))
        XCTAssertEqual(push.state, .failed)          // 静默记失败
        XCTAssertNotNil(push.lastError)

        backend.putPushTokenResult = true
        await push.unlockDidComplete(paired: true)   // 下次解锁重试注册
        XCTAssertEqual(driver.registerCalls, 2)
        await push.deviceTokenDidArrive(Data([0x01, 0x02]))
        XCTAssertEqual(push.state, .uploaded)
        XCTAssertEqual(backend.pushTokenUploads.count, 2)
    }

    func testRegistrationFailureIsLoggedAndRetryable() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        let driver = FakeDriver()
        let push = PushRegistrationStore(backend: backend, driver: driver, env: "sandbox")
        await push.unlockDidComplete(paired: true)
        // 模拟器常规路径：系统回调 didFail（no valid aps-environment 等）。
        push.registrationDidFail("no valid aps-environment")
        XCTAssertEqual(push.state, .failed)
        XCTAssertEqual(push.lastError, "no valid aps-environment")
        await push.unlockDidComplete(paired: true)   // 失败后可重试
        XCTAssertEqual(driver.registerCalls, 2)
    }

    func testDeniedAuthorizationFallsBackToPolling() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        let driver = FakeDriver()
        driver.authResult = false
        let push = PushRegistrationStore(backend: backend, driver: driver, env: "sandbox")
        await push.unlockDidComplete(paired: true)
        XCTAssertEqual(push.state, .denied)
        XCTAssertEqual(driver.registerCalls, 0)      // 不注册：轮询兜底照常
        await push.unlockDidComplete(paired: true)   // 用户在设置里授权后自愈，不重复弹窗
        XCTAssertEqual(push.state, .denied)
        XCTAssertEqual(driver.registerCalls, 0)
    }

    func testNoDriverStaysIdleWithoutSideEffects() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        let push = PushRegistrationStore(backend: backend, driver: nil, env: "sandbox")
        await push.unlockDidComplete(paired: true)
        XCTAssertEqual(push.state, .idle)
        XCTAssertTrue(backend.pushTokenUploads.isEmpty)
    }

    // MARK: 推送响应 → 立即刷新（§13）

    func testPushTriggersImmediateRefreshWhileUnlocked() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        backend.approvalEntries = [entry(id: "a", createdAt: 1)]
        let app = AppModel(backend: backend, authenticator: MockBiometricAuthenticator(),
                           haptics: NoHaptics())
        app.forcePhase(.unlocked)
        backend.approvalEntries.append(entry(id: "b", createdAt: 2))   // 推送刚带来的新审批
        await app.handleApprovalPush(approvalID: "b")
        // 不等 3 秒轮询：刷新立即发生。
        XCTAssertNil(app.pendingPushApprovalID)
        XCTAssertEqual(app.approvals.displayEntries.map(\.approvalID), ["a", "b"])
        XCTAssertNotNil(app.approvals.lastRefreshAt)
    }

    func testPushWhileLockedIsStagedAndConsumedAfterUnlock() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        let app = AppModel(backend: backend, authenticator: MockBiometricAuthenticator(),
                           haptics: NoHaptics())
        app.forcePhase(.locked)
        await app.handleApprovalPush(approvalID: "late-1")
        XCTAssertEqual(app.pendingPushApprovalID, "late-1")   // 先暂存
        XCTAssertTrue(app.approvals.displayEntries.isEmpty)
        backend.approvalEntries = [entry(id: "late-1")]
        await app.attemptUnlock()                              // 解锁后立即消费
        XCTAssertEqual(app.phase, .unlocked)
        XCTAssertNil(app.pendingPushApprovalID)
        XCTAssertEqual(app.approvals.displayEntries.map(\.approvalID), ["late-1"])
    }

    func testPushWithoutApprovalIDDoesNotConsumePending() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        let app = AppModel(backend: backend, authenticator: MockBiometricAuthenticator(),
                           haptics: NoHaptics())
        app.forcePhase(.unlocked)
        await app.handleApprovalPush(approvalID: nil)          // 非审批推送：不刷新
        XCTAssertNil(app.approvals.lastRefreshAt)
        XCTAssertNil(app.pendingPushApprovalID)
    }

    // MARK: triggerRefresh 与 3 秒轮询互斥防抖（§8.3 / §13）

    func testTriggerRefreshDebouncesConcurrentCalls() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        backend.approvalEntries = [entry(id: "a")]
        backend.approvalsLoadDelay = .milliseconds(50)
        let store = ApprovalsStore(backend: backend, haptics: NoHaptics())
        async let first: Void = store.triggerRefresh()
        async let second: Void = store.triggerRefresh()
        await first
        await second
        XCTAssertEqual(backend.approvalLoadCount, 1)   // 并发触发合并为一次刷新
        XCTAssertEqual(store.displayEntries.map(\.approvalID), ["a"])
    }

    func testTriggerRefreshWorksWithoutPollingActive() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        backend.approvalEntries = [entry(id: "a")]
        let store = ApprovalsStore(backend: backend, haptics: NoHaptics())
        await store.triggerRefresh()                   // 未激活也能推送刷新
        XCTAssertFalse(store.active)
        XCTAssertEqual(store.displayEntries.map(\.approvalID), ["a"])
    }

    func testTriggerRefreshKeepsPollingActiveAndResetsCadence() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        backend.approvalEntries = [entry(id: "a")]
        let store = ApprovalsStore(backend: backend, haptics: NoHaptics())
        store.setActive(true)
        await store.triggerRefresh()
        XCTAssertEqual(store.active, true)             // 轮询周期被重置而非关闭
        XCTAssertEqual(store.displayEntries.map(\.approvalID), ["a"])
        store.setActive(false)
    }
}
