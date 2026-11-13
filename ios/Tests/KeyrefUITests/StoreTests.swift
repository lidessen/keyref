// Store-level tests with the MemoryBackend and MockBiometricAuthenticator:
// lock states S2/S3/S4, the sync banner error mapping, editor save pipeline,
// pairing selection defaults and the revoke flow's default-checked rotation.
import XCTest
@testable import KeyrefUI
import KeyrefCore

@MainActor
final class StoreTests: XCTestCase {

    func makeApp(backend: MemoryBackend,
                 auth: MockBiometricAuthenticator = MockBiometricAuthenticator()) -> AppModel {
        AppModel(backend: backend, authenticator: auth,
                 haptics: NoHaptics(), clipboard: NoClipboard(),
                 systemOpener: NoSystemOpener())
    }

    // MARK: lock (S2/S3/S4)

    func testUnlockSuccessTransitionsToUnlocked() async {
        let backend = MemoryBackend().seedVault(itemCount: 2)
        let app = makeApp(backend: backend)
        app.forcePhase(.locked)
        await app.attemptUnlock()
        XCTAssertEqual(app.phase, .unlocked)
        XCTAssertEqual(app.lockDisplay, .waiting)
    }

    func testFaceIDFailureShowsS3AndRetryHint() async {
        let backend = MemoryBackend().seedVault()
        let auth = MockBiometricAuthenticator(queue: [.failure(.failed)])
        let app = makeApp(backend: backend, auth: auth)
        app.forcePhase(.locked)
        await app.attemptUnlock()
        XCTAssertEqual(app.phase, .locked)
        XCTAssertEqual(app.lockDisplay, .biometricFailed(attempts: 1))
        await app.attemptUnlock()
        XCTAssertEqual(app.lockDisplay, .biometricFailed(attempts: 2))
    }

    func testFaceIDCancelKeepsWaitingScreen() async {
        let backend = MemoryBackend().seedVault()
        let auth = MockBiometricAuthenticator(queue: [.failure(.cancelled)])
        let app = makeApp(backend: backend, auth: auth)
        app.forcePhase(.locked)
        await app.attemptUnlock()
        XCTAssertEqual(app.lockDisplay, .waiting)
    }

    func testWrapInvalidShowsS4() async {
        let backend = MemoryBackend().seedVault()
        backend.localWrapInvalid = true
        let app = makeApp(backend: backend)
        app.forcePhase(.locked)
        await app.attemptUnlock()
        XCTAssertEqual(app.lockDisplay, .wrapInvalid)
    }

    func testBootWithoutVaultLandsOnOnboarding() async {
        let app = makeApp(backend: MemoryBackend())
        await app.boot()
        XCTAssertEqual(app.phase, .onboarding)
    }

    // MARK: sync banner mapping (S6, §2.4 table)

    func testSyncFailureBannerCopy() async {
        let backend = MemoryBackend().seedVault()
        backend.syncError = APIError.transport("offline")
        let app = makeApp(backend: backend)
        await app.items.syncNow()
        XCTAssertEqual(app.items.syncDot, .offline)
        XCTAssertEqual(app.items.syncFailure?.headline, "连不上服务器，稍后自动重试。")

        backend.syncError = APIError.rateLimited
        await app.items.syncNow()
        XCTAssertEqual(app.items.syncFailure?.headline, "请求太快被限流，稍后自动重试。")
    }

    func testQuotaExceededMarksOverQuota() async {
        let backend = MemoryBackend().seedVault()
        backend.syncError = APIError.quotaExceeded
        let app = makeApp(backend: backend)
        await app.items.syncNow()
        XCTAssertTrue(app.items.overQuota)
        XCTAssertEqual(app.items.syncFailure?.headline, "免费额度已用尽。")
    }

    func testDeviceRevokedBannerOffersTakeover() async {
        let backend = MemoryBackend().seedVault()
        backend.syncError = APIError.deviceRevoked
        let app = makeApp(backend: backend)
        await app.items.syncNow()
        XCTAssertEqual(app.items.syncFailure?.headline, "这台设备已被撤销。")
        XCTAssertTrue(app.items.syncDot == .failed)
    }

    func testVerificationFailureStopsRetrying() async {
        let backend = MemoryBackend().seedVault()
        backend.syncError = APIError.badSignature
        let app = makeApp(backend: backend)
        await app.items.syncNow()
        XCTAssertEqual(app.items.syncDot, .failed)
        XCTAssertEqual(app.items.syncFailure?.headline,
                       "服务器返回的数据没有通过校验，已拒绝应用。")
    }

    // MARK: item editor save pipeline (§2.6)

    func makeEditor(backend: MemoryBackend, create: Bool) -> ItemEditorModel {
        ItemEditorModel(mode: create ? .create : .edit(existing: ItemRow(
            id: "x", ref: "openai-prod", name: "OpenAI 生产密钥",
            itemDescription: "", type: "api_key", masked: "sk-****abcd",
            policy: ItemPolicy(), injectable: false, createdAt: 0, updatedAt: 0,
            grants: [])),
            backend: backend, haptics: NoHaptics(),
            existingRefs: ["openai-prod": "OpenAI 生产密钥"])
    }

    func testEditorRefUniquenessMessage() {
        let editor = makeEditor(backend: MemoryBackend(), create: true)
        editor.ref = "openai-prod"
        XCTAssertEqual(editor.refConflictMessage, "这个 ref 已被「OpenAI 生产密钥」使用")
        editor.ref = "other-ref"
        XCTAssertNil(editor.refConflictMessage)
    }

    func testEditorDenyListConfirmationGate() async {
        let backend = MemoryBackend()
        let editor = makeEditor(backend: backend, create: true)
        editor.ref = "new-ref"
        editor.name = "Python 工具"
        editor.value = "value-123456"
        editor.allowCommandsText = "python3"
        let outcome = await editor.save(force: false)
        XCTAssertEqual(outcome, .needsDenyListConfirmation(name: "python3"))
        let forced = await editor.save(force: true)
        XCTAssertEqual(forced, .saved)
    }

    func testEditorPasteLeakCheckGate() async {
        let backend = MemoryBackend()
        let editor = makeEditor(backend: backend, create: true)
        editor.ref = "new-ref"
        let secret = "sk-secret-value-9999"
        editor.value = secret
        editor.name = "OpenAI \(secret)"  // 手滑把秘密贴进名称
        let outcome = await editor.save(force: false)
        guard case .needsLeakConfirmation(let findings) = outcome else {
            return XCTFail("expected leak confirmation, got \(outcome)")
        }
        XCTAssertEqual(findings.first?.field, "名称")
        // 可强制保存：这道检查挡的是手滑，不是审查。
        let forced = await editor.save(force: true)
        XCTAssertEqual(forced, .saved)
        XCTAssertEqual(backend.secrets.count, 1)
    }

    func testQuotaBlocksCreateWithSpecCopy() async {
        let backend = MemoryBackend()
        backend.createItemError = APIError.quotaExceeded
        let editor = makeEditor(backend: backend, create: true)
        editor.ref = "new-ref"
        editor.name = "N"
        editor.value = "v-12345678"
        let outcome = await editor.save(force: true)
        XCTAssertEqual(outcome, .failed("免费额度已用尽，不能新增或修改。仍可查看和删除。"))
    }

    // MARK: pairing (§2.8, S11, §15)

    func testPairingOfferParsesAndDetectsOriginMismatch() async {
        let backend = MemoryBackend().seedVault()
        backend.unlocked = true
        let owner = try? OwnerKeys.generate(preferEnclave: false)
        let offer = PairingOffer.make(
            hpkeKEM: KEMName.x25519, hpkePublicKey: Data(repeating: 1, count: 32),
            signAlg: SignAlg.ed25519, signPublicKey: Data(repeating: 2, count: 32),
            nonce: KeyrefEncoding.newID(), label: "build-bot",
            origin: URL(string: "https://other.example")!,
            confirmSecret: Data(repeating: 3, count: KeyrefSizes.pairConfirmKey))
        let app = makeApp(backend: backend)
        let model = PairingFlowModel(backend: backend, haptics: NoHaptics())
        XCTAssertTrue(model.originMismatch(offer))
        model.handlePayload(offer.payload(), items: app.items.rows)
        guard case .verify = model.step else {
            return XCTFail("expected verify step, got \(model.step)")
        }
        XCTAssertEqual(offer.fingerprint.count, 19)  // 4-4-4-4
        _ = owner
    }

    func testGrantSelectionDefaultsToEmpty() {
        let backend = MemoryBackend().seedVault()
        let model = PairingFlowModel(backend: backend, haptics: NoHaptics())
        // 配对完成时授予集合为空，直到人勾选（§15）。
        XCTAssertTrue(model.selected.isEmpty)
        XCTAssertEqual(model.itemCount, 0)
    }

    func testPairCompletionRequiresSelection() async {
        let backend = MemoryBackend().seedVault()
        backend.unlocked = true
        let app = makeApp(backend: backend)
        await app.items.refresh()
        let model = PairingFlowModel(backend: backend, haptics: NoHaptics())
        let owner = try! OwnerKeys.generate(preferEnclave: false)
        let offer = PairingOffer.make(
            hpkeKEM: KEMName.x25519, hpkePublicKey: owner.kemPublicKey,
            signAlg: SignAlg.ecdsaP256, signPublicKey: owner.signPublicKey,
            nonce: KeyrefEncoding.newID(), label: "build-bot",
            origin: backend.origin,
            confirmSecret: Data(repeating: 4, count: KeyrefSizes.pairConfirmKey))
        model.handlePayload(offer.payload(), items: app.items.rows)
        model.proceedToSelection(offer)
        // 勾选第一条（默认不勾选 → 人勾选 → 授予 view + use 两条）。
        model.toggle(app.items.rows[0].id)
        XCTAssertEqual(model.selected.count, 1)
        let selections = model.selected.sorted().flatMap { itemID in
            [GrantSelection(itemID: itemID, kind: "view"),
             GrantSelection(itemID: itemID, kind: "use")]
        }
        await model.complete(grantSelections: selections, items: app.items.rows,
                             authenticator: app.authenticator)
        guard case .done = model.step else {
            return XCTFail("expected done, got \(model.step)")
        }
        XCTAssertEqual(backend.pairingCompletions.count, 1)
        XCTAssertEqual(backend.pairingCompletions[0].selections.count, 2)
    }

    // MARK: revoke (§2.10, B6)

    func testRevokeDefaultsToRotationChecked() {
        let backend = MemoryBackend().seedVault()
        let device = backend.seedDevice("build-bot", grants: [
            GrantSummary(deviceID: "d", itemID: "i1", kind: "use", expiresAt: 0),
            GrantSummary(deviceID: "d", itemID: "i2", kind: "use", expiresAt: 0),
            GrantSummary(deviceID: "d", itemID: "i3", kind: "view", expiresAt: 0),
        ])
        let model = RevokeFlowModel(backend: backend, haptics: NoHaptics(),
                                    device: device) { _ in "item" }
        XCTAssertTrue(model.rotateSelected)  // 默认勾选（§8.4 默认动作）
        XCTAssertEqual(model.grantCount, 3)
        XCTAssertEqual(model.useGrantCount, 2)
    }

    func testRevokeInterruptionIsResumable() async {
        let backend = MemoryBackend().seedVault()
        let device = backend.seedDevice("build-bot", grants: [
            GrantSummary(deviceID: "d", itemID: "i1", kind: "use", expiresAt: 0),
            GrantSummary(deviceID: "d", itemID: "i2", kind: "use", expiresAt: 0),
        ])
        backend.interruptRotationAt = 0
        let model = RevokeFlowModel(backend: backend, haptics: NoHaptics(),
                                    device: device) { _ in "item" }
        await model.run(authenticator: MockBiometricAuthenticator())
        guard case .interrupted(let remaining) = model.phase else {
            return XCTFail("expected interrupted, got \(model.phase)")
        }
        XCTAssertEqual(remaining, 2)
        XCTAssertTrue(backend.hasPendingRotation(deviceID: device.id))
        await model.resume(authenticator: MockBiometricAuthenticator())
        XCTAssertEqual(model.phase, .done)
        XCTAssertEqual(backend.rotationResumed, [device.id])
        XCTAssertFalse(backend.hasPendingRotation(deviceID: device.id))
    }

    // MARK: settings (§2.14–§2.16)

    func testOriginValidationRejectsHTTP() {
        XCTAssertTrue(SettingsStore.isValidOrigin("https://sync.example"))
        XCTAssertFalse(SettingsStore.isValidOrigin("http://sync.example"))
        XCTAssertFalse(SettingsStore.isValidOrigin("not a url"))
        let settings = SettingsStore(backend: MemoryBackend(), haptics: NoHaptics())
        settings.newOriginText = "http://x.example"
        XCTAssertEqual(settings.originInlineError, "正式版只接受系统信任的 HTTPS。")
    }

    func testDeleteRequiresTypingAndNeverFakesSuccess() async {
        let backend = MemoryBackend().seedVault()
        backend.failDeleteVault = true
        let app = makeApp(backend: backend)
        let settings = app.settings
        settings.deleteConfirmText = "删除"
        let ok = await settings.deleteVault(authenticator: MockBiometricAuthenticator())
        XCTAssertFalse(ok)
        XCTAssertEqual(settings.deleteFailed, "删除没有完成，数据还在。请重试。")
        XCTAssertFalse(settings.deleteConfirmed)
        XCTAssertEqual(backend.deleteAttempts, 1)

        backend.failDeleteVault = false
        let ok2 = await settings.deleteVault(authenticator: MockBiometricAuthenticator())
        XCTAssertTrue(ok2)
        XCTAssertTrue(settings.deleteConfirmed)
        XCTAssertFalse(backend.hasVault)
    }

    func testDeleteConfirmRequiresExactWord() async {
        let app = makeApp(backend: MemoryBackend())
        app.settings.deleteConfirmText = "删除 "
        XCTAssertFalse(app.settings.deleteConfirmValid)
        app.settings.deleteConfirmText = "删除"
        XCTAssertTrue(app.settings.deleteConfirmValid)
    }

    // MARK: recovery (§2.12, §2.13)

    func testRecoveryBadCodeShowsSpecCopy() async {
        let backend = MemoryBackend().seedVault()
        backend.failRecoveryCodeCheck = true
        let model = RecoveryFlowModel(backend: backend, haptics: NoHaptics(), mode: .takeover)
        model.codeInput = "NOT-A-CODE"
        await model.submitCode()
        XCTAssertEqual(model.phase, .input)
        XCTAssertEqual(model.inputError, "恢复码不正确。")
    }

    func testTakeoverCommitRevokesDevicesAndReports() async {
        let backend = MemoryBackend().seedVault(itemCount: 2)
        let model = RecoveryFlowModel(backend: backend, haptics: NoHaptics(), mode: .takeover)
        let code = RecoveryCode.generatePayload().code
        model.codeInput = code
        await model.submitCode()
        XCTAssertEqual(model.phase, .confirmCommit)
        await model.commit()
        XCTAssertEqual(model.phase, .done)
        XCTAssertEqual(model.summary?.itemCount, 2)
        XCTAssertEqual(model.summary?.revokedDeviceCount, 3)
    }

    // MARK: account / S12-S13

    func testOverQuotaReasonPicksFirstTrippedLimit() {
        let limits = PlanLimits.make(items: 20, devicesIOS: 1, devicesCLI: 1,
                                     storageBytes: 1_048_576, auditRetentionDays: 7,
                                     auditMaxEvents: 100, requestsPerDay: 500,
                                     requestsPerMinute: 30)
        let usage = AccountUsage.make(items: 20, devicesActive: 1, storageBytes: 400_000,
                                      auditEvents: 3, requestsToday: 87)
        let snapshot = AccountSnapshot(plan: "free", origin: "https://sync.keyref.app",
                                       limits: limits, usage: usage)
        XCTAssertTrue(snapshot.isOverQuota)
        XCTAssertTrue(snapshot.overQuotaReason?.contains("条目数") == true)
        XCTAssertEqual(snapshot.isHosted, true)
    }

    // MARK: auto-lock (§9.5)

    func testAutoLockAfterBackgroundInterval() {
        let app = makeApp(backend: MemoryBackend().seedVault())
        app.forcePhase(.unlocked)
        let t0 = Date(timeIntervalSince1970: 10_000)
        app.handleScenePhase(.background, now: t0)
        app.handleScenePhase(.active, now: t0.addingTimeInterval(30))
        XCTAssertEqual(app.phase, .unlocked)
        app.handleScenePhase(.background, now: t0)
        app.handleScenePhase(.active, now: t0.addingTimeInterval(61))
        XCTAssertEqual(app.phase, .locked)
    }

    func testImmediateAutoLock() {
        let backend = MemoryBackend().seedVault()
        let app = AppModel(backend: backend, authenticator: MockBiometricAuthenticator(),
                           haptics: NoHaptics(), clipboard: NoClipboard(),
                           systemOpener: NoSystemOpener(), autoLock: .immediate)
        app.forcePhase(.unlocked)
        let t0 = Date(timeIntervalSince1970: 10_000)
        app.handleScenePhase(.background, now: t0)
        app.handleScenePhase(.active, now: t0)
        XCTAssertEqual(app.phase, .locked)
    }
}
