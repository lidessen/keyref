// Second-iPhone tests (Phase 2, design §9.4 path 2): the flow-model state
// machine on the MemoryBackend, and the FULL two-phone flow against the
// in-process FakeKeyrefServer — two LiveBackend instances (in-memory
// KeyStore + UIStateStore each) where the new phone ends up able to decrypt
// every item and the signed directory carries both owners. The approval
// decision path (§8.3) runs end-to-end over the same fake server, including
// the CLI-side one-time unwrap.
import CryptoKit
import XCTest
@testable import KeyrefCore
@testable import KeyrefUI

@MainActor
final class SecondDeviceFlowTests: XCTestCase {

    override func tearDown() {
        UITestURLProtocol.handler = nil
        UITestURLProtocol.calls = []
        super.tearDown()
    }

    // MARK: flow model (MemoryBackend)

    func testNewPhoneFlowStates() async {
        let backend = MemoryBackend()
        let model = SecondDeviceFlowModel(role: .newPhone, backend: backend,
                                          haptics: NoHaptics())
        guard case .preparingOffer = model.step else { return XCTFail("starts at preparingOffer") }
        await model.prepareOffer()
        guard case .showingOffer(let offer) = model.step else {
            return XCTFail("expected showingOffer, got \(model.step)")
        }
        XCTAssertEqual(offer.label, "这台 iPhone")
        XCTAssertEqual(backend.joinOffers.count, 1)
        model.beginWaitingForHandoff()
        guard case .waitingHandoff = model.step else { return XCTFail("expected waitingHandoff") }
        // 粘贴/扫描回执 → 接管。
        let handoff = JoinHandoff(vaultID: KeyrefEncoding.newID(),
                                  newOwnerDeviceID: offer.deviceID,
                                  directoryRevision: 2,
                                  ownerSignPublicKey: Data([0x04]) + Data(repeating: 8, count: 64),
                                  vmkWrap: Data(repeating: 9, count: 129))
        backend.adoptOverridesVaultID = handoff.vaultID
        await model.submitHandoff(handoff.payload())
        guard case .doneNew(let count) = model.step else {
            return XCTFail("expected doneNew, got \(model.step)")
        }
        XCTAssertEqual(count, 0)  // 空 vault
        XCTAssertTrue(backend.hasVault)
        XCTAssertEqual(backend.vaultID, handoff.vaultID)
        XCTAssertEqual(backend.ownDeviceID, offer.deviceID)
        XCTAssertTrue(backend.adoptedHandoffs.count == 1)
    }

    func testNewPhoneAdoptFailureShowsRetryCopy() async {
        let backend = MemoryBackend()
        backend.adoptSecondDeviceError = APIError.transport("boom")
        let model = SecondDeviceFlowModel(role: .newPhone, backend: backend,
                                          haptics: NoHaptics())
        await model.prepareOffer()
        model.beginWaitingForHandoff()
        await model.submitHandoff("keyref://handoff?v=1&vault=0f1e2d3c4b5a69788796a5b4c3d2e1f0&device=aaaabbbbccccddddeeeeffff00001111&rev=2&owner=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D%3D&w=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D%3D")
        guard case .failed(let message) = model.step else {
            return XCTFail("expected failed, got \(model.step)")
        }
        XCTAssertTrue(message.contains("交接没有完成"))
    }

    func testOldPhoneScanVerifyAndAdmit() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        backend.unlocked = true
        let model = SecondDeviceFlowModel(role: .oldPhone, backend: backend,
                                          haptics: NoHaptics())
        guard case .scanning = model.step else { return XCTFail("starts at scanning") }
        // 非 join 码保持扫描（S7）。
        model.handleScanned("keyref://pair?v=1&k=AAAA&s=AAAA&n=aa&name=x&u=https://a.example")
        guard case .scanning = model.step else { return XCTFail("non-join payload must keep scanning") }

        let offer = JoinOffer(hpkeKEM: KEMName.p256,
                              hpkePublicKey: Data([0x04]) + Data(repeating: 1, count: 64),
                              signAlg: SignAlg.ecdsaP256,
                              signPublicKey: Data([0x04]) + Data(repeating: 2, count: 64),
                              deviceID: KeyrefEncoding.newID(),
                              label: "新 iPhone",
                              origin: backend.origin)
        model.handleScanned(offer.payload())
        guard case .verifyOld(let parsed) = model.step else {
            return XCTFail("expected verifyOld, got \(model.step)")
        }
        XCTAssertEqual(parsed, offer)
        XCTAssertFalse(model.originMismatch)

        let auth = MockBiometricAuthenticator(queue: [.failure(.cancelled)])
        await model.confirmAdmit(offer: parsed, label: parsed.label, authenticator: auth)
        guard case .verifyOld = model.step else { return XCTFail("Face ID 取消应停在核对页") }

        await model.confirmAdmit(offer: parsed, label: parsed.label,
                                 authenticator: MockBiometricAuthenticator())
        guard case .showingHandoff(let payload) = model.step else {
            return XCTFail("expected showingHandoff, got \(model.step)")
        }
        XCTAssertNotNil(try? JoinHandoff.parse(payload))
        XCTAssertEqual(backend.admittedJoins.count, 1)
        XCTAssertEqual(backend.admittedJoins[0].offer.deviceID, offer.deviceID)
    }

    func testOldPhoneBlocksOriginMismatch() async {
        let backend = MemoryBackend().seedVault(itemCount: 1)
        backend.unlocked = true
        let model = SecondDeviceFlowModel(role: .oldPhone, backend: backend,
                                          haptics: NoHaptics())
        let offer = JoinOffer(hpkeKEM: KEMName.p256,
                              hpkePublicKey: Data([0x04]) + Data(repeating: 1, count: 64),
                              signAlg: SignAlg.ecdsaP256,
                              signPublicKey: Data([0x04]) + Data(repeating: 2, count: 64),
                              deviceID: KeyrefEncoding.newID(),
                              label: "别家的手机",
                              origin: URL(string: "https://other.example")!)
        model.handleScanned(offer.payload())
        guard case .verifyOld = model.step else { return XCTFail("expected verifyOld") }
        XCTAssertTrue(model.originMismatch)
        await model.confirmAdmit(offer: offer, label: offer.label,
                                 authenticator: MockBiometricAuthenticator())
        // origin 不一致时 UI 禁用继续按钮；模型侧不再允许误触提交。
        guard case .verifyOld = model.step else {
            return XCTFail("mismatched origin must not admit, got \(model.step)")
        }
    }

    // MARK: full two-phone flow over the fake server (§9.4)

    private func makeBackend(origin: URL) -> LiveBackend {
        LiveBackend(keyStore: InMemoryKeyStore(), stateStore: UIStateStore(),
                    origin: origin, urlSession: UITestURLProtocol.makeSession())
    }

    /// The §3.11 approval-request transcript the CLI signs (v2 A).
    private func requestTranscript(vaultID: String, cliDeviceID: String, itemID: String,
                                   ephemeral: Curve25519.KeyAgreement.PrivateKey,
                                   ciphertext: Data) throws -> Data {
        try buildApprovalRequestTranscript(ApprovalRequestTranscript(
            vaultID: vaultID,
            cliDeviceID: cliDeviceID,
            subjectKind: ApprovalSubjectKind.item,
            subjectID: itemID,
            expiresAt: 1790000120000,
            cliEphemeralPublicKey: ephemeral.publicKey.rawRepresentation,
            requestCiphertext: ciphertext))
    }

    func testSecondIPhoneJoinFullFlow() async throws {
        let server = FakeKeyrefServer()
        UITestURLProtocol.handler = server.handler
        let origin = URL(string: "https://fake.test")!

        // 旧手机：建库、放一条条目。
        let oldPhone = makeBackend(origin: origin)
        let draft = try await oldPhone.prepareCreation(label: "旧 iPhone")
        try await oldPhone.uploadCreatedVault(draft)
        try await oldPhone.createItem(ItemDraft(
            ref: "openai-prod", name: "OpenAI 生产密钥", itemDescription: "",
            type: "api_key", value: "sk-value-1234567890", policy: ItemPolicy()))
        let vaultID = try XCTUnwrap(oldPhone.vaultID)
        // bootstrap sync 必须已把签名目录落到本机（admit 的输入）。
        XCTAssertNotNil(oldPhone.stateStore.currentDirectory(), "bootstrap sync must land the directory")

        // 新手机：出「加入已有保险库」二维码。
        let newPhone = makeBackend(origin: origin)
        let offer = try await newPhone.prepareJoinOffer(label: "新 iPhone")

        // 旧手机：Face ID（此处由流程模型保证，测试直接走 backend）→
        // 签两台 owner 的目录（revision + 1）→ VMK 交接码。
        let handoffPayload = try await oldPhone.admitSecondDevice(offer: offer, label: "新 iPhone")
        let handoff = try JoinHandoff.parse(handoffPayload)
        XCTAssertEqual(handoff.vaultID, vaultID)
        XCTAssertEqual(handoff.newOwnerDeviceID, offer.deviceID)
        XCTAssertEqual(server.currentDirectoryRevision, 2)  // directory_revision + 1

        // 新手机：接管 —— 解 VMK、session、cursor=0 引导。
        try await newPhone.adoptSecondDevice(handoffPayload: handoffPayload)

        // 接管后能解全部条目（§9.4 / 任务验收）。
        let items = await newPhone.loadItems()
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items.first?.ref, "openai-prod")
        XCTAssertEqual(try newPhone.revealSecret(items[0].id), "sk-value-1234567890")

        // 目录里两台 owner（kind=ios、active）。
        let devices = await newPhone.loadDevices()
        let owners = devices.filter { $0.kind == "ios" && $0.isActive }
        XCTAssertEqual(owners.count, 2)
        XCTAssertTrue(owners.contains { $0.id == offer.deviceID })
        // 旧手机侧同样看到两台 owner。
        let oldDevices = await oldPhone.loadDevices()
        XCTAssertEqual(oldDevices.filter { $0.kind == "ios" && $0.isActive }.count, 2)

        // 新手机在本地状态里以旧 owner 的签名公钥为信任锚（§6.18 的对应物）。
        XCTAssertEqual(try newPhone.stateStore.pinnedOwnerKey(), oldPhone.owner?.signPublicKey)
    }

    // MARK: approval decision end-to-end (§8.3) over the fake server

    func testApprovalDecisionEndToEndWithOneTimeUnwrap() async throws {
        let server = FakeKeyrefServer()
        UITestURLProtocol.handler = server.handler
        let origin = URL(string: "https://fake.test")!
        let phone = makeBackend(origin: origin)
        let draft = try await phone.prepareCreation(label: "旧 iPhone")
        try await phone.uploadCreatedVault(draft)
        try await phone.createItem(ItemDraft(
            ref: "wifi-home", name: "家里 Wi-Fi", itemDescription: "",
            type: "password", value: "correct-horse-battery", policy: ItemPolicy()))
        let vaultID = try XCTUnwrap(phone.vaultID)
        let owner = try XCTUnwrap(phone.owner)
        let ownerDeviceID = try XCTUnwrap(phone.ownDeviceID)
        let itemID = try XCTUnwrap(phone.stateStore.allItems().first?.itemID)
        let itemRow = try XCTUnwrap(phone.stateStore.itemByID(itemID))
        let itemKey = try ItemCrypto.unwrapItemKey(vmk: phone.vmk!, blob: itemRow.vaultWrappedItemKey,
                                                   vaultID: vaultID, itemID: itemID)

        // 模拟 CLI 设备：先把它写进签名目录（带公钥的目录行）。
        let cliSigner = try Ed25519Signer()
        let cliDeviceID = KeyrefEncoding.newID()
        let cliDevice = KeyrefDirectoryDevice(
            deviceID: cliDeviceID, kind: DeviceKind.cli, status: DeviceStatus.active,
            hpkeKEM: KEMName.x25519, hpkePublicKey: Data(repeating: 1, count: 32),
            signAlg: SignAlg.ed25519, signPublicKey: cliSigner.signPublicKey,
            renewalSignPublicKey: Data(), grantsDigest: emptyGrantsDigest())
        let ownEntry = KeyrefDirectoryDevice(
            deviceID: ownerDeviceID, kind: DeviceKind.ios, status: DeviceStatus.active,
            hpkeKEM: owner.kemKEMName, hpkePublicKey: owner.kemPublicKey,
            signAlg: owner.signer.signAlg, signPublicKey: owner.signPublicKey,
            renewalSignPublicKey: Data(), grantsDigest: emptyGrantsDigest())
        try await phone.publishDirectory([ownEntry, cliDevice], revision: 2,
                                         owner: owner, vaultID: vaultID)

        // CLI 构造 §6.19 请求（HPKE 给 owner + Ed25519 签密文）。
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let plaintext = ApprovalRequestPlaintext(
            v: 1, cliDeviceID: cliDeviceID, itemID: itemID,
            argv: ["keyref", "exec", "--allow-argv", "--",
                   "mytool", "--token", "{{keyref:wifi-home}}"],
            refs: ["wifi-home"], injection: "argv", hosts: [],
            ephemeralKEM: KEMName.x25519,
            ephemeralPublicKey: ephemeral.publicKey.rawRepresentation,
            createdAt: 1790000000000)
        let info = try hpkeInfo(purpose: KeyrefPurpose.approvalRequest,
                                vaultID: vaultID, recipientDeviceID: ownerDeviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                               recipientPublicKey: owner.kemPublicKey,
                                               info: info,
                                               plaintext: WireJSON.encoder.encode(plaintext))
        let ciphertext = enc + ct
        let approvalID = KeyrefEncoding.newID()
        server.pendingApprovals = [PendingApproval.make(
            approvalID: approvalID, cliDeviceID: cliDeviceID, itemID: itemID,
            cliEphemeralPublicKey: ephemeral.publicKey.rawRepresentation,
            requestCiphertext: ciphertext,
            requestSignature: try cliSigner.sign(try requestTranscript(
                vaultID: vaultID, cliDeviceID: cliDeviceID, itemID: itemID,
                ephemeral: ephemeral, ciphertext: ciphertext)),
            createdAt: 1790000000000, expiresAt: 1790000120000)]

        // iOS 前台轮询 → 解开 + 验签 + 展示。
        let entries = await phone.loadPendingApprovals()
        XCTAssertEqual(entries.count, 1)
        let entry = try XCTUnwrap(entries.first)
        XCTAssertTrue(entry.valid)
        XCTAssertEqual(entry.itemRef, "wifi-home")
        XCTAssertTrue(entry.argv.contains("{{keyref:wifi-home}}"))  // argv 原文（§7.1）
        XCTAssertTrue(entry.argv.contains("--allow-argv"))

        // 批准：一次性包裹 → 服务器记录 decision。
        try await phone.decideApproval(approvalID: approvalID, approve: true)
        let decision = try XCTUnwrap(server.decision(for: approvalID))
        XCTAssertEqual(decision.decision, "approved")
        let oneTimeEnc = try XCTUnwrap(decision.oneTimeEnc)
        let oneTimeWrapped = try XCTUnwrap(decision.oneTimeWrappedKey)

        // The decision carries a signature (§3.12, v2 B): the CLI verifies
        // it under the owner's public key before it unwraps, so a decision
        // the server made up does not pass.
        let decisionTranscript = try buildApprovalDecisionTranscript(ApprovalDecisionTranscript(
            vaultID: vaultID,
            approvalID: approvalID,
            decisionDeviceID: ownerDeviceID,
            decision: "approved",
            requestCiphertext: ciphertext,
            oneTimeEnc: oneTimeEnc,
            oneTimeWrappedKey: oneTimeWrapped))
        try verifyDeviceSignature(transcript: decisionTranscript,
                                  signature: decision.decisionSignature,
                                  signAlg: SignAlg.ecdsaP256,
                                  publicKey: owner.signPublicKey)

        // CLI 取走包裹，解开 item key（§7.1 步骤 4 / D4 绑定）。
        let unwrapped = try ItemCrypto.unwrapOneTimeItemKey(
            kemName: KEMName.x25519, receiver: .x25519(ephemeral),
            vaultID: vaultID, deviceID: cliDeviceID, itemID: itemID,
            approvalID: approvalID, requestCiphertext: ciphertext,
            enc: oneTimeEnc, wrappedKey: oneTimeWrapped)
        XCTAssertEqual(unwrapped, itemKey)

        // 拒绝路径：第二个请求同页拒绝，不带任何包裹。收件箱先刷新一次
        // （真实界面在展示拒绝按钮前已经拉取过待审批列表）。
        let ephemeral2 = Curve25519.KeyAgreement.PrivateKey()
        let plaintext2 = ApprovalRequestPlaintext(
            v: 1, cliDeviceID: cliDeviceID, itemID: itemID,
            argv: ["curl", "https://api.openai.com"], refs: ["wifi-home"],
            injection: "env", hosts: ["api.openai.com"],
            ephemeralKEM: KEMName.x25519,
            ephemeralPublicKey: ephemeral2.publicKey.rawRepresentation,
            createdAt: 1790000000000)
        let (enc2, ct2) = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                                 recipientPublicKey: owner.kemPublicKey,
                                                 info: info,
                                                 plaintext: WireJSON.encoder.encode(plaintext2))
        let ciphertext2 = enc2 + ct2
        let approvalID2 = KeyrefEncoding.newID()
        server.pendingApprovals = [PendingApproval.make(
            approvalID: approvalID2, cliDeviceID: cliDeviceID, itemID: itemID,
            cliEphemeralPublicKey: ephemeral2.publicKey.rawRepresentation,
            requestCiphertext: ciphertext2,
            requestSignature: try cliSigner.sign(try requestTranscript(
                vaultID: vaultID, cliDeviceID: cliDeviceID, itemID: itemID,
                ephemeral: ephemeral2, ciphertext: ciphertext2)),
            createdAt: 1790000000000, expiresAt: 1790000120000)]
        _ = await phone.loadPendingApprovals()
        try await phone.decideApproval(approvalID: approvalID2, approve: false)
        let deny = try XCTUnwrap(server.decision(for: approvalID2))
        XCTAssertEqual(deny.decision, "denied")
        XCTAssertNil(deny.oneTimeEnc)
        XCTAssertNil(deny.oneTimeWrappedKey)
    }

    func testApprovalWithForgedSignatureShowsInvalid() async throws {
        let server = FakeKeyrefServer()
        UITestURLProtocol.handler = server.handler
        let origin = URL(string: "https://fake.test")!
        let phone = makeBackend(origin: origin)
        let draft = try await phone.prepareCreation(label: "旧 iPhone")
        try await phone.uploadCreatedVault(draft)
        let vaultID = try XCTUnwrap(phone.vaultID)
        let owner = try XCTUnwrap(phone.owner)
        let ownerDeviceID = try XCTUnwrap(phone.ownDeviceID)

        // 目录里没有这个"CLI 设备"——无从验证，视为无效。
        let impostor = try Ed25519Signer()
        let cliDeviceID = KeyrefEncoding.newID()
        let (enc, ct) = try KeyrefHPKE.wrapKey(
            kemName: owner.kemKEMName, recipientPublicKey: owner.kemPublicKey,
            info: try hpkeInfo(purpose: KeyrefPurpose.approvalRequest,
                               vaultID: vaultID, recipientDeviceID: ownerDeviceID),
            plaintext: Data("{\"v\":1}".utf8))
        let ciphertext = enc + ct
        server.pendingApprovals = [PendingApproval.make(
            approvalID: KeyrefEncoding.newID(), cliDeviceID: cliDeviceID,
            itemID: "99990000aaaabbbbccccddddeeeeffff",
            cliEphemeralPublicKey: Data(repeating: 3, count: 32),
            requestCiphertext: ciphertext,
            requestSignature: try impostor.sign(ciphertext),
            createdAt: 1, expiresAt: 1790000120000)]
        let entries = await phone.loadPendingApprovals()
        XCTAssertEqual(entries.count, 1)
        XCTAssertFalse(entries[0].valid)  // 显示为无效并可忽略（§8.3）
        // 无效请求不提交任何决定。
        do {
            try await phone.decideApproval(approvalID: entries[0].approvalID, approve: true)
            XCTFail("invalid requests carry no record; decision must fail")
        } catch { /* fail closed */ }
    }
}
