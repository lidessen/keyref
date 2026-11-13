// In-memory AppBackend for previews and unit tests: deterministic, no
// Keychain and no network. Behavior knobs let tests drive the failure
// states the spec calls out (upload failure, quota, frozen, mid-rotation
// interruption, wrap invalidity).
import Foundation
import KeyrefCore

@MainActor
public final class MemoryBackend: AppBackend {
    public var hasVault = false
    public var vaultID: String?
    public var ownDeviceID: String?
    public var cachedItemCount = 0
    public var localWrapInvalid = false
    public var origin: URL
    public var plan = "free"
    public var frozen = false
    public var unlocked = false

    // Failure injection.
    public var uploadError: Error?
    public var createItemError: Error?
    public var syncError: Error?
    public var failDeleteVault = false
    public var failRecoveryCodeCheck = false
    public var interruptRotationAt: Int? = nil
    public var probeResult = true
    public var accountSnapshot: AccountSnapshot?

    public private(set) var items: [ItemRow] = []
    public private(set) var devices: [DeviceRow] = []
    public private(set) var audit: [AuditRow] = []
    public private(set) var secrets: [String: String] = [:]  // itemID → value
    public private(set) var pendingVault: CreatedVaultDraft?
    public private(set) var uploadAttempts = 0
    public private(set) var revokedDevices: [String] = []
    public private(set) var pendingRotation: [String: Int] = [:]
    public private(set) var rotationResumed: [String] = []
    public private(set) var deleteAttempts = 0
    public private(set) var migratedOrigin: URL?
    public private(set) var rotatedVMKCount = 0
    public private(set) var pairingCompletions: [(offer: PairingOffer, selections: [GrantSelection])] = []
    public private(set) var grantOperations: [(deviceID: String, itemID: String, kind: String, revoke: Bool)] = []

    // Phase 2 seams: approvals (§8.3) and the second iPhone (§9.4 path 2).
    public var approvalEntries: [ApprovalInboxEntry] = []
    public private(set) var approvalDecisions: [(approvalID: String, approve: Bool)] = []
    public var decideApprovalError: Error?
    public var joinOffers: [JoinOffer] = []
    public var admitSecondDeviceError: Error?
    public var adoptSecondDeviceError: Error?
    public private(set) var admittedJoins: [(offer: JoinOffer, label: String)] = []
    public private(set) var adoptedHandoffs: [String] = []
    /// What admitSecondDevice hands back (the UI renders it as a QR).
    public var nextHandoffPayload: String?
    /// 新手机端回执的 vault 覆盖（测试里模拟「旧手机给的 vault」）。
    public var adoptOverridesVaultID: String?
    // APNs 响应测试接缝（Phase 2, §13）：token 上传记录与结果、待审批
    // 加载的人工延迟与计数（triggerRefresh 互斥防抖断言用）。
    public var pushTokenUploads: [(token: String, env: String)] = []
    public var putPushTokenResult = true
    public var approvalsLoadDelay: Duration?
    public private(set) var approvalLoadCount = 0

    // v0.7 seams: 存储类别（§6.6）、轮换（§8.4）、iCloud 副本（§6.7）。
    /// 仅本机条目 id 集（seedLocalOnlyItem / createItem 写入）。
    public var localOnlyItemIDs: Set<String> = []
    /// 轮换观察记录：rotateItem / rotateAllItems 触达的条目。
    public private(set) var rotatedItemIDs: [String] = []
    public var rotateAllItemsError: Error?
    public private(set) var rotateAllAttempts = 0
    /// iCloud 副本观察记录。
    public var cloudBackupEnabled = true
    public var cloudBackupStatusResult: CloudBackupStatus = .ready(itemCount: 0, snapshotRevision: 0)
    public var snapshotRestoreResult = SnapshotRestoreSummary(appliedCount: 0, snapshotRevision: 0)
    public var snapshotRestoreError: Error?
    public private(set) var snapshotUploadCount = 0
    public private(set) var snapshotRestoreCount = 0
    /// §6.7 每条目覆盖（setSnapshotExcluded 写入；loadItems 回读）。
    public var snapshotExcludedItems: Set<String> = []

    // v0.8 §14.8 seams: auto-approval delegation.
    /// Installed policy (nil = never installed); revision 0 goes with it.
    public var delegationPolicy: KeyrefDelegationPolicy?
    public var delegationRevision: UInt64 = 0
    public var putDelegationError: Error?
    /// Every successful PUT, for tests to assert the revision ladder.
    public private(set) var delegationPuts: [(revision: UInt64, policy: KeyrefDelegationPolicy)] = []

    public init(origin: URL = URL(string: "https://sync.keyref.app")!) {
        self.origin = origin
    }

    // MARK: seed helpers for previews/tests

    @discardableResult
    public func seedVault(itemCount: Int = 3, labelPrefix: String = "OpenAI") -> Self {
        hasVault = true
        vaultID = KeyrefEncoding.newID()
        ownDeviceID = KeyrefEncoding.newID()
        unlocked = false
        for i in 0..<itemCount {
            let id = KeyrefEncoding.newID()
            let value = "sk-\(String(repeating: String(i), count: 12))abcd"
            let ref = "test-\(i)"
            let policy = ItemPolicy()
            items.append(ItemRow(
                id: id, ref: ref, name: "\(labelPrefix) \(i)",
                itemDescription: "测试条目 \(i)", type: "api_key",
                masked: "sk-****abcd", policy: policy, injectable: false,
                createdAt: now() - Int64(i) * 1000, updatedAt: now() - Int64(i) * 1000,
                grants: [], ciphertextBytes: 512))
            secrets[id] = value
        }
        cachedItemCount = items.count
        devices.append(DeviceRow(id: KeyrefEncoding.newID(), kind: "ios", status: "active",
                                 label: "这台 iPhone", createdAt: now(),
                                 fingerprint: "1111-2222-3333-4444", grants: []))
        return self
    }

    public func seedDevice(_ label: String, status: String = "active", grants: [GrantSummary] = []) -> DeviceRow {
        let row = DeviceRow(id: KeyrefEncoding.newID(), kind: "cli", status: status,
                            label: label, createdAt: now(),
                            fingerprint: "A1B2-C3D4-E5F6-7890", grants: grants)
        devices.append(row)
        return row
    }

    /// 仅本机条目（§6.6）：sensitivity 派生为 approval、不参与服务器恢复。
    @discardableResult
    public func seedLocalOnlyItem(ref: String, name: String, value: String) -> ItemRow {
        let id = KeyrefEncoding.newID()
        var policy = ItemPolicy()
        policy.sensitivity = StorageClass.localOnly.sensitivity
        let row = ItemRow(
            id: id, ref: ref, name: name, itemDescription: "仅本机条目",
            type: "password", masked: "***", policy: policy, injectable: false,
            createdAt: now(), updatedAt: now(), grants: [], ciphertextBytes: 256,
            storageClass: .localOnly)
        items.append(row)
        secrets[id] = value
        localOnlyItemIDs.insert(id)
        cachedItemCount = items.count
        return row
    }

    func now() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    // MARK: AppBackend

    public func loadLocalState() async {
        cachedItemCount = items.count
    }

    public func unlockAfterBiometrics() async throws {
        guard hasVault else { throw LockError.noVault }
        if localWrapInvalid { throw LockError.wrapInvalid }
        unlocked = true
    }

    public func lock() {
        unlocked = false
    }

    public func checkPrerequisites() -> [Prerequisite] {
        [
            Prerequisite(id: "passcode", title: "设备密码已设置", satisfied: true),
            Prerequisite(id: "biometry", title: "Face ID 已录入", satisfied: true),
        ]
    }

    public func prepareCreation(label: String) async throws -> CreatedVaultDraft {
        let code = RecoveryCode.generatePayload().code
        let draft = CreatedVaultDraft(vaultID: KeyrefEncoding.newID(),
                                      recoveryCode: code,
                                      recoveryGroups: RecoveryCodeGroups.groups(of: code),
                                      uploaded: false)
        pendingVault = draft
        return draft
    }

    public func uploadCreatedVault(_ draft: CreatedVaultDraft) async throws {
        uploadAttempts += 1
        if let uploadError { throw uploadError }
        hasVault = true
        vaultID = draft.vaultID
        ownDeviceID = KeyrefEncoding.newID()
        pendingVault = nil
        var uploaded = draft
        uploaded.uploaded = true
    }

    public func loadItems() async -> [ItemRow] {
        items.sorted { $0.updatedAt > $1.updatedAt }
    }

    public func revealSecret(_ itemID: String) throws -> String {
        secrets[itemID] ?? ""
    }

    public func createItem(_ draft: ItemDraft) async throws {
        if let createItemError { throw createItemError }
        let id = KeyrefEncoding.newID()
        var policy = draft.policy
        policy.sensitivity = draft.storageClass.sensitivity
        items.append(ItemRow(id: id, ref: draft.ref, name: draft.name,
                             itemDescription: draft.itemDescription, type: draft.type,
                             masked: "sk-****abcd", policy: policy,
                             injectable: draft.injectable,
                             createdAt: now(), updatedAt: now(), grants: [],
                             ciphertextBytes: draft.value.utf8.count,
                             storageClass: draft.storageClass))
        secrets[id] = draft.value
        if draft.storageClass == .localOnly { localOnlyItemIDs.insert(id) }
        cachedItemCount = items.count
    }

    public func updateItem(id: String, _ draft: ItemEditDraft) async throws {
        guard let idx = items.firstIndex(where: { $0.id == id }) else { return }
        items[idx].name = draft.name
        items[idx].itemDescription = draft.itemDescription
        var policy = draft.policy
        policy.sensitivity = draft.storageClass.sensitivity
        items[idx].policy = policy
        items[idx].storageClass = draft.storageClass
        items[idx].updatedAt = now()
        if draft.storageClass == .localOnly {
            localOnlyItemIDs.insert(id)
        } else {
            localOnlyItemIDs.remove(id)
        }
        if !draft.value.isEmpty { secrets[id] = draft.value }
    }

    public func deleteItem(id: String) async throws {
        items.removeAll { $0.id == id }
        secrets.removeValue(forKey: id)
        localOnlyItemIDs.remove(id)
        cachedItemCount = items.count
    }

    public func rotateItem(id: String, newValue: String) async throws {
        secrets[id] = newValue
        rotatedItemIDs.append(id)
    }

    public func syncNow() async throws -> SyncOutcomeInfo {
        if let syncError { throw syncError }
        return SyncOutcomeInfo(applied: 0, deleted: 0, revokedSelf: false)
    }

    public func fetchAccount() async -> AccountSnapshot? { accountSnapshot }

    public func probeVaultExists(onOrigin: URL) async -> Bool { probeResult }

    public func loadDevices() async -> [DeviceRow] { devices }

    public func completePairing(offer: PairingOffer, deviceLabel: String,
                                selections: [GrantSelection]) async throws {
        pairingCompletions.append((offer, selections))
        devices.append(DeviceRow(id: KeyrefEncoding.newID(), kind: offer.kind, status: "active",
                                 label: deviceLabel, createdAt: now(),
                                 fingerprint: offer.fingerprint, grants: []))
    }

    public func appendGrants(deviceID: String, _ selections: [GrantSelection]) async throws {
        for s in selections {
            grantOperations.append((deviceID, s.itemID, s.kind, false))
            if let idx = devices.firstIndex(where: { $0.id == deviceID }) {
                devices[idx].grants.append(GrantSummary(deviceID: deviceID, itemID: s.itemID,
                                                        kind: s.kind,
                                                        expiresAt: now() + 30 * 86_400_000))
            }
        }
    }

    public func revokeGrant(deviceID: String, itemID: String, kind: String) async throws {
        grantOperations.append((deviceID, itemID, kind, true))
        if let idx = devices.firstIndex(where: { $0.id == deviceID }) {
            devices[idx].grants.removeAll { $0.itemID == itemID && $0.kind == kind }
        }
    }

    public func renameDevice(deviceID: String, label: String) async throws {
        if let idx = devices.firstIndex(where: { $0.id == deviceID }) {
            devices[idx].label = label
        }
    }

    public func revokeDevice(deviceID: String, rotate: Bool,
                             progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> RevokeSummary {
        await progress(.directory)
        await progress(.grants)
        var rotated = 0
        if rotate {
            let count = useGrantCount(deviceID)
            for i in stride(from: count, through: 1, by: -1) {
                if let stopAt = interruptRotationAt, rotated == stopAt, stopAt < count {
                    pendingRotation[deviceID] = i
                    throw APIError.transport("interrupted")
                }
                await progress(.rotation(remaining: i - 1))
                rotated += 1
            }
        }
        revokedDevices.append(deviceID)
        if let idx = devices.firstIndex(where: { $0.id == deviceID }) {
            devices[idx].status = "revoked"
            devices[idx].grants = []
        }
        return RevokeSummary(deviceID: deviceID, rotatedCount: rotated)
    }

    public func hasPendingRotation(deviceID: String) -> Bool {
        pendingRotation[deviceID] != nil
    }

    public func renewExpiringGrants() async -> Int { 0 }

    public func resumeRotation(deviceID: String,
                               progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> RevokeSummary {
        rotationResumed.append(deviceID)
        let remaining = pendingRotation[deviceID] ?? 0
        for i in stride(from: remaining, through: 1, by: -1) {
            await progress(.rotation(remaining: i - 1))
        }
        pendingRotation.removeValue(forKey: deviceID)
        revokedDevices.append(deviceID)
        if let idx = devices.firstIndex(where: { $0.id == deviceID }) {
            devices[idx].status = "revoked"
            devices[idx].grants = []
        }
        return RevokeSummary(deviceID: deviceID, rotatedCount: remaining)
    }

    func useGrantCount(_ deviceID: String) -> Int {
        devices.first(where: { $0.id == deviceID })?.grants
            .filter { $0.kind == "use" }.count ?? 0
    }

    public func loadEncryptedAuditRows() async -> [AuditRow] { audit }

    public func decryptAuditRows() async -> [AuditRow] {
        audit.map { row in
            var r = row
            if !row.decryptFailed && r.payload == nil {
                r.payload = AuditEventPayload(
                    time: row.createdAt, deviceID: row.deviceID,
                    refs: ["openai-prod"], injection: ["env"],
                    argv: ["curl", "{{keyref:openai-prod}}"], allowArgv: false,
                    policyResult: "allow", childExit: 0, redactions: 1)
            }
            return r
        }
    }

    public func fetchAccountSnapshot() async -> AccountSnapshot? {
        accountSnapshot ?? AccountSnapshot(plan: plan, origin: origin.absoluteString,
                                           limits: nil, usage: nil)
    }

    public func switchOrigin(to newOrigin: URL,
                             progress: @Sendable @escaping (MigrationStep) async -> Void) async throws {
        await progress(.createVaultOnNewOrigin)
        await progress(.fullUpload)
        await progress(.verify)
        origin = newOrigin
        migratedOrigin = newOrigin
    }

    public func deleteVault() async throws {
        deleteAttempts += 1
        if failDeleteVault { throw APIError.transport("failed") }
        hasVault = false
        items = []
        devices = []
        secrets = [:]
        localOnlyItemIDs = []
    }

    public func rotateVMKAndRecovery() async throws -> String {
        rotatedVMKCount += 1
        let code = RecoveryCode.generatePayload().code
        return code
    }

    public func rotateRecoveryCodeFull() async throws -> String {
        rotatedVMKCount += 1
        return RecoveryCode.generatePayload().code
    }

    public func prepareRecovery(code: String, mode: RecoveryMode) async throws -> RecoveryPreparation {
        if failRecoveryCodeCheck { throw RecoveryInputError.badCode }
        if RecoveryCodeGroups.groups(of: code).count != RecoveryCode.symbolCount / 5 + 1 {
            throw RecoveryInputError.badCode
        }
        return RecoveryPreparation(mode: mode, vaultID: vaultID ?? KeyrefEncoding.newID(),
                                   vmk: Data(repeating: 1, count: 32),
                                   deviceCountToRevoke: mode == .takeover ? 3 : 0)
    }

    public func commitRecovery(_ prep: RecoveryPreparation,
                               progress: @Sendable @escaping (RecoveryStep) async -> Void) async throws -> TakeoverSummary {
        await progress(.download)
        await progress(.rotateItems(remaining: items.count))
        hasVault = true
        unlocked = true
        return TakeoverSummary(itemCount: items.count,
                               revokedDeviceCount: prep.deviceCountToRevoke)
    }

    // MARK: approvals (§8.3)

    public func loadPendingApprovals() async -> [ApprovalInboxEntry] {
        approvalLoadCount += 1
        if let approvalsLoadDelay {
            try? await Task.sleep(for: approvalsLoadDelay)
        }
        return approvalEntries
    }

    public func decideApproval(approvalID: String, approve: Bool) async throws {
        if let decideApprovalError { throw decideApprovalError }
        approvalDecisions.append((approvalID, approve))
        approvalEntries.removeAll { $0.approvalID == approvalID }
    }

    // MARK: messages (design v0.8 §14.4)

    /// In-memory inbox for previews and UI tests.
    public var messageEntries: [MessageInboxEntry] = []
    public private(set) var deletedMessageIDs: [String] = []
    public private(set) var messageLoadCount = 0

    public func loadMessages() async -> [MessageInboxEntry] {
        messageLoadCount += 1
        return messageEntries.sorted { $0.createdAt > $1.createdAt }
    }

    public func deleteMessage(messageID: String) async throws {
        deletedMessageIDs.append(messageID)
        messageEntries.removeAll { $0.messageID == messageID }
    }

    public func clearMessages() async throws {
        deletedMessageIDs.append(contentsOf: messageEntries.map(\.messageID))
        messageEntries.removeAll()
    }

    /// Records the 设为主接收端 request for tests and previews.
    public private(set) var primaryReceiverSets: [String?] = []

    public func setPrimaryReceiver(deviceID: String?) async throws {
        primaryReceiverSets.append(deviceID)
    }

    // MARK: push (Phase 2, §13)

    public func putPushToken(token: String, env: String) async -> Bool {
        pushTokenUploads.append((token, env))
        return putPushTokenResult
    }

    // MARK: second iPhone (§9.4 path 2)

    public func prepareJoinOffer(label: String) async throws -> JoinOffer {
        let offer = JoinOffer(
            hpkeKEM: KEMName.p256,
            hpkePublicKey: Data([0x04]) + Data(repeating: 0x11, count: 64),
            signAlg: SignAlg.ecdsaP256,
            signPublicKey: Data([0x04]) + Data(repeating: 0x22, count: 64),
            deviceID: KeyrefEncoding.newID(),
            label: label, origin: origin)
        joinOffers.append(offer)
        return offer
    }

    public func admitSecondDevice(offer: JoinOffer, label: String) async throws -> String {
        if let admitSecondDeviceError { throw admitSecondDeviceError }
        admittedJoins.append((offer, label))
        let handoff = JoinHandoff(
            vaultID: vaultID ?? KeyrefEncoding.newID(),
            newOwnerDeviceID: offer.deviceID,
            directoryRevision: 2,
            ownerSignPublicKey: Data([0x04]) + Data(repeating: 0x33, count: 64),
            vmkWrap: Data(repeating: 0x44, count: 129))
        let payload = nextHandoffPayload ?? JoinHandoffEnvelope(
            handoff: handoff,
            snapshot: localOnlyItemIDs.isEmpty ? nil : Data("memory-snapshot".utf8)).payload()
        return payload
    }

    public func adoptSecondDevice(handoffPayload: String) async throws {
        if let adoptSecondDeviceError { throw adoptSecondDeviceError }
        adoptedHandoffs.append(handoffPayload)
        hasVault = true
        let handoff = try JoinHandoff.parse(handoffPayload)
        vaultID = adoptOverridesVaultID ?? handoff.vaultID
        ownDeviceID = handoff.newOwnerDeviceID
        unlocked = true
        cachedItemCount = items.count
    }

    // MARK: rotation ritual (v0.7, §8.4)

    public func rotateAllItems(progress: @Sendable @escaping (RotationProgress) async -> Void) async throws -> RotationSummary {
        rotateAllAttempts += 1
        if let rotateAllItemsError { throw rotateAllItemsError }
        let total = items.count
        for (i, row) in items.enumerated() {
            rotatedItemIDs.append(row.id)
            await progress(RotationProgress(rotated: i + 1, total: total))
        }
        return RotationSummary(rotatedCount: total, failedCount: 0)
    }

    // MARK: iCloud whole-file copy (v0.7, §6.7)

    public func setCloudBackupEnabled(_ enabled: Bool) {
        cloudBackupEnabled = enabled
    }

    public func uploadSnapshotIfDirty() async {
        snapshotUploadCount += 1
    }

    public func cloudBackupStatus() async -> CloudBackupStatus {
        cloudBackupEnabled ? cloudBackupStatusResult : .disabled
    }

    public func setSnapshotExcluded(itemID: String, excluded: Bool) {
        if excluded {
            snapshotExcludedItems.insert(itemID)
        } else {
            snapshotExcludedItems.remove(itemID)
        }
    }

    @discardableResult
    public func restoreCloudSnapshot() async throws -> SnapshotRestoreSummary {
        snapshotRestoreCount += 1
        if let snapshotRestoreError { throw snapshotRestoreError }
        return snapshotRestoreResult
    }

    // MARK: auto-approval delegation (design v0.8 §14.8)

    /// Seeds an already-installed policy so previews and store tests can
    /// render the 已开启 state without a round trip.
    @discardableResult
    public func seedDelegation(_ policy: KeyrefDelegationPolicy,
                               revision: UInt64 = 1) -> Self {
        delegationPolicy = policy
        delegationRevision = revision
        return self
    }

    public func loadDelegation() async -> DelegationState? {
        guard let policy = delegationPolicy, delegationRevision >= 1 else { return nil }
        return DelegationState(revision: delegationRevision, policy: policy)
    }

    public func putDelegation(revision: UInt64, policy: KeyrefDelegationPolicy) async throws {
        if let putDelegationError { throw putDelegationError }
        // §6.31: strictly greater than what is stored.
        guard revision > delegationRevision else { throw APIError.revisionConflict }
        try policy.validate()
        delegationPuts.append((revision, policy))
        delegationRevision = revision
        delegationPolicy = policy
    }
}
