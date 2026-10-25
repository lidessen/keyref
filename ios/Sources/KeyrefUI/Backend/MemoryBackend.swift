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
        items.append(ItemRow(id: id, ref: draft.ref, name: draft.name,
                             itemDescription: draft.itemDescription, type: draft.type,
                             masked: "sk-****abcd", policy: draft.policy,
                             injectable: draft.injectable,
                             createdAt: now(), updatedAt: now(), grants: [],
                             ciphertextBytes: draft.value.utf8.count))
        secrets[id] = draft.value
        cachedItemCount = items.count
    }

    public func updateItem(id: String, _ draft: ItemEditDraft) async throws {
        guard let idx = items.firstIndex(where: { $0.id == id }) else { return }
        items[idx].name = draft.name
        items[idx].itemDescription = draft.itemDescription
        items[idx].policy = draft.policy
        items[idx].injectable = draft.injectable
        items[idx].updatedAt = now()
        if !draft.value.isEmpty { secrets[id] = draft.value }
    }

    public func deleteItem(id: String) async throws {
        items.removeAll { $0.id == id }
        secrets.removeValue(forKey: id)
        cachedItemCount = items.count
    }

    public func rotateItem(id: String, newValue: String) async throws {
        secrets[id] = newValue
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
        devices.append(DeviceRow(id: KeyrefEncoding.newID(), kind: "cli", status: "active",
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
        approvalEntries
    }

    public func decideApproval(approvalID: String, approve: Bool) async throws {
        if let decideApprovalError { throw decideApprovalError }
        approvalDecisions.append((approvalID, approve))
        approvalEntries.removeAll { $0.approvalID == approvalID }
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
        let payload = nextHandoffPayload ?? handoff.payload()
        return payload
    }

    public func adoptSecondDevice(handoffPayload: String) async throws {
        if let adoptSecondDeviceError { throw adoptSecondDeviceError }
        let handoff = try JoinHandoff.parse(handoffPayload)
        adoptedHandoffs.append(handoffPayload)
        hasVault = true
        vaultID = adoptOverridesVaultID ?? handoff.vaultID
        ownDeviceID = handoff.newOwnerDeviceID
        unlocked = true
        cachedItemCount = items.count
    }
}
