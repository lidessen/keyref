// Production AppBackend: wires the stores to KeyrefCore — Keychain-backed
// KeyStore (docs/design.md §9.3, §9.5), the owner identity, VaultFlows for
// creation/recovery (§8.5, §9.3), ItemCrypto for item sealing (§6.1), the
// SyncEngine (§10.6), PairingClient (§8.1), AuditEnvelope (§7.7) and the
// APIClient endpoints (protocol §5–§6). @MainActor: the crypto calls are
// sync and fast; network calls are async.
import Foundation
import KeyrefCore
import LocalAuthentication

/// Token box the APIClient reads from any thread.
final class SessionBox: @unchecked Sendable {
    private let lock = NSLock()
    private var token: String?
    func set(_ t: String?) { lock.lock(); defer { lock.unlock() }; token = t }
    func get() -> String? { lock.lock(); defer { lock.unlock() }; return token }
}

@MainActor
public final class LiveBackend: AppBackend {
    public let keyStore: KeyStore
    public let stateStore: UIStateStore
    /// 仅本机条目的 secret 密文（AES-GCM(item key)，锁机后是惰性字节，
    /// §6.6）。生产用 SQLite 实现；测试/预览注入内存实现。
    public let localSecrets: LocalSecretStore
    /// iCloud 整文件副本的存储缝（§6.7）。nil = 此构建未启用（设置里显示
    /// 「副本不可用」，本地功能不受影响）。
    public let snapshotStore: (any SnapshotStore)?
    let sessionBox = SessionBox()

    public private(set) var hasVault = false
    public private(set) var vaultID: String?
    public private(set) var ownDeviceID: String?
    public private(set) var cachedItemCount = 0
    public private(set) var localWrapInvalid = false
    public private(set) var origin: URL
    public private(set) var plan = "free"
    public private(set) var frozen = false

    var vmk: Data?
    var owner: OwnerKeys?
    var renewalSigner: Ed25519Signer?
    var pendingCreation: CreateVaultRequest?
    var pendingRecovery: PendingRecovery?
    /// 新手机在「加入已有保险库」时暂存的 owner 身份（§9.4 path 2），
    /// adopt 时才落 Keychain——取消加入就不留痕迹。
    var pendingJoin: PendingJoin?
    /// Device ids whose §8.4 rotation is mid-flight (§2.10 失败态).
    var pendingRotation: [String: Int] = [:]
    var auditCursor: Int64 = 0
    var encryptedAudit: [EncryptedAuditRow] = []
    /// 最近一次拉到的待审批原始行 + 已解开的明文（decide 时复用，§8.3）。
    var approvalRecords: [String: ApprovalRecord] = [:]
    /// §6.7 全局开关（默认开）+ 去抖脏标记（编辑后置位，退后台消费）。
    var cloudBackupEnabled = true
    var snapshotDirty = false

    struct PendingJoin {
        var owner: OwnerKeys
        var deviceID: String
        var label: String
    }

    struct ApprovalRecord {
        var row: PendingApproval
        var plaintext: ApprovalRequestPlaintext
    }

    struct EncryptedAuditRow: Sendable {
        var seq: Int64
        var createdAt: Int64
        var deviceID: String
        var ciphertext: Data
    }

    struct PendingRecovery {
        var mode: RecoveryMode
        var plan: VaultFlows.TakeoverPlan
        var newDeviceID: String
    }

    let urlSession: URLSession

    public init(keyStore: KeyStore, stateStore: UIStateStore,
                origin: URL = URL(string: "https://sync.keyref.app")!,
                urlSession: URLSession = .shared,
                localSecrets: LocalSecretStore = InMemoryLocalSecretStore(),
                snapshotStore: (any SnapshotStore)? = nil) {
        self.keyStore = keyStore
        self.stateStore = stateStore
        self.origin = origin
        self.urlSession = urlSession
        self.localSecrets = localSecrets
        self.snapshotStore = snapshotStore
    }

    var api: APIClient {
        APIClient(baseURL: origin, session: urlSession,
                  bearerToken: { [sessionBox] in sessionBox.get() })
    }

    // MARK: - lifecycle (S2/S3/S4)

    public func loadLocalState() async {
        if let stored = try? keyStore.retrieve(.vaultID), !stored.isEmpty,
           let id = String(data: stored, encoding: .utf8) {
            vaultID = id
            hasVault = true
        } else {
            vaultID = nil
            hasVault = false
        }
        ownDeviceID = stateStore.ownID()
        cachedItemCount = stateStore.allItems().count
        localWrapInvalid = false
    }

    public func unlockAfterBiometrics() async throws {
        guard hasVault, let vaultID else { throw LockError.noVault }
        localWrapInvalid = false
        guard let wrapData = try? keyStore.retrieve(.vmkWrap) else {
            throw LockError.wrapInvalid
        }
        guard let owner = loadOwnerKeys() else { throw LockError.wrapInvalid }
        let deviceID = stateStore.ownID() ?? ""
        do {
            vmk = try VaultFlows.unwrapLocalVMK(owner: owner, wrap: wrapData,
                                                vaultID: vaultID, ownerDeviceID: deviceID)
            self.owner = owner
        } catch {
            // Re-enrolled biometry invalidated the enclave wrap (§9.5): S4.
            throw LockError.wrapInvalid
        }
    }

    func loadOwnerKeys() -> OwnerKeys? {
        if let keys = try? OwnerKeys.load(from: keyStore, enclaveBacked: true) {
            return keys
        }
        return try? OwnerKeys.load(from: keyStore, enclaveBacked: false)
    }

    public func lock() {
        vmk = nil
    }

    // MARK: - creation (§2.2, §9.3)

    public func checkPrerequisites() -> [Prerequisite] {
        let ctx = LAContext()
        var err: NSError?
        if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) {
            return [
                Prerequisite(id: "passcode", title: "设备密码已设置", satisfied: true),
                Prerequisite(id: "biometry", title: "Face ID 已录入", satisfied: true),
            ]
        }
        let code = LAError.Code(rawValue: err?.code ?? 0)
        let passcodeOK = code != .passcodeNotSet
        let biometryOK = code != .biometryNotEnrolled && code != .biometryNotAvailable
            && code != .biometryLockout && code != .passcodeNotSet
        return [
            Prerequisite(id: "passcode", title: "设备密码已设置", satisfied: passcodeOK),
            Prerequisite(id: "biometry", title: "Face ID 已录入", satisfied: biometryOK),
        ]
    }

    /// Owner generation with the documented fallback chain. On hosts without
    /// an enclave or passcode (the simulator) software keys with weaker
    /// storage keep the flow walkable — never a silent substitution (§9.2).
    func generateOwnerKeys() throws -> OwnerKeys {
        if let keys = try? OwnerKeys.generate(preferEnclave: true, biometryRequired: true) {
            return keys
        }
        if let keys = try? OwnerKeys.generate(preferEnclave: true, biometryRequired: false) {
            return keys
        }
        return try OwnerKeys.generate(preferEnclave: false)
    }

    public func prepareCreation(label: String) async throws -> CreatedVaultDraft {
        let owner = try generateOwnerKeys()
        var renewalSeed = Data(count: 32)
        _ = renewalSeed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let renewal = try Ed25519Signer(seed: renewalSeed)
        let deviceID = KeyrefEncoding.newID()

        let created = try VaultFlows.createVault(owner: owner, ownerDeviceID: deviceID,
                                                 label: label, renewalSigner: renewal)
        let vaultID = created.request.vaultID

        // Persist (§9.3 steps 2–3). Enclave dataRepresentations carry their
        // own access control; software scalars use ThisDeviceOnly storage.
        try owner.persist(to: keyStore, biometryRequired: false)
        try keyStore.store(.renewalSignPrivate, renewalSeed)
        try keyStore.store(.vaultID, Data(vaultID.utf8))
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID, recipientDeviceID: deviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                               recipientPublicKey: owner.kemPublicKey,
                                               info: info, plaintext: created.vmk)
        try keyStore.store(.vmkWrap, enc + ct)

        try stateStore.setVaultID(vaultID)
        try stateStore.setOwnDeviceID(deviceID)
        try stateStore.setPinnedOwnerKey(owner.signPublicKey)
        try stateStore.setCursor(0)
        stateStore.setDeviceInfo(UIStateStore.DeviceInfo(label: label, createdAt: nowMillis()), for: deviceID)

        self.owner = owner
        self.renewalSigner = renewal
        self.ownDeviceID = deviceID
        self.vaultID = vaultID
        self.hasVault = true
        self.vmk = created.vmk
        pendingCreation = created.request

        return CreatedVaultDraft(vaultID: vaultID,
                                 recoveryCode: created.recoveryCode,
                                 recoveryGroups: RecoveryCodeGroups.groups(of: created.recoveryCode),
                                 uploaded: false)
    }

    public func uploadCreatedVault(_ draft: CreatedVaultDraft) async throws {
        guard let request = pendingCreation else {
            throw APIError.transport("no pending creation")
        }
        _ = try await api.createVault(request)
        pendingCreation = nil
        if let owner, let deviceID = ownDeviceID {
            if let session = try? await SessionClient(api: api).start(deviceID: deviceID,
                                                                      signer: owner.signer) {
                sessionBox.set(session.token)
            }
        }
        _ = try? await syncNow()
    }

    // MARK: - items (§2.4–§2.6)

    func guardUnlocked() throws -> (vmk: Data, owner: OwnerKeys, vaultID: String) {
        guard let vmk, let owner, let vaultID else { throw LockError.noVault }
        return (vmk, owner, vaultID)
    }

    public func loadItems() async -> [ItemRow] {
        guard let (vmk, _, vaultID) = try? guardUnlocked() else { return [] }
        let rows = stateStore.allItems()
        let grants = stateStore.allGrants()
        var out: [ItemRow] = []
        out.reserveCapacity(rows.count)
        for row in rows where !row.tombstone {
            guard let meta = try? decryptMeta(row, vmk: vmk, vaultID: vaultID) else { continue }
            let itemGrants = grants.filter { $0.itemID == row.itemID && !$0.deleted }
                .map { GrantSummary(deviceID: $0.deviceID, itemID: $0.itemID,
                                    kind: $0.kind, expiresAt: $0.expiresAt) }
            out.append(ItemRow(
                id: row.itemID, ref: meta.ref, name: meta.name,
                itemDescription: meta.description, type: meta.type, masked: meta.masked,
                policy: meta.policy, injectable: meta.injectable,
                createdAt: row.updatedAt, updatedAt: row.updatedAt,
                grants: itemGrants,
                ciphertextBytes: row.metaCiphertext.count
                    + row.secretCiphertext.count
                    + ((try? localSecrets.record(itemID: row.itemID))??.secretCiphertext.count ?? 0),
                storageClass: StorageClass(sensitivity: meta.policy.sensitivity)))
        }
        cachedItemCount = out.count
        return out.sorted { $0.updatedAt > $1.updatedAt }
    }

    func decryptMeta(_ row: ItemData, vmk: Data, vaultID: String) throws -> ItemMeta {
        let metaKey = try ItemCrypto.unwrapMetaKey(vmk: vmk, blob: row.vaultWrappedMetaKey,
                                                   vaultID: vaultID, itemID: row.itemID)
        return try ItemCrypto.openMeta(key: metaKey, blob: row.metaCiphertext,
                                       vaultID: vaultID, itemID: row.itemID)
    }

    /// 仅本机条目的 secret 密文不在服务器行上（secret_ciphertext = NULL，
    /// §6.6）——从本地加密存储取字节、用本地包裹解 item key。解锁路径与
    /// 同步条目相同：都需要先解出 VMK。
    func decryptSecret(_ row: ItemData, vmk: Data, vaultID: String) throws -> SecretPlaintext {
        let itemKey: Data
        let blob: Data
        if row.vaultWrappedItemKey.isEmpty || row.secretCiphertext.isEmpty {
            guard let record = try localSecrets.record(itemID: row.itemID),
                  !record.secretCiphertext.isEmpty, !record.vaultWrappedItemKey.isEmpty else {
                throw KeyrefCryptoError.invalidBlob
            }
            itemKey = try ItemCrypto.unwrapItemKey(vmk: vmk, blob: record.vaultWrappedItemKey,
                                                   vaultID: vaultID, itemID: row.itemID)
            blob = record.secretCiphertext
        } else {
            itemKey = try ItemCrypto.unwrapItemKey(vmk: vmk, blob: row.vaultWrappedItemKey,
                                                   vaultID: vaultID, itemID: row.itemID)
            blob = row.secretCiphertext
        }
        return try ItemCrypto.openSecret(key: itemKey, blob: blob,
                                         vaultID: vaultID, itemID: row.itemID)
    }

    public func revealSecret(_ itemID: String) throws -> String {
        let (vmk, _, vaultID) = try guardUnlocked()
        guard let row = stateStore.itemByID(itemID) else { return "" }
        return try decryptSecret(row, vmk: vmk, vaultID: vaultID).value
    }

    public func createItem(_ draft: ItemDraft) async throws {
        let (vmk, owner, vaultID) = try guardUnlocked()
        let deviceID = ownDeviceID ?? ""
        let itemID = KeyrefEncoding.newID()
        let meta = ItemMeta(v: 1, ref: draft.ref, name: draft.name,
                            description: draft.itemDescription, type: draft.type,
                            masked: maskOf(draft.value, type: draft.type),
                            injectable: draft.injectable, policy: draft.policy)
        let secret = SecretPlaintext(v: 1, value: draft.value)
        if draft.storageClass == .localOnly {
            // 仅本机（§6.6）：签名誊本与 PUT 只带 meta 材料，secret 密文与
            // item key 包裹落本地加密存储。
            let sealed = try ItemCrypto.sealLocalOnlyItem(vaultID: vaultID, itemID: itemID,
                                                          revision: 1, writerDeviceID: deviceID,
                                                          vmk: vmk, signer: owner.signer,
                                                          meta: meta, secret: secret)
            storeLocalOnly(sealed, itemID: itemID, revision: 1, vaultID: vaultID, deviceID: deviceID)
            snapshotDirty = true
        } else {
            let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: itemID, revision: 1,
                                                 writerDeviceID: deviceID, vmk: vmk,
                                                 signer: owner.signer, meta: meta, secret: secret)
            storeSealed(sealed, itemID: itemID, revision: 1, vaultID: vaultID, deviceID: deviceID)
        }
        _ = try? await syncPut(itemID: itemID, vaultID: vaultID)
    }

    public func updateItem(id: String, _ draft: ItemEditDraft) async throws {
        let (vmk, owner, vaultID) = try guardUnlocked()
        let deviceID = ownDeviceID ?? ""
        guard let row = stateStore.itemByID(id),
              let oldMeta = try? decryptMeta(row, vmk: vmk, vaultID: vaultID),
              let oldSecret = try? decryptSecret(row, vmk: vmk, vaultID: vaultID) else {
            throw APIError.notFound
        }
        let currentClass = StorageClass(sensitivity: oldMeta.policy.sensitivity)
        // 同步 → 仅本机不可行（§6.6）：服务器上已有的密文无法撤回。
        guard !(currentClass == .synced && draft.storageClass == .localOnly) else {
            throw APIError.invalidField
        }
        let value = draft.value.isEmpty ? oldSecret.value : draft.value
        let targetClass = draft.storageClass
        let meta = ItemMeta(v: 1, ref: oldMeta.ref, name: draft.name,
                            description: draft.itemDescription, type: oldMeta.type,
                            masked: maskOf(value, type: oldMeta.type),
                            injectable: draft.injectable,
                            policy: ItemPolicy(sensitivity: targetClass.sensitivity,
                                               commandPolicy: draft.policy.commandPolicy,
                                               allowCommands: draft.policy.allowCommands,
                                               allowedHosts: draft.policy.allowedHosts,
                                               allowArgv: draft.policy.allowArgv))
        let secret = SecretPlaintext(v: 1, value: value)
        let revision = row.revision + 1
        switch (currentClass, targetClass) {
        case (.localOnly, .localOnly):
            // meta 重封、item key 不变；secret 用同一把 key 重加密，本地包裹更新。
            let itemKey = try unwrapLocalItemKey(row, vmk: vmk, vaultID: vaultID)
            let metaKey = try ItemCrypto.unwrapMetaKey(vmk: vmk, blob: row.vaultWrappedMetaKey,
                                                       vaultID: vaultID, itemID: id)
            let metaCT = try ItemCrypto.sealMeta(key: metaKey, meta: meta,
                                                 vaultID: vaultID, itemID: id)
            let secretCT = try ItemCrypto.sealSecret(key: itemKey, secret: secret,
                                                     vaultID: vaultID, itemID: id)
            let vwMeta = try ItemCrypto.wrapMetaKeyWithVMK(vmk: vmk, metaKey: metaKey,
                                                           vaultID: vaultID, itemID: id)
            let vwItem = try ItemCrypto.wrapItemKeyWithVMK(vmk: vmk, itemKey: itemKey,
                                                           vaultID: vaultID, itemID: id)
            let t = ItemTranscript(vaultID: vaultID, itemID: id, revision: revision,
                                   metaCiphertext: metaCT, secretCiphertext: Data(),
                                   vaultWrappedMetaKey: vwMeta, vaultWrappedItemKey: Data(),
                                   writerDeviceID: deviceID)
            let signature = try owner.signer.sign(t.buildBytes())
            try? stateStore.upsertItem(ItemData.make(
                vaultID: vaultID, itemID: id, revision: revision, tombstone: false,
                metaCiphertext: metaCT, secretCiphertext: Data(),
                vaultWrappedMetaKey: vwMeta, vaultWrappedItemKey: Data(),
                writerDeviceID: deviceID, signature: signature, updatedAt: nowMillis()))
            let oldRecord = try localSecrets.record(itemID: id)
                ?? LocalSecretRecord(itemID: id, secretCiphertext: Data(),
                                     vaultWrappedItemKey: Data(), revision: 0, updatedAt: 0)
            try localSecrets.save(LocalSecretRecord(
                itemID: id, secretCiphertext: secretCT, vaultWrappedItemKey: vwItem,
                revision: max(oldRecord.revision, revision), updatedAt: nowMillis()))
            snapshotDirty = true
        case (.localOnly, .synced):
            // 仅本机 → 同步：新 revision 全量上传（secret 首次上服务器）。
            let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: id, revision: revision,
                                                 writerDeviceID: deviceID, vmk: vmk,
                                                 signer: owner.signer, meta: meta, secret: secret)
            storeSealed(sealed, itemID: id, revision: revision, vaultID: vaultID, deviceID: deviceID)
            try localSecrets.remove(itemID: id)
            snapshotDirty = true
        default:
            let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: id, revision: revision,
                                                 writerDeviceID: deviceID, vmk: vmk,
                                                 signer: owner.signer, meta: meta, secret: secret)
            storeSealed(sealed, itemID: id, revision: revision, vaultID: vaultID, deviceID: deviceID)
        }
        _ = try? await syncPut(itemID: id, vaultID: vaultID)
    }

    public func deleteItem(id: String) async throws {
        let (_, owner, vaultID) = try guardUnlocked()
        let deviceID = ownDeviceID ?? ""
        let revision = (stateStore.itemByID(id)?.revision ?? 0) + 1
        let signature = try ItemCrypto.signTombstone(vaultID: vaultID, itemID: id,
                                                     revision: revision,
                                                     writerDeviceID: deviceID,
                                                     signer: owner.signer)
        try stateStore.deleteItem(id)
        try? localSecrets.remove(itemID: id)
        snapshotDirty = true
        _ = try? await api.deleteItem(itemID: id,
                                      DeleteItemRequest.make(revision: revision, signature: signature))
    }

    public func rotateItem(id: String, newValue: String) async throws {
        let (vmk, owner, vaultID) = try guardUnlocked()
        let deviceID = ownDeviceID ?? ""
        guard let row = stateStore.itemByID(id),
              let meta = try? decryptMeta(row, vmk: vmk, vaultID: vaultID),
              let old = try? decryptSecret(row, vmk: vmk, vaultID: vaultID) else {
            throw APIError.notFound
        }
        let value = newValue.isEmpty ? old.value : newValue
        if StorageClass.of(row) == .localOnly {
            // 仅本机：只轮换本地包裹（新 item key、重加密、重包裹），不动
            // 服务器（§8.4 定期轮换 / §2.5 替换值）。
            let record = try localSecrets.record(itemID: id)
                ?? LocalSecretRecord(itemID: id, secretCiphertext: Data(),
                                     vaultWrappedItemKey: Data(),
                                     revision: row.revision, updatedAt: nowMillis())
            let updated = try ItemCrypto.rotateLocalOnlySecret(vaultID: vaultID, itemID: id,
                                                               vmk: vmk, meta: meta,
                                                               secret: SecretPlaintext(v: 1, value: value),
                                                               oldRecord: record)
            try localSecrets.save(updated)
            snapshotDirty = true
            return
        }
        try await reencryptItem(row, meta: meta, value: value,
                                vaultID: vaultID, owner: owner, deviceID: deviceID)
    }

    func putRequest(_ sealed: ItemCrypto.SealedItem, revision: UInt64, deviceID: String) -> PutItemRequest {
        PutItemRequest.make(revision: revision, tombstone: false,
                       metaCiphertext: sealed.transcript.metaCiphertext,
                       secretCiphertext: sealed.transcript.secretCiphertext,
                       vaultWrappedMetaKey: sealed.transcript.vaultWrappedMetaKey,
                       vaultWrappedItemKey: sealed.transcript.vaultWrappedItemKey,
                       writerDeviceID: deviceID, signature: sealed.signature)
    }

    /// PUT /v1/items/:item_id from the locally stored row: full material for
    /// synced items, meta-only for 仅本机 (§6.6: secret_ciphertext 省略,
    /// vault_wrapped_item_key 不上传——服务器上没有 use 授权，用不到它).
    func syncPut(itemID: String, vaultID: String) async throws {
        guard let row = stateStore.itemByID(itemID), !row.tombstone else { return }
        let localOnly = StorageClass.of(row) == .localOnly
        let put = PutItemRequest.make(
            revision: row.revision, tombstone: false,
            metaCiphertext: row.metaCiphertext,
            secretCiphertext: localOnly ? Data() : row.secretCiphertext,
            vaultWrappedMetaKey: row.vaultWrappedMetaKey,
            vaultWrappedItemKey: localOnly ? Data() : row.vaultWrappedItemKey,
            writerDeviceID: row.writerDeviceID, signature: row.signature)
        _ = try? await api.putItem(itemID: itemID, put)
    }

    /// 仅本机条目：行里只有 meta 材料；secret 密文与 item key 包裹进本地
    /// 加密存储（§6.6）。
    func storeLocalOnly(_ sealed: ItemCrypto.SealedLocalOnlyItem, itemID: String,
                        revision: UInt64, vaultID: String, deviceID: String) {
        try? stateStore.upsertItem(ItemData.make(
            vaultID: vaultID, itemID: itemID, revision: revision, tombstone: false,
            metaCiphertext: sealed.transcript.metaCiphertext,
            secretCiphertext: Data(),
            vaultWrappedMetaKey: sealed.transcript.vaultWrappedMetaKey,
            vaultWrappedItemKey: Data(),
            writerDeviceID: deviceID, signature: sealed.signature,
            updatedAt: nowMillis()))
        try? localSecrets.save(LocalSecretRecord(
            itemID: itemID, secretCiphertext: sealed.secretCiphertext,
            vaultWrappedItemKey: sealed.vaultWrappedItemKey,
            revision: revision, updatedAt: nowMillis()))
    }

    /// Unwraps a local-only item's key from its LOCAL wrap (the server row
    /// carries no vault_wrapped_item_key, §6.6).
    func unwrapLocalItemKey(_ row: ItemData, vmk: Data, vaultID: String) throws -> Data {
        if !row.vaultWrappedItemKey.isEmpty {
            return try ItemCrypto.unwrapItemKey(vmk: vmk, blob: row.vaultWrappedItemKey,
                                                vaultID: vaultID, itemID: row.itemID)
        }
        guard let record = try localSecrets.record(itemID: row.itemID),
              !record.vaultWrappedItemKey.isEmpty else {
            throw KeyrefCryptoError.invalidBlob
        }
        return try ItemCrypto.unwrapItemKey(vmk: vmk, blob: record.vaultWrappedItemKey,
                                            vaultID: vaultID, itemID: row.itemID)
    }

    func storeSealed(_ sealed: ItemCrypto.SealedItem, itemID: String, revision: UInt64,
                     vaultID: String, deviceID: String) {
        try? stateStore.upsertItem(ItemData.make(
            vaultID: vaultID, itemID: itemID, revision: revision, tombstone: false,
            metaCiphertext: sealed.transcript.metaCiphertext,
            secretCiphertext: sealed.transcript.secretCiphertext,
            vaultWrappedMetaKey: sealed.transcript.vaultWrappedMetaKey,
            vaultWrappedItemKey: sealed.transcript.vaultWrappedItemKey,
            writerDeviceID: deviceID, signature: sealed.signature,
            updatedAt: nowMillis()))
    }

    /// New item key, re-encrypt, re-wrap `use` grants to remaining active
    /// devices (§8.4 step 3). Returns how many grants were re-wrapped.
    @discardableResult
    func reencryptItem(_ row: ItemData, meta: ItemMeta, value: String,
                       vaultID: String, owner: OwnerKeys, deviceID: String) async throws -> Int {
        let vmk = try guardUnlocked().vmk
        let revision = row.revision + 1
        let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: row.itemID,
                                             revision: revision, writerDeviceID: deviceID,
                                             vmk: vmk, signer: owner.signer,
                                             meta: meta, secret: SecretPlaintext(v: 1, value: value))
        storeSealed(sealed, itemID: row.itemID, revision: revision,
                    vaultID: vaultID, deviceID: deviceID)
        _ = try? await api.putItem(itemID: row.itemID,
                                   putRequest(sealed, revision: revision, deviceID: deviceID))
        var rewrapped = 0
        var newGrants: [GrantData] = []
        for grant in stateStore.allGrants()
        where grant.itemID == row.itemID && grant.kind == "use" && !grant.deleted {
            guard let device = directoryDevices()?.first(where: { $0.deviceID == grant.deviceID }),
                  device.status == DeviceStatus.active else { continue }
            let (enc, ct) = try ItemCrypto.wrapGrantKey(
                kemName: device.hpkeKEM, recipientPublicKey: device.hpkePublicKey,
                kind: "use", vaultID: vaultID, recipientDeviceID: device.deviceID,
                key: sealed.itemKey)
            var g = GrantData.make(deviceID: device.deviceID, itemID: row.itemID, kind: "use",
                              hpkeEnc: enc, wrappedKey: ct, expiresAt: grant.expiresAt,
                              revision: grant.revision + 1, signature: Data(), deleted: false)
            g.signature = try owner.signer.sign(g.transcript(vaultID: vaultID).buildBytes())
            newGrants.append(g)
            rewrapped += 1
        }
        if !newGrants.isEmpty {
            _ = try? await api.putGrants(PutGrantsRequest.make(grants: newGrants))
            for g in newGrants { try? stateStore.upsertGrant(g) }
        }
        return rewrapped
    }

    func maskOf(_ value: String, type: String) -> String {
        guard !value.isEmpty else { return "***" }
        switch type {
        case "password", "note": return "***"
        default:
            let tail = value.suffix(4)
            return "\(value.prefix(3))****\(tail)"
        }
    }

    func nowMillis() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    // MARK: - sync & account (§2.4, §2.17)

    @discardableResult
    public func syncNow() async throws -> SyncOutcomeInfo {
        let engine = SyncEngine(api: api)
        do {
            let outcome = try await engine.run(store: stateStore)
            frozen = false
            cachedItemCount = stateStore.allItems().count
            return SyncOutcomeInfo(applied: outcome.applied, deleted: outcome.deleted,
                                   revokedSelf: outcome.revokedSelf)
        } catch let e as APIError {
            if case .vaultFrozen = e { frozen = true }
            throw e
        }
    }

    public func fetchAccount() async -> AccountSnapshot? { await fetchAccountSnapshot() }

    public func probeVaultExists(onOrigin url: URL) async -> Bool {
        guard let vaultID else { return false }
        let probe = APIClient(baseURL: url)
        do {
            _ = try await probe.getRecoveryMaterials(vaultID: vaultID)
            return true
        } catch APIError.notFound {
            return false
        } catch {
            return true  // inconclusive → stay on the safe path
        }
    }

    // MARK: - devices & grants (§2.7–§2.10)

    func directoryDevices() -> [KeyrefDirectoryDevice]? {
        guard let vaultID, let dir = stateStore.currentDirectory() else { return nil }
        return try? VaultFlows.parseVerifiedDevices(dir.signed, vaultID: vaultID)
    }

    public func loadDevices() async -> [DeviceRow] {
        let grants = stateStore.allGrants()
        let infos = stateStore.allDeviceInfo()
        let rows: [DeviceRow] = (directoryDevices() ?? []).map { d in
            let dg = grants.filter { $0.deviceID == d.deviceID && !$0.deleted }
                .map { GrantSummary(deviceID: $0.deviceID, itemID: $0.itemID,
                                    kind: $0.kind, expiresAt: $0.expiresAt) }
            let label = infos[d.deviceID]?.label ?? d.fingerprint
            let createdAt = infos[d.deviceID]?.createdAt ?? 0
            return DeviceRow(id: d.deviceID, kind: d.kind, status: d.status, label: label,
                             createdAt: createdAt,
                             revokedAt: d.status == DeviceStatus.revoked ? 0 : nil,
                             fingerprint: d.fingerprint, grants: dg)
        }
        return rows
    }

    public func completePairing(offer: PairingOffer, deviceLabel: String,
                                selections: [GrantSelection]) async throws {
        let (vmk, owner, vaultID) = try guardUnlocked()
        let device = DeviceInput.make(
            deviceID: KeyrefEncoding.newID(), kind: DeviceKind.cli,
            hpkeKEM: offer.hpkeKEM, hpkePublicKey: offer.hpkePublicKey,
            signAlg: offer.signAlg, signPublicKey: offer.signPublicKey,
            label: deviceLabel, renewalSignPublicKey: Data())
        var grants: [GrantData] = []
        var revision: UInt64 = 1
        let expires = nowMillis() + 30 * 86_400_000
        for selection in selections {
            guard let row = stateStore.itemByID(selection.itemID) else { continue }
            // 仅本机条目永远没有 use 授予（§6.6）；UI 已隐藏，这里兜底。
            if selection.kind == "use", StorageClass.of(row) == .localOnly { continue }
            let key: Data
            if selection.kind == "use" {
                key = try ItemCrypto.unwrapItemKey(vmk: vmk, blob: row.vaultWrappedItemKey,
                                                   vaultID: vaultID, itemID: row.itemID)
            } else {
                key = try ItemCrypto.unwrapMetaKey(vmk: vmk, blob: row.vaultWrappedMetaKey,
                                                   vaultID: vaultID, itemID: row.itemID)
            }
            let (enc, ct) = try ItemCrypto.wrapGrantKey(
                kemName: device.hpkeKEM, recipientPublicKey: device.hpkePublicKey,
                kind: selection.kind, vaultID: vaultID,
                recipientDeviceID: device.deviceID, key: key)
            var g = GrantData.make(deviceID: device.deviceID, itemID: row.itemID, kind: selection.kind,
                              hpkeEnc: enc, wrappedKey: ct, expiresAt: expires,
                              revision: revision, signature: Data(), deleted: false)
            g.signature = try owner.signer.sign(g.transcript(vaultID: vaultID).buildBytes())
            grants.append(g)
            revision += 1
        }
        try await PairingClient(api: api).complete(vaultID: vaultID, nonce: offer.nonce,
                                                   device: device, grants: grants,
                                                   ownerSigner: owner.signer)
        stateStore.setDeviceInfo(UIStateStore.DeviceInfo(label: deviceLabel, createdAt: nowMillis()),
                                  for: device.deviceID)
        _ = try? await syncNow()
    }

    public func appendGrants(deviceID: String, _ selections: [GrantSelection]) async throws {
        let (vmk, owner, vaultID) = try guardUnlocked()
        guard let device = directoryDevices()?.first(where: { $0.deviceID == deviceID }) else {
            throw APIError.notFound
        }
        var rows: [GrantData] = []
        var revision = (stateStore.allGrants().filter { $0.deviceID == deviceID }
            .map { $0.revision }.max() ?? 0) + 1
        let expires = nowMillis() + 30 * 86_400_000
        for selection in selections {
            guard let row = stateStore.itemByID(selection.itemID) else { continue }
            if selection.kind == "use", StorageClass.of(row) == .localOnly { continue }  // §6.6
            let key: Data
            if selection.kind == "use" {
                key = try ItemCrypto.unwrapItemKey(vmk: vmk, blob: row.vaultWrappedItemKey,
                                                   vaultID: vaultID, itemID: row.itemID)
            } else {
                key = try ItemCrypto.unwrapMetaKey(vmk: vmk, blob: row.vaultWrappedMetaKey,
                                                   vaultID: vaultID, itemID: row.itemID)
            }
            let (enc, ct) = try ItemCrypto.wrapGrantKey(
                kemName: device.hpkeKEM, recipientPublicKey: device.hpkePublicKey,
                kind: selection.kind, vaultID: vaultID, recipientDeviceID: deviceID, key: key)
            var g = GrantData.make(deviceID: deviceID, itemID: row.itemID, kind: selection.kind,
                              hpkeEnc: enc, wrappedKey: ct, expiresAt: expires,
                              revision: revision, signature: Data(), deleted: false)
            g.signature = try owner.signer.sign(g.transcript(vaultID: vaultID).buildBytes())
            rows.append(g)
            revision += 1
        }
        _ = try? await api.putGrants(PutGrantsRequest.make(grants: rows))
        for g in rows { try? stateStore.upsertGrant(g) }
    }

    public func revokeGrant(deviceID: String, itemID: String, kind: String) async throws {
        let (_, owner, vaultID) = try guardUnlocked()
        guard let grant = stateStore.allGrants().first(where: {
            $0.deviceID == deviceID && $0.itemID == itemID && $0.kind == kind && !$0.deleted
        }) else { throw APIError.notFound }
        let revision = grant.revision + 1
        let t = GrantTranscript.deletion(vaultID: vaultID, deviceID: deviceID,
                                         itemID: itemID, kind: kind, revision: revision)
        let signature = try owner.signer.sign(t.buildBytes())
        try stateStore.deleteGrant(itemID: itemID, kind: kind)
        _ = try? await api.deleteGrant(DeleteGrantRequest.make(deviceID: deviceID, itemID: itemID,
                                                          kind: kind, revision: revision,
                                                          signature: signature))
    }

    public func renameDevice(deviceID: String, label: String) async throws {
        var info = stateStore.info(for: deviceID) ?? UIStateStore.DeviceInfo(label: label, createdAt: nowMillis())
        info.label = label
        stateStore.setDeviceInfo(info, for: deviceID)
    }

    public func revokeDevice(deviceID: String, rotate: Bool,
                             progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> RevokeSummary {
        let (_, owner, vaultID) = try guardUnlocked()
        // 1. Sign a new directory with the device revoked (§8.4 step 1) —
        // lands locally first; the revoke itself is not reversible (§2.10).
        await progress(.directory)
        try await updateDirectoryRevoking(deviceID: deviceID, owner: owner, vaultID: vaultID)
        // 2. Delete its grants (§8.4 step 2).
        await progress(.grants)
        try await deleteGrantsOfDevice(deviceID: deviceID, owner: owner, vaultID: vaultID)
        // 3. Rotate item keys it could use (§8.4 step 3). Resumable (§2.10).
        var rotated = 0
        if rotate {
            do {
                rotated = try await rotateGrantedItems(deviceID: deviceID, progress: progress)
                pendingRotation.removeValue(forKey: deviceID)
            } catch {
                // 撤销已生效、轮换可重入（§2.10 失败态）：记录剩余数。
                pendingRotation[deviceID] = pendingRotation[deviceID]
                    ?? deviceUseGrantCount(deviceID: deviceID)
                throw error
            }
        }
        return RevokeSummary(deviceID: deviceID, rotatedCount: rotated)
    }

    func deviceUseGrantCount(deviceID: String) -> Int {
        stateStore.allGrants().filter { $0.deviceID == deviceID && $0.kind == "use" && !$0.deleted }.count
    }

    public func resumeRotation(deviceID: String,
                               progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> RevokeSummary {
        let rotated = try await rotateGrantedItems(deviceID: deviceID, progress: progress)
        pendingRotation.removeValue(forKey: deviceID)
        return RevokeSummary(deviceID: deviceID, rotatedCount: rotated)
    }

    public func hasPendingRotation(deviceID: String) -> Bool {
        pendingRotation[deviceID] != nil
    }

    func updateDirectoryRevoking(deviceID: String, owner: OwnerKeys, vaultID: String) async throws {
        guard let dir = stateStore.currentDirectory(),
              var devices = directoryDevices(),
              let idx = devices.firstIndex(where: { $0.deviceID == deviceID }) else {
            throw APIError.notFound
        }
        let old = devices[idx]
        devices[idx] = KeyrefDirectoryDevice(
            deviceID: old.deviceID, kind: old.kind, status: DeviceStatus.revoked,
            hpkeKEM: old.hpkeKEM, hpkePublicKey: old.hpkePublicKey,
            signAlg: old.signAlg, signPublicKey: old.signPublicKey,
            renewalSignPublicKey: old.renewalSignPublicKey,
            grantsDigest: old.grantsDigest)
        try await publishDirectory(devices, revision: dir.directoryRevision + 1,
                                   owner: owner, vaultID: vaultID)
    }

    func publishDirectory(_ devices: [KeyrefDirectoryDevice], revision: UInt64,
                          owner: OwnerKeys, vaultID: String) async throws {
        let dd: [DirectoryDevice] = devices.map {
            DirectoryDevice(deviceID: $0.deviceID, kind: $0.kind, status: $0.status,
                            hpkeKEM: $0.hpkeKEM, hpkePublicKey: $0.hpkePublicKey,
                            signAlg: $0.signAlg, signPublicKey: $0.signPublicKey,
                            renewalSignPublicKey: $0.renewalSignPublicKey,
                            grantsDigest: $0.grantsDigest)
        }
        let transcript = DirectoryTranscript(vaultID: vaultID, directoryRevision: revision, devices: dd)
        let bytes = try transcript.buildBytes()
        let signature = try owner.signer.sign(bytes)
        try stateStore.storeDirectory(DirectoryData.make(directoryRevision: revision,
                                                    signed: bytes, signature: signature))
        _ = try await api.putDirectory(PutDirectoryRequest.make(directoryRevision: revision,
                                                           directorySigned: bytes,
                                                           signature: signature))
    }

    func deleteGrantsOfDevice(deviceID: String, owner: OwnerKeys, vaultID: String) async throws {
        for grant in stateStore.allGrants()
        where grant.deviceID == deviceID && !grant.deleted {
            let revision = grant.revision + 1
            let t = GrantTranscript.deletion(vaultID: vaultID, deviceID: deviceID,
                                             itemID: grant.itemID, kind: grant.kind,
                                             revision: revision)
            let signature = try owner.signer.sign(t.buildBytes())
            try stateStore.deleteGrant(itemID: grant.itemID, kind: grant.kind)
            _ = try? await api.deleteGrant(DeleteGrantRequest.make(deviceID: deviceID,
                                                              itemID: grant.itemID,
                                                              kind: grant.kind,
                                                              revision: revision,
                                                              signature: signature))
        }
    }

    /// Rotation of every item the device held a `use` grant on (§8.4).
    /// Resumable: directory + grant deletion landed first (§2.10 失败态).
    func rotateGrantedItems(deviceID: String,
                            progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> Int {
        let (vmk, owner, vaultID) = try guardUnlocked()
        let ownDevice = ownDeviceID ?? ""
        let itemIDs = Set(stateStore.allGrants()
            .filter { $0.deviceID == deviceID && $0.kind == "use" && !$0.deleted }
            .map { $0.itemID })
        var remaining = itemIDs.count
        for itemID in itemIDs.sorted() {
            guard let row = stateStore.itemByID(itemID),
                  let meta = try? decryptMeta(row, vmk: vmk, vaultID: vaultID),
                  let secret = try? decryptSecret(row, vmk: vmk, vaultID: vaultID) else {
                remaining = max(0, remaining - 1)
                continue
            }
            try await reencryptItem(row, meta: meta, value: secret.value,
                                    vaultID: vaultID, owner: owner, deviceID: ownDevice)
            remaining = max(0, remaining - 1)
            await progress(.rotation(remaining: remaining))
        }
        return itemIDs.count
    }

    // MARK: - audit (§2.11, §7.7)

    public func loadEncryptedAuditRows() async -> [AuditRow] {
        do {
            let page = try await api.getAuditPage(cursor: auditCursor)
            for row in page.events {
                encryptedAudit.append(EncryptedAuditRow(seq: row.seq, createdAt: row.createdAt,
                                                        deviceID: row.deviceID,
                                                        ciphertext: row.ciphertext))
            }
            auditCursor = page.cursor
        } catch {
            // keep cached rows; the caller surfaces the failure
        }
        return encryptedAudit.map {
            AuditRow(seq: $0.seq, createdAt: $0.createdAt, deviceID: $0.deviceID,
                     payload: nil, decryptFailed: false)
        }
    }

    public func decryptAuditRows() async -> [AuditRow] {
        guard let owner, let vaultID, let deviceID = ownDeviceID else {
            return encryptedAudit.map {
                AuditRow(seq: $0.seq, createdAt: $0.createdAt, deviceID: $0.deviceID,
                         payload: nil, decryptFailed: true)
            }
        }
        var out: [AuditRow] = []
        for row in encryptedAudit {
            do {
                let payload = try AuditEnvelope.open(envelope: row.ciphertext, vaultID: vaultID,
                                                     reportingDeviceID: row.deviceID,
                                                     owner: owner, ownerDeviceID: deviceID)
                out.append(AuditRow(seq: row.seq, createdAt: payload.time,
                                    deviceID: row.deviceID, payload: payload,
                                    decryptFailed: false))
            } catch {
                out.append(AuditRow(seq: row.seq, createdAt: row.createdAt,
                                    deviceID: row.deviceID, payload: nil,
                                    decryptFailed: true))
            }
        }
        return out
    }

    // MARK: - settings (§2.14–§2.17)

    public func fetchAccountSnapshot() async -> AccountSnapshot? {
        do {
            let account = try await api.account()
            plan = account.plan
            return AccountSnapshot(plan: account.plan, origin: origin.absoluteString,
                                   limits: account.limits, usage: account.usage)
        } catch {
            return AccountSnapshot(plan: plan, origin: origin.absoluteString,
                                   limits: nil, usage: nil)
        }
    }

    public func switchOrigin(to newOrigin: URL,
                             progress: @Sendable @escaping (MigrationStep) async -> Void) async throws {
        // 空库：直接改，无确认页（§2.15）。
        guard hasVault, let owner, let vaultID else {
            origin = newOrigin
            return
        }
        let deviceID = ownDeviceID ?? ""
        let newAPI = APIClient(baseURL: newOrigin, bearerToken: { [sessionBox] in sessionBox.get() })

        // Recovery material stays valid — the same seed derived it; the
        // recovery code does not change (§8.5: 迁移不重新生成主密钥).
        await progress(.createVaultOnNewOrigin)
        let materials = try await api.getRecoveryMaterials(vaultID: vaultID)
        let device = DeviceInput.make(
            deviceID: deviceID, kind: DeviceKind.ios,
            hpkeKEM: owner.kemKEMName, hpkePublicKey: owner.kemPublicKey,
            signAlg: owner.signer.signAlg, signPublicKey: owner.signPublicKey,
            label: stateStore.info(for: deviceID)?.label ?? "这台 iPhone",
            renewalSignPublicKey: renewalSigner?.signPublicKey ?? Data())
        let ownerDevice = DirectoryDevice(
            deviceID: deviceID, kind: DeviceKind.ios, status: DeviceStatus.active,
            hpkeKEM: owner.kemKEMName, hpkePublicKey: owner.kemPublicKey,
            signAlg: owner.signer.signAlg, signPublicKey: owner.signPublicKey,
            renewalSignPublicKey: renewalSigner?.signPublicKey ?? Data(),
            grantsDigest: emptyGrantsDigest())
        let transcript = DirectoryTranscript(vaultID: vaultID, directoryRevision: 1,
                                             devices: [ownerDevice])
        let dirBytes = try transcript.buildBytes()
        let create = CreateVaultRequest.make(
            vaultID: vaultID, device: device,
            recoveryWrap: materials.recoveryWrap,
            recoveryKDFJSON: materials.recoveryKDFJSON,
            recoverySignPub: materials.recoverySignPub,
            directoryRevision: 1, directorySigned: dirBytes,
            signature: try owner.signer.sign(dirBytes), pow: nil)
        _ = try await newAPI.createVault(create)

        // Full upload: re-seal every item at fresh revisions on the new vault
        // (§2.15: 新服务器上会重建这个保险库，并上传全部密文).
        await progress(.fullUpload)
        let vmk = try guardUnlocked().vmk
        var revision: UInt64 = 1
        for row in stateStore.allItems() where !row.tombstone {
            guard let meta = try? decryptMeta(row, vmk: vmk, vaultID: vaultID),
                  let secret = try? decryptSecret(row, vmk: vmk, vaultID: vaultID) else { continue }
            let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: row.itemID,
                                                 revision: revision, writerDeviceID: deviceID,
                                                 vmk: vmk, signer: owner.signer,
                                                 meta: meta, secret: secret)
            _ = try await newAPI.putItem(itemID: row.itemID,
                                         putRequest(sealed, revision: revision, deviceID: deviceID))
            revision += 1
        }

        await progress(.verify)
        try stateStore.setCursor(0)
        origin = newOrigin
        if let session = try? await SessionClient(api: api).start(deviceID: deviceID,
                                                                  signer: owner.signer) {
            sessionBox.set(session.token)
        }
        let engine = SyncEngine(api: api)
        _ = try? await engine.run(store: stateStore)
    }

    public func deleteVault() async throws {
        guard let vaultID, let owner else { throw LockError.noVault }
        // Two steps (§11): challenge first, then the owner-signed confirm.
        let (challenge, _) = try await api.requestVaultDeleteChallenge(vaultID: vaultID)
        let t = try buildVaultDeleteTranscript(vaultID: vaultID, challenge: challenge)
        let signature = try owner.signer.sign(t)
        try await api.deleteVault(vaultID: vaultID, challenge: challenge, signature: signature)
        // Confirmed by the server — only now tear down locally (§2.16:
        // 绝不显示「已删除」，除非服务器确认成功).
        try? keyStore.removeAll()
        stateStore.wipeAll()
        try? localSecrets.removeAll()   // 仅本机 secret 密文随库删除（§6.6）
        vmk = nil
        self.owner = nil
        hasVault = false
        self.vaultID = nil
        ownDeviceID = nil
        cachedItemCount = 0
        snapshotDirty = false
    }

    public func rotateVMKAndRecovery() async throws -> String {
        try await rotateRecovery(layerOnly: true)
    }

    public func rotateRecoveryCodeFull() async throws -> String {
        try await rotateRecovery(layerOnly: false)
    }

    /// §8.4: 只换包裹层 (layerOnly) vs B5 全套 (rotate every item key and
    /// re-encrypt). Both publish a new recovery code, shown exactly once (S9).
    func rotateRecovery(layerOnly: Bool) async throws -> String {
        guard let owner, let vaultID, let deviceID = ownDeviceID else { throw LockError.noVault }
        let currentVMK = try guardUnlocked().vmk
        let newVMK = randomKey()

        for row in stateStore.allItems() where !row.tombstone {
            let metaKey = try ItemCrypto.unwrapMetaKey(vmk: currentVMK, blob: row.vaultWrappedMetaKey,
                                                       vaultID: vaultID, itemID: row.itemID)
            let itemKey = try ItemCrypto.unwrapItemKey(vmk: currentVMK, blob: row.vaultWrappedItemKey,
                                                       vaultID: vaultID, itemID: row.itemID)
            let metaCT = row.metaCiphertext
            let secretCT: Data
            if layerOnly {
                secretCT = row.secretCiphertext
            } else {
                let plain = try ItemCrypto.openSecret(key: itemKey, blob: row.secretCiphertext,
                                                      vaultID: vaultID, itemID: row.itemID)
                secretCT = try ItemCrypto.sealSecret(key: itemKey, secret: plain,
                                                     vaultID: vaultID, itemID: row.itemID)
            }
            let vwMeta = try ItemCrypto.wrapMetaKeyWithVMK(vmk: newVMK, metaKey: metaKey,
                                                           vaultID: vaultID, itemID: row.itemID)
            let vwItem = try ItemCrypto.wrapItemKeyWithVMK(vmk: newVMK, itemKey: itemKey,
                                                           vaultID: vaultID, itemID: row.itemID)
            let revision = row.revision + 1
            let t = ItemTranscript(vaultID: vaultID, itemID: row.itemID, revision: revision,
                                   metaCiphertext: metaCT, secretCiphertext: secretCT,
                                   vaultWrappedMetaKey: vwMeta, vaultWrappedItemKey: vwItem,
                                   writerDeviceID: deviceID)
            let signature = try owner.signer.sign(t.buildBytes())
            let put = PutItemRequest.make(revision: revision, tombstone: false,
                                     metaCiphertext: metaCT, secretCiphertext: secretCT,
                                     vaultWrappedMetaKey: vwMeta, vaultWrappedItemKey: vwItem,
                                     writerDeviceID: deviceID, signature: signature)
            try? stateStore.upsertItem(ItemData.make(vaultID: vaultID, itemID: row.itemID,
                                                revision: revision, tombstone: false,
                                                metaCiphertext: metaCT, secretCiphertext: secretCT,
                                                vaultWrappedMetaKey: vwMeta,
                                                vaultWrappedItemKey: vwItem,
                                                writerDeviceID: deviceID, signature: signature,
                                                updatedAt: nowMillis()))
            _ = try? await api.putItem(itemID: row.itemID, put)
        }

        // Re-wrap the local VMK wrap (new wrap layer, §8.4).
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID, recipientDeviceID: deviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                               recipientPublicKey: owner.kemPublicKey,
                                               info: info, plaintext: newVMK)
        try keyStore.store(.vmkWrap, enc + ct)
        vmk = newVMK

        let (request, code, _) = try VaultFlows.replaceRecoveryMaterial(vaultID: vaultID,
                                                                        vmk: newVMK, owner: owner)
        try await api.putVaultRecovery(request)
        return code
    }

    // MARK: - recovery (§2.12, §2.13)

    public func prepareRecovery(code: String, mode: RecoveryMode) async throws -> RecoveryPreparation {
        // Parse first — malformed input never reaches the network.
        guard let parsed = try? RecoveryCode.decode(code) else {
            throw RecoveryInputError.badCode
        }
        let materials: RecoveryMaterialsResponse
        do {
            materials = try await api.getRecoveryMaterials(vaultID: parsed.vaultID)
        } catch let e as APIError {
            switch e {
            case .notFound: throw RecoveryInputError.vaultNotFound
            case .rateLimited: throw RecoveryInputError.rateLimited
            case .transport: throw RecoveryInputError.network("连不上服务器，稍后重试。")
            default: throw RecoveryInputError.network("服务器返回了错误，稍后重试。")
            }
        } catch {
            throw RecoveryInputError.network("连不上服务器，稍后重试。")
        }
        guard let owner = try? generateOwnerKeys() else {
            throw RecoveryInputError.network("无法生成这台手机的密钥。")
        }
        let newDeviceID = mode == .takeover ? KeyrefEncoding.newID() : (ownDeviceID ?? KeyrefEncoding.newID())
        do {
            let plan: VaultFlows.TakeoverPlan
            if mode == .takeover {
                plan = try VaultFlows.planTakeover(recoveryCode: code,
                                                   recoveryMaterials: materials,
                                                   newOwner: owner,
                                                   newOwnerDeviceID: newDeviceID,
                                                   label: "这台 iPhone")
            } else {
                plan = try buildLocalRebuildPlan(code: code, materials: materials,
                                                 owner: owner, myID: newDeviceID)
            }
            try owner.persist(to: keyStore, biometryRequired: false)
            self.owner = owner
            pendingRecovery = PendingRecovery(mode: mode, plan: plan, newDeviceID: newDeviceID)
            let revoked = (try? VaultFlows.parseVerifiedDevices(plan.directoryTranscript,
                                                                vaultID: plan.vaultID))?
                .filter { $0.status == DeviceStatus.revoked }.count ?? 0
            return RecoveryPreparation(mode: mode, vaultID: plan.vaultID, vmk: plan.vmk,
                                       deviceCountToRevoke: revoked)
        } catch {
            // The AEAD tag is the "code correct" verdict (§8.5).
            throw RecoveryInputError.badCode
        }
    }

    /// 本机重建 (§9.5): only this device's row is refreshed; other devices
    /// stay untouched; no revocation alert; local ciphertext stays.
    func buildLocalRebuildPlan(code: String, materials: RecoveryMaterialsResponse,
                               owner: OwnerKeys, myID: String) throws -> VaultFlows.TakeoverPlan {
        let parsed = try RecoveryCode.decode(code)
        let keys = try RecoveryKeys.derive(fromSeed: parsed.seed)
        let vmk = try RecoveryKeys.unwrapVMK(keys: keys, recoveryWrap: materials.recoveryWrap,
                                             vaultID: parsed.vaultID)
        let previous = try VaultFlows.parseVerifiedDevices(materials.directorySigned,
                                                           vaultID: parsed.vaultID)
        var devices: [DirectoryDevice] = []
        var foundSelf = false
        for d in previous {
            if d.deviceID == myID {
                foundSelf = true
                devices.append(DirectoryDevice(
                    deviceID: myID, kind: DeviceKind.ios, status: DeviceStatus.active,
                    hpkeKEM: owner.kemKEMName, hpkePublicKey: owner.kemPublicKey,
                    signAlg: owner.signer.signAlg, signPublicKey: owner.signPublicKey,
                    renewalSignPublicKey: d.renewalSignPublicKey,
                    grantsDigest: d.grantsDigest))
            } else {
                devices.append(DirectoryDevice(
                    deviceID: d.deviceID, kind: d.kind, status: d.status,
                    hpkeKEM: d.hpkeKEM, hpkePublicKey: d.hpkePublicKey,
                    signAlg: d.signAlg, signPublicKey: d.signPublicKey,
                    renewalSignPublicKey: d.renewalSignPublicKey,
                    grantsDigest: d.grantsDigest))
            }
        }
        if !foundSelf {
            devices.append(DirectoryDevice(
                deviceID: myID, kind: DeviceKind.ios, status: DeviceStatus.active,
                hpkeKEM: owner.kemKEMName, hpkePublicKey: owner.kemPublicKey,
                signAlg: owner.signer.signAlg, signPublicKey: owner.signPublicKey,
                renewalSignPublicKey: Data(), grantsDigest: emptyGrantsDigest()))
        }
        let revision = materials.directoryRevision + 1
        let transcript = DirectoryTranscript(vaultID: parsed.vaultID,
                                             directoryRevision: revision, devices: devices)
        let bytes = try transcript.buildBytes()
        let request = RecoveryDirectoryRequest.make(
            vaultID: parsed.vaultID, directoryRevision: revision,
            directorySigned: bytes,
            recoverySignature: try keys.signer.sign(bytes),
            ownerSignature: try owner.signer.sign(bytes))
        return VaultFlows.makeTakeoverPlan(vaultID: parsed.vaultID, vmk: vmk,
                                           request: request, directoryTranscript: bytes)
    }

    public func commitRecovery(_ prep: RecoveryPreparation,
                               progress: @Sendable @escaping (RecoveryStep) async -> Void) async throws -> TakeoverSummary {
        guard let owner, let pending = pendingRecovery, pending.mode == prep.mode else {
            throw RecoveryInputError.badCode
        }
        // Irreversible commit (§2.12: 提交后，之前的所有设备立即失去同步).
        let session = try await api.submitRecoveryDirectory(pending.plan.request)
        sessionBox.set(session.token)
        pendingRecovery = nil
        try stateStore.setVaultID(prep.vaultID)
        try stateStore.setPinnedOwnerKey(owner.signPublicKey)
        try stateStore.setOwnDeviceID(pending.newDeviceID)
        try stateStore.setCursor(0)
        vaultID = prep.vaultID
        ownDeviceID = pending.newDeviceID
        hasVault = true
        localWrapInvalid = false
        vmk = prep.vmk

        if prep.mode == .takeover {
            // 下载全部密文 (cursor 0 bootstrap, §10.6).
            await progress(.download)
            let engine = SyncEngine(api: api)
            _ = try? await engine.run(store: stateStore)
        } else {
            // 校验本地密文 — ciphertext already here (§2.13 difference).
            _ = stateStore.allItems().count
        }

        // Auto background step (§2.12): rotate the item keys the revoked
        // devices held — §8.4 default action, no confirmation needed.
        let itemCount = stateStore.allItems().filter { !$0.tombstone }.count
        if prep.mode == .takeover {
            // 仅本机条目的 iCloud 副本要用新 owner 的密钥重签上传（§6.7）。
            snapshotDirty = true
            await progress(.rotateItems(remaining: itemCount))
            let vmk = prep.vmk
            let deviceID = pending.newDeviceID
            var remaining = itemCount
            for row in stateStore.allItems() where !row.tombstone {
                if let meta = try? decryptMeta(row, vmk: vmk, vaultID: prep.vaultID),
                   let secret = try? decryptSecret(row, vmk: vmk, vaultID: prep.vaultID) {
                    try? await reencryptItem(row, meta: meta, value: secret.value,
                                             vaultID: prep.vaultID, owner: owner,
                                             deviceID: deviceID)
                }
                remaining = max(0, remaining - 1)
                await progress(.rotateItems(remaining: remaining))
            }
        }
        return TakeoverSummary(itemCount: itemCount,
                               revokedDeviceCount: prep.deviceCountToRevoke)
    }

    // MARK: - approvals (Phase 2, §8.3, protocol §6.19–§6.21)

    /// Pulls pending approvals and prepares them for display: open the
    /// request for this owner, re-verify the CLI signature against the
    /// signed directory (§8.3 step 3 — 通过才展示；验不过显示为无效并可忽略).
    public func loadPendingApprovals() async -> [ApprovalInboxEntry] {
        guard let vaultID, let owner, let deviceID = ownDeviceID, vmk != nil else {
            return []
        }
        let rows: [PendingApproval]
        do {
            rows = try await api.listApprovals(status: "pending").approvals
        } catch {
            return []
        }
        let devices = directoryDevices() ?? []
        let infos = stateStore.allDeviceInfo()
        var out: [ApprovalInboxEntry] = []
        approvalRecords.removeAll()
        for row in rows {
            let device = devices.first { $0.deviceID == row.cliDeviceID }
            let label = infos[row.cliDeviceID]?.label ?? device?.fingerprint ?? row.cliDeviceID
            guard let device else {
                // 发起设备不在签名目录里：无从验证，视为无效。
                out.append(.invalid(row, cliDeviceLabel: label))
                continue
            }
            do {
                let plaintext = try ApprovalFlows.openRequest(row, owner: owner,
                                                              vaultID: vaultID,
                                                              ownerDeviceID: deviceID)
                try ApprovalFlows.verifyRequestSignature(row, device: device)
                try ApprovalFlows.validatePlaintext(plaintext, pending: row)
                approvalRecords[row.approvalID] = ApprovalRecord(row: row, plaintext: plaintext)
                let itemMeta = stateStore.itemByID(row.itemID).flatMap {
                    try? decryptMeta($0, vmk: vmk!, vaultID: vaultID)
                }
                out.append(ApprovalInboxEntry(
                    approvalID: row.approvalID,
                    cliDeviceID: row.cliDeviceID,
                    cliDeviceLabel: label,
                    itemID: row.itemID,
                    itemName: itemMeta?.name ?? row.itemID,
                    itemRef: itemMeta?.ref ?? "",
                    argv: plaintext.argv,
                    refs: plaintext.refs,
                    injection: plaintext.injection,
                    hosts: plaintext.hosts,
                    createdAt: row.createdAt,
                    expiresAt: row.expiresAt,
                    valid: true))
            } catch {
                out.append(.invalid(row, cliDeviceLabel: label))
            }
        }
        return out
    }

    public func decideApproval(approvalID: String, approve: Bool) async throws {
        guard let vaultID else { throw LockError.noVault }
        guard let record = approvalRecords[approvalID] else {
            throw APIError.notFound
        }
        let decision: ApprovalDecisionRequest
        if approve {
            // §8.3 step 3: Face ID 已过（调用方），现在用请求里的临时
            // X25519 公钥包裹该条目 item key——只对这一次请求、这一个条目。
            guard let (vmkValue, _, _) = try? guardUnlocked() else {
                throw LockError.noVault
            }
            guard let itemRow = stateStore.itemByID(record.plaintext.itemID) else {
                throw APIError.notFound
            }
            if StorageClass.of(itemRow) == .localOnly {
                // 仅本机条目（§6.6）：服务器上没有 secret_ciphertext，包裹
                // 载荷换成 secret 密文本身（info 绑定不变）。
                let record_ = try localSecrets.record(itemID: itemRow.itemID)
                let secretCT: Data
                if let localRecord = record_, !localRecord.secretCiphertext.isEmpty {
                    secretCT = localRecord.secretCiphertext
                } else if !itemRow.secretCiphertext.isEmpty {
                    secretCT = itemRow.secretCiphertext
                } else {
                    throw KeyrefCryptoError.invalidBlob
                }
                decision = try ApprovalFlows.approveSecretDeliveryDecision(
                    vaultID: vaultID, pending: record.row,
                    plaintext: record.plaintext, secretCiphertext: secretCT)
            } else {
                let itemKey = try ItemCrypto.unwrapItemKey(vmk: vmkValue,
                                                           blob: itemRow.vaultWrappedItemKey,
                                                           vaultID: vaultID,
                                                           itemID: record.plaintext.itemID)
                decision = try ApprovalFlows.approveDecision(vaultID: vaultID,
                                                             pending: record.row,
                                                             plaintext: record.plaintext,
                                                             itemKey: itemKey)
            }
        } else {
            decision = ApprovalFlows.denyDecision()
        }
        try await api.submitApprovalDecision(approvalID: approvalID, decision)
        approvalRecords.removeValue(forKey: approvalID)
    }

    // MARK: - second iPhone (Phase 2, §9.4 path 2)

    /// 新手机：生成 owner 身份（暂存内存，adopt 才落 Keychain），出 join offer。
    public func prepareJoinOffer(label: String) async throws -> JoinOffer {
        guard !hasVault else {
            throw APIError.invalidField  // 已有保险库的设备不走加入流程
        }
        let joinOwner = try generateOwnerKeys()
        let deviceID = KeyrefEncoding.newID()
        pendingJoin = PendingJoin(owner: joinOwner, deviceID: deviceID, label: label)
        return JoinOffer(hpkeKEM: joinOwner.kemKEMName,
                         hpkePublicKey: joinOwner.kemPublicKey,
                         signAlg: joinOwner.signer.signAlg,
                         signPublicKey: joinOwner.signPublicKey,
                         deviceID: deviceID,
                         label: label,
                         origin: origin)
    }

    /// 旧手机：签「两台 owner 都 active」的新目录（revision + 1）交给服务器
    /// （PUT /v1/directory，设备行随目录落库），再把 VMK HPKE 给新手机。
    public func admitSecondDevice(offer: JoinOffer, label: String) async throws -> String {
        let (vmk, owner, vaultID) = try guardUnlocked()
        guard offer.deviceID != ownDeviceID,
              KeyrefEncoding.isValidID(offer.deviceID) else {
            throw KeyrefWireError.invalidField("new owner device id is not valid")
        }
        guard let current = stateStore.currentDirectory() else {
            throw APIError.notFound
        }
        let join = try OwnerPairing.buildJoinDirectory(vaultID: vaultID, offer: offer,
                                                       currentDirectorySigned: current.signed)
        let joinDevices = join.devices.map {
            KeyrefDirectoryDevice(deviceID: $0.deviceID, kind: $0.kind, status: $0.status,
                                  hpkeKEM: $0.hpkeKEM, hpkePublicKey: $0.hpkePublicKey,
                                  signAlg: $0.signAlg, signPublicKey: $0.signPublicKey,
                                  renewalSignPublicKey: $0.renewalSignPublicKey,
                                  grantsDigest: $0.grantsDigest)
        }
        try await publishDirectory(joinDevices, revision: join.revision,
                                   owner: owner, vaultID: vaultID)
        let wrap = try OwnerPairing.wrapVMK(vmk: vmk, vaultID: vaultID, offer: offer)
        let handoff = JoinHandoff(vaultID: vaultID,
                                  newOwnerDeviceID: offer.deviceID,
                                  directoryRevision: join.revision,
                                  ownerSignPublicKey: owner.signPublicKey,
                                  vmkWrap: wrap)
        stateStore.setDeviceInfo(UIStateStore.DeviceInfo(label: label, createdAt: nowMillis()),
                                 for: offer.deviceID)
        _ = try? await syncNow()
        // 转移即分叉（§9.4 / §6.6 双 owner 行）：交接载荷带上仅本机条目的
        // 快照 blob（§6.7 快照格式，owner 签名）。此后两台各自编辑、不合并。
        var envelope = JoinHandoffEnvelope(handoff: handoff, snapshot: nil)
        if let snapshot = buildLocalOnlySnapshot(signer: owner.signer) {
            envelope.snapshot = snapshot.data
        }
        return envelope.payload()
    }

    /// 新手机：解 VMK（AEAD tag = 判真伪）、落 Keychain、开 session、
    /// cursor=0 引导全部密文（§10.6）；交接码里的仅本机快照验签后入库
    /// （§9.4 转移即分叉）。
    public func adoptSecondDevice(handoffPayload: String) async throws {
        guard let pending = pendingJoin else {
            throw APIError.transport("no pending join offer")
        }
        let envelope = try JoinHandoffEnvelope.parse(handoffPayload)
        let handoff = envelope.handoff
        guard handoff.newOwnerDeviceID == pending.deviceID else {
            throw KeyrefWireError.invalidField("handoff is for another device")
        }
        let joinVMK = try OwnerPairing.unwrapHandoffVMK(handoff, owner: pending.owner)

        try pending.owner.persist(to: keyStore, biometryRequired: false)
        try keyStore.store(.vmkWrap, handoff.vmkWrap)
        try keyStore.store(.vaultID, Data(handoff.vaultID.utf8))
        try stateStore.setVaultID(handoff.vaultID)
        try stateStore.setPinnedOwnerKey(handoff.ownerSignPublicKey)
        try stateStore.setOwnDeviceID(pending.deviceID)
        try stateStore.setCursor(0)
        stateStore.setDeviceInfo(UIStateStore.DeviceInfo(label: pending.label, createdAt: nowMillis()),
                                 for: pending.deviceID)

        owner = pending.owner
        renewalSigner = nil
        vaultID = handoff.vaultID
        ownDeviceID = pending.deviceID
        hasVault = true
        localWrapInvalid = false
        vmk = joinVMK
        pendingJoin = nil

        if let session = try? await SessionClient(api: api).start(deviceID: pending.deviceID,
                                                                  signer: pending.owner.signer) {
            sessionBox.set(session.token)
        }
        let engine = SyncEngine(api: api)
        _ = try? await engine.run(store: stateStore)
        // 转移即分叉：交接快照（仅本机条目）先验签（用旧 owner 的签名公钥，
        // 即交接码里那把）再入库（§9.4）。快照的 revision 单调延续。
        if let snapshot = envelope.snapshot, !snapshot.isEmpty {
            _ = try? SnapshotEngine.restore(
                data: snapshot, vaultID: handoff.vaultID,
                rows: stateStore.allItems(), state: stateStore,
                secrets: localSecrets,
                trustedOwnerKeys: [handoff.ownerSignPublicKey])
            try? localSecrets.setSnapshotRevision(
                (try? SnapshotCodec.parseUnverified(snapshot))?.snapshotRevision ?? 0)
            snapshotDirty = true
        }
    }

    // MARK: - push (Phase 2, §13)

    public func putPushToken(token: String, env: String) async -> Bool {
        // 仅会话有效时上传；否则静默跳过——注册状态机在下次解锁后重试。
        guard sessionBox.get() != nil else { return false }
        do {
            try await api.putPushToken(token: token, env: env)
            return true
        } catch {
            // 静默失败（会话过期 / 网络 / 限流）：轮询兜底照常，下次注册重试。
            return false
        }
    }

    // MARK: - rotation ritual (v0.7, §8.4 定期轮换)

    /// 立即轮换全部条目。同步条目走既有 per-item 原子 PUT（新 item key、
    /// 重包裹、重加密、revision + 1，重发 use 授权）；仅本机条目只轮换本地
    /// 包裹（§8.4：不动服务器）。逐条自洽：某条失败计入 failedCount 并继续，
    /// 整轮重试即可补齐（已轮换的条目再轮换一次无副作用）。
    public func rotateAllItems(progress: @Sendable @escaping (RotationProgress) async -> Void) async throws -> RotationSummary {
        let (vmk, owner, vaultID) = try guardUnlocked()
        let deviceID = ownDeviceID ?? ""
        let rows = stateStore.allItems().filter { !$0.tombstone }.sorted { $0.itemID < $1.itemID }
        var rotated = 0
        var failed = 0
        for (index, row) in rows.enumerated() {
            do {
                if StorageClass.of(row) == .localOnly {
                    guard let meta = try? decryptMeta(row, vmk: vmk, vaultID: vaultID),
                          let secret = try? decryptSecret(row, vmk: vmk, vaultID: vaultID) else {
                        throw KeyrefCryptoError.invalidBlob
                    }
                    let record = try localSecrets.record(itemID: row.itemID)
                        ?? LocalSecretRecord(itemID: row.itemID, secretCiphertext: Data(),
                                             vaultWrappedItemKey: Data(),
                                             revision: row.revision, updatedAt: nowMillis())
                    let updated = try ItemCrypto.rotateLocalOnlySecret(
                        vaultID: vaultID, itemID: row.itemID, vmk: vmk, meta: meta,
                        secret: secret, oldRecord: record)
                    try localSecrets.save(updated)
                    snapshotDirty = true
                } else {
                    guard let meta = try? decryptMeta(row, vmk: vmk, vaultID: vaultID),
                          let secret = try? decryptSecret(row, vmk: vmk, vaultID: vaultID) else {
                        throw KeyrefCryptoError.invalidBlob
                    }
                    try await reencryptItem(row, meta: meta, value: secret.value,
                                            vaultID: vaultID, owner: owner, deviceID: deviceID)
                }
                rotated += 1
            } catch {
                failed += 1
            }
            await progress(RotationProgress(rotated: index + 1, total: rows.count))
        }
        return RotationSummary(rotatedCount: rotated, failedCount: failed)
    }

    // MARK: - iCloud whole-file copy (v0.7, §6.7)

    public func setCloudBackupEnabled(_ enabled: Bool) {
        cloudBackupEnabled = enabled
    }

    /// 编辑后退后台的去抖上传（§6.7）：合并云端（「revision 大者胜」双向）、
    /// 以更高的 snapshot_revision 重传。签名需要 owner 密钥——Face ID 场景
    /// 下失败就保留脏标记，下次后台/解锁再试（绝不阻塞本地功能）。
    public func uploadSnapshotIfDirty() async {
        guard snapshotDirty, cloudBackupEnabled, hasVault,
              let vaultID, let owner, snapshotStore != nil else { return }
        snapshotDirty = false
        do {
            _ = try await uploadSnapshotNow(vaultID: vaultID, owner: owner)
        } catch {
            snapshotDirty = true  // 下次再试（§6.7：绝不因此阻塞本地功能）
        }
    }

    /// Trusted owner sign keys for snapshot verification: the pinned key
    /// plus every owner key recorded in the signed directory (a pre-takeover
    /// snapshot is signed by the pre-takeover owner, §6.7 恢复路径).
    func trustedOwnerKeys() -> [Data] {
        var keys: [Data] = []
        if let pinned = try? stateStore.pinnedOwnerKey(), !pinned.isEmpty {
            keys.append(pinned)
        }
        if let own = owner {
            keys.append(own.signPublicKey)
        }
        for device in directoryDevices() ?? [] where device.kind == DeviceKind.ios {
            keys.append(device.signPublicKey)
        }
        return keys
    }

    func buildLocalOnlySnapshot(signer: TranscriptSigner) -> SnapshotBuildResult? {
        guard let vaultID else { return nil }
        let revision = (try? localSecrets.snapshotRevision()) ?? 0
        return try? SnapshotEngine.build(
            vaultID: vaultID, snapshotRevision: revision + 1,
            rows: stateStore.allItems(), secrets: localSecrets, signer: signer)
    }

    func uploadSnapshotNow(vaultID: String, owner: OwnerKeys) async throws -> SnapshotManifest? {
        guard let store = snapshotStore else { return nil }
        return try await SnapshotEngine.uploadMerged(
            vaultID: vaultID, rows: stateStore.allItems(), state: stateStore,
            secrets: localSecrets, signer: owner.signer, store: store,
            trustedOwnerKeys: trustedOwnerKeys())
    }

    public func cloudBackupStatus() async -> CloudBackupStatus {
        guard hasVault, vaultID != nil else { return .noVault }
        guard cloudBackupEnabled else { return .disabled }
        guard let snapshotStore else {
            return .unavailable("此构建未启用 iCloud 副本")
        }
        let probe = await snapshotStore.checkAvailability()
        guard probe.available else {
            return .unavailable(probe.reason ?? "副本不可用")
        }
        let localCount = stateStore.allItems()
            .filter { StorageClass.of($0) == .localOnly }.count
        let revision = (try? localSecrets.snapshotRevision()) ?? 0
        return .ready(itemCount: localCount, snapshotRevision: revision)
    }

    @discardableResult
    public func restoreCloudSnapshot() async throws -> SnapshotRestoreSummary {
        guard let vaultID else { throw LockError.noVault }
        guard let snapshotStore else {
            throw SnapshotStoreError.unavailable("此构建未启用 iCloud 副本")
        }
        guard let data = try await snapshotStore.download(vaultID: vaultID) else {
            throw SnapshotEngineError.notFound
        }
        let outcome = try SnapshotEngine.restore(
            data: data, vaultID: vaultID, rows: stateStore.allItems(),
            state: stateStore, secrets: localSecrets,
            trustedOwnerKeys: trustedOwnerKeys())
        if outcome.snapshotRevision > ((try? localSecrets.snapshotRevision()) ?? 0) {
            try? localSecrets.setSnapshotRevision(outcome.snapshotRevision)
        }
        snapshotDirty = true
        return SnapshotRestoreSummary(appliedCount: outcome.applied,
                                      snapshotRevision: outcome.snapshotRevision)
    }
}
