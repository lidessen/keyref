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
    /// §6.7 每条目覆盖：本机对每个 item 的最近一次决定（含时间戳）。
    /// 快照是整文件共享物——排除集随 manifest 分发、上传前与云端做 LWW
    /// 合并（SnapshotEngine.mergeExclusions），本机 UserDefaults 只持久化
    /// 自己的写入（item id 不是密钥材料）。
    var snapshotExclusions: [String: SnapshotExclusion] = LiveBackend.loadSnapshotExclusions()

    static func loadSnapshotExclusions() -> [String: SnapshotExclusion] {
        guard let raw = UserDefaults.standard.dictionary(
            forKey: "settings.snapshotExclusions") as? [String: String] else { return [:] }
        var out: [String: SnapshotExclusion] = [:]
        for (id, value) in raw {
            let parts = value.split(separator: "|")
            guard parts.count == 2, let at = Int64(parts[1]),
                  KeyrefEncoding.isValidID(id) else { continue }
            out[id] = SnapshotExclusion(itemID: id, excluded: parts[0] == "excluded",
                                        atMillis: at)
        }
        return out
    }

    func persistSnapshotExclusions() {
        var raw: [String: String] = [:]
        for (id, e) in snapshotExclusions {
            raw[id] = "\(e.excluded ? "excluded" : "included")|\(e.atMillis)"
        }
        UserDefaults.standard.set(raw, forKey: "settings.snapshotExclusions")
    }

    struct PendingJoin {
        var owner: OwnerKeys
        var deviceID: String
        var label: String
    }

    struct ApprovalRecord {
        var row: PendingApproval
        var plaintext: ApprovalRequestPlaintext
        /// For an SMS consumption: the message's §3.9 plaintext JSON bytes,
        /// which the decision delivers verbatim (D18), plus the fields the
        /// approval screen shows next to the command.
        var messagePayload: Data?
        var message: MessageInboxEntry?
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
    /// §8.4 到期预警（S14）：授予写入/续期后排 7 天与 1 天前的本地通知，
    /// 撤销后取消。生产注入 LiveNotificationScheduler；测试注入 no-op。
    let notifications: NotificationScheduler

    public init(keyStore: KeyStore, stateStore: UIStateStore,
                origin: URL = URL(string: "https://sync.keyref.app")!,
                urlSession: URLSession = .shared,
                localSecrets: LocalSecretStore = InMemoryLocalSecretStore(),
                snapshotStore: (any SnapshotStore)? = nil,
                notifications: NotificationScheduler = NoNotificationScheduler()) {
        self.keyStore = keyStore
        self.stateStore = stateStore
        self.urlSession = urlSession
        self.localSecrets = localSecrets
        self.snapshotStore = snapshotStore
        self.notifications = notifications
        // A previously chosen origin (Settings → 服务器, §2.15) wins over
        // the compiled-in default — otherwise every restart silently
        // points back at the default origin.
        if let stored = try? keyStore.retrieve(.serverOrigin),
           let text = String(data: stored, encoding: .utf8),
           let url = URL(string: text), url.scheme == "https" || url.scheme == "http" {
            self.origin = url
        } else {
            self.origin = origin
        }
    }

    /// Switches the sync server origin and persists it (§2.15). Callers
    /// handle the migration ritual; this only records the choice.
    public func setOrigin(_ url: URL) {
        guard url.scheme == "https" || url.scheme == "http" else { return }
        origin = url
        try? keyStore.store(.serverOrigin, Data(url.absoluteString.utf8))
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
        // 回灌（§6.5）：UIStateStore 的行在内存里，进程重启后 ownDeviceID /
        // pinnedOwnerKey / cursor 从 Keychain 恢复。没有 ownDeviceID，解锁
        // 会解不出 VMK（info 绑定设备 id），SyncEngine 也直接 notPaired。
        if ownDeviceID == nil, let stored = try? keyStore.retrieve(.ownDeviceID),
           !stored.isEmpty, let id = String(data: stored, encoding: .utf8) {
            ownDeviceID = id
            try? stateStore.setOwnDeviceID(id)
        }
        let pinnedMissing = ((try? stateStore.pinnedOwnerKey()) ?? nil)?.isEmpty ?? true
        if pinnedMissing, let stored = try? keyStore.retrieve(.pinnedOwnerKey),
           !stored.isEmpty {
            try? stateStore.setPinnedOwnerKey(stored)
        }
        let storedVaultID = (try? stateStore.vaultID()) ?? nil
        if storedVaultID == nil || storedVaultID?.isEmpty == true {
            if let vaultID { try? stateStore.setVaultID(vaultID) }
        }
        if (try? stateStore.cursor()) == 0, let stored = try? keyStore.retrieve(.syncCursor),
           !stored.isEmpty, let text = String(data: stored, encoding: .utf8),
           let saved = Int64(text), saved > 0,
           // The rows themselves live only in memory (UIStateStore, Phase 1):
           // restoring a non-zero cursor without a directory would skip the
           // bootstrap and leave the list empty until the next full re-pull
           // (§10.6: only cursor=0 bootstraps). When the in-memory state is
           // cold (no directory), re-bootstrap instead.
           (try? stateStore.currentDirectory()) != nil {
            try? stateStore.setCursor(saved)
        }
        cachedItemCount = stateStore.allItems().count
        localWrapInvalid = false
    }

    /// Persists the restart-critical state-store seeds (§6.5). Called at
    /// every point that writes them into the (memory-only) state store.
    func persistLocalStateSeeds(vaultID: String, ownDeviceID: String,
                                pinnedOwnerKey: Data, cursor: Int64) {
        try? keyStore.store(.ownDeviceID, Data(ownDeviceID.utf8))
        try? keyStore.store(.pinnedOwnerKey, pinnedOwnerKey)
        try? keyStore.store(.syncCursor, Data(String(cursor).utf8))
    }

    func persistSyncCursor() {
        guard let cursor = try? stateStore.cursor() else { return }
        try? keyStore.store(.syncCursor, Data(String(cursor).utf8))
    }

    public func unlockAfterBiometrics() async throws {
        guard hasVault, let vaultID else { throw LockError.noVault }
        localWrapInvalid = false
        guard let wrapData = try? keyStore.retrieve(.vmkWrap) else {
            throw LockError.wrapInvalid
        }
        guard let owner = loadOwnerKeys() else { throw LockError.wrapInvalid }
        // ownDeviceID 缺失先恢复（loadLocalState 已做一遍；这里兜底）——
        // 它丢失不是「包裹失效」（S4 的定义是隔区/AEAD 打不开），静默恢复
        // 才不会把健康保险库误送进本机重建流程。
        var deviceID = stateStore.ownID() ?? ""
        if deviceID.isEmpty, let stored = try? keyStore.retrieve(.ownDeviceID),
           !stored.isEmpty, let id = String(data: stored, encoding: .utf8) {
            deviceID = id
            try? stateStore.setOwnDeviceID(id)
            ownDeviceID = id
        }
        do {
            vmk = try VaultFlows.unwrapLocalVMK(owner: owner, wrap: wrapData,
                                                vaultID: vaultID, ownerDeviceID: deviceID)
            self.owner = owner
        } catch {
            // Re-enrolled biometry invalidated the enclave wrap (§9.5): S4.
            throw LockError.wrapInvalid
        }
        // Session renewal (§8.2): the token never survives a process
        // restart, so the first unlock after a cold start re-runs the
        // two-step challenge — otherwise every server call would 401
        // until something else happened to mint a token.
        await renewSessionIfNeeded()
    }

    func loadOwnerKeys() -> OwnerKeys? {
        if let keys = try? OwnerKeys.load(from: keyStore, enclaveBacked: true) {
            return keys
        }
        return try? OwnerKeys.load(from: keyStore, enclaveBacked: false)
    }

    /// Test hook: adopts an unlocked state without the biometrics
    /// roundtrip (LiveBackend's crypto paths are exercised against
    /// MockURLProtocol in the KeyrefCoreTests suite).
    func adoptForTesting(vaultID: String, owner: OwnerKeys, vmk: Data, ownDeviceID: String) {
        self.vaultID = vaultID
        self.owner = owner
        self.vmk = vmk
        self.ownDeviceID = ownDeviceID
        self.hasVault = true
    }

    public func lock() {
        vmk = nil
    }

    // MARK: - creation (§2.2, §9.3)

    public func checkPrerequisites() -> [Prerequisite] {
        #if DEBUG
        // UI-test hook (see KeyrefUITestHooks): simulators have no
        // passcode/biometry enrolled, which would block the creation UI
        // before any crypto runs. Never compiled into release builds.
        if KeyrefUITestHooks.assumePrerequisitesSatisfied {
            return [
                Prerequisite(id: "passcode", title: "设备密码已设置", satisfied: true),
                Prerequisite(id: "biometry", title: "Face ID 已录入", satisfied: true),
            ]
        }
        #endif
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
        persistLocalStateSeeds(vaultID: vaultID, ownDeviceID: deviceID,
                               pinnedOwnerKey: owner.signPublicKey, cursor: 0)
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
        guard var request = pendingCreation else {
            throw APIError.transport("no pending creation")
        }
        // Hosted servers gate vault creation behind a small proof of work
        // (protocol §10.1). Solve off the cooperative pool (tens of ms of
        // CPU) and retry once with the solution.
        do {
            _ = try await api.createVault(request)
        } catch APIError.powRequired(let challenge, _) {
            request.pow = try await solvePoW(challenge: challenge, vaultID: request.vaultID)
            _ = try await api.createVault(request)
        }
        pendingCreation = nil
        if let owner, let deviceID = ownDeviceID {
            if let session = try? await SessionClient(api: api).start(deviceID: deviceID,
                                                                      signer: owner.signer) {
                sessionBox.set(session.token)
            }
        }
        _ = try? await syncNow()
    }

    /// Runs PoW.solve off the cooperative pool (protocol §10.1).
    func solvePoW(challenge: Data, vaultID: String) async throws -> PoWSolution {
        let nonce = try await Task.detached(priority: .userInitiated) {
            try PoW.solve(challenge: challenge, vaultID: vaultID)
        }.value
        return PoWSolution(challenge: challenge, nonce: nonce)
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
                storageClass: StorageClass(sensitivity: meta.policy.sensitivity),
                snapshotExcluded: snapshotExclusions[row.itemID]?.excluded == true))
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
        do {
            try await syncPut(itemID: itemID, vaultID: vaultID)
        } catch {
            // 上传失败：回滚本次创建，避免「本地已存在、重试再建一条重复
            // 条目」。调用方（编辑器）显示失败，重试是干净的一次新建。
            try? stateStore.deleteItem(itemID)
            try? localSecrets.remove(itemID: itemID)
            throw error
        }
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
        // 上传失败时要恢复的写入前状态：服务器要求 PUT revision 恰为
        // current+1（items.go `want = current.Revision+1`）——本地先停在
        // N+1 的话，之后每次重试都算出 N+2，永远 revision_conflict，条目
        // 从此改不了/转不了/删不了。
        let preEditRow = row
        let preEditRecord = try? localSecrets.record(itemID: id)
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
            // (.synced, .synced)：编辑复用现有 metaKey/itemKey（§6.3 授权绑
            // key）。每次换新 key 会让已配对 CLI 的全部 view/use 授权在下一
            // 次 list/get/exec 时解不开新密文（exit 16）——换 key 只属于
            // rotateItem → reencryptItem（会重发全部授权）。
            let metaKey = try ItemCrypto.unwrapMetaKey(vmk: vmk, blob: row.vaultWrappedMetaKey,
                                                       vaultID: vaultID, itemID: id)
            let itemKey = try ItemCrypto.unwrapItemKey(vmk: vmk, blob: row.vaultWrappedItemKey,
                                                       vaultID: vaultID, itemID: id)
            let metaCT = try ItemCrypto.sealMeta(key: metaKey, meta: meta,
                                                 vaultID: vaultID, itemID: id)
            // 值未改动时保留原 secret 密文（明文相同，不必重新加密）。
            let secretCT = draft.value.isEmpty
                ? row.secretCiphertext
                : try ItemCrypto.sealSecret(key: itemKey, secret: secret,
                                            vaultID: vaultID, itemID: id)
            // key 与 VMK 都没变，两个包裹原样保留（AAD 绑 vault+item，不含 revision）。
            let t = ItemTranscript(vaultID: vaultID, itemID: id, revision: revision,
                                   metaCiphertext: metaCT, secretCiphertext: secretCT,
                                   vaultWrappedMetaKey: row.vaultWrappedMetaKey,
                                   vaultWrappedItemKey: row.vaultWrappedItemKey,
                                   writerDeviceID: deviceID)
            let signature = try owner.signer.sign(t.buildBytes())
            try? stateStore.upsertItem(ItemData.make(
                vaultID: vaultID, itemID: id, revision: revision, tombstone: false,
                metaCiphertext: metaCT, secretCiphertext: secretCT,
                vaultWrappedMetaKey: row.vaultWrappedMetaKey,
                vaultWrappedItemKey: row.vaultWrappedItemKey,
                writerDeviceID: deviceID, signature: signature, updatedAt: nowMillis()))
        }
        do {
            try await syncPut(itemID: id, vaultID: vaultID)
        } catch {
            // 回滚到写入前状态再抛出（照 createItem 的处理）：本地与服务器
            // 停在同一 revision，重试才有效。
            try? stateStore.upsertItem(preEditRow)
            if let preEditRecord {
                try? localSecrets.save(preEditRecord)
            } else {
                try? localSecrets.remove(itemID: id)
            }
            throw error
        }
    }

    public func deleteItem(id: String) async throws {
        let (_, owner, vaultID) = try guardUnlocked()
        let deviceID = ownDeviceID ?? ""
        let revision = (stateStore.itemByID(id)?.revision ?? 0) + 1
        let signature = try ItemCrypto.signTombstone(vaultID: vaultID, itemID: id,
                                                     revision: revision,
                                                     writerDeviceID: deviceID,
                                                     signer: owner.signer)
        // 服务器确认成功才删本地行（§2.16：绝不先斩后奏——本地先删会让
        // 重试从 revision 1 重新计数，永远追不上服务器的 revision_conflict）。
        try await api.deleteItem(itemID: id,
                                 DeleteItemRequest.make(revision: revision, signature: signature))
        try stateStore.deleteItem(id)
        try? localSecrets.remove(itemID: id)
        snapshotDirty = true
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
    /// 错误向上传播：吞掉它意味着这次写入永远不会再上传（服务器停在旧
    /// revision，CLI 与迁移都拉不到），UI 还会假报成功。
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
        _ = try await api.putItem(itemID: itemID, put)
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
    /// 仅本机行走 §6.6 分流：只轮换本地包裹（新 item key、重加密、重包裹、
    /// 本地 revision + 1），绝不上传 secret 密文、不改写服务器行。
    @discardableResult
    func reencryptItem(_ row: ItemData, meta: ItemMeta, value: String,
                       vaultID: String, owner: OwnerKeys, deviceID: String) async throws -> Int {
        let vmk = try guardUnlocked().vmk
        if StorageClass.of(row) == .localOnly {
            let record = try localSecrets.record(itemID: row.itemID)
                ?? LocalSecretRecord(itemID: row.itemID, secretCiphertext: Data(),
                                     vaultWrappedItemKey: Data(),
                                     revision: row.revision, updatedAt: nowMillis())
            let updated = try ItemCrypto.rotateLocalOnlySecret(
                vaultID: vaultID, itemID: row.itemID, vmk: vmk, meta: meta,
                secret: SecretPlaintext(v: 1, value: value), oldRecord: record)
            try localSecrets.save(updated)
            snapshotDirty = true
            return 0
        }
        let revision = row.revision + 1
        let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: row.itemID,
                                             revision: revision, writerDeviceID: deviceID,
                                             vmk: vmk, signer: owner.signer,
                                             meta: meta, secret: SecretPlaintext(v: 1, value: value))
        storeSealed(sealed, itemID: row.itemID, revision: revision,
                    vaultID: vaultID, deviceID: deviceID)
        do {
            try await api.putItem(itemID: row.itemID,
                                  putRequest(sealed, revision: revision, deviceID: deviceID))
        } catch {
            // PUT 失败：服务器还停在 N（want = N+1）——本地必须回到 N，
            // 否则之后每次重试都算出 N+2，永远 revision_conflict（轮换/
            // 撤销轮换卡死）。grants 重包在 PUT 之后，此时还未动。
            try? stateStore.upsertItem(row)
            throw error
        }
        var rewrapped = 0
        var newGrants: [GrantData] = []
        for grant in stateStore.allGrants()
        where grant.itemID == row.itemID
            && (grant.kind == GrantKind.use || grant.kind == GrantKind.view) && !grant.deleted {
            guard let device = directoryDevices()?.first(where: { $0.deviceID == grant.deviceID }),
                  device.status == DeviceStatus.active else { continue }
            // sealItem 同时换了 metaKey 和 itemKey：use 授予包新 itemKey，
            // view 授予包新 metaKey，否则 view 设备解不开新的 meta。
            let wrapKey = grant.kind == GrantKind.view ? sealed.metaKey : sealed.itemKey
            let (enc, ct) = try ItemCrypto.wrapGrantKey(
                kemName: device.hpkeKEM, recipientPublicKey: device.hpkePublicKey,
                kind: grant.kind, vaultID: vaultID, recipientDeviceID: device.deviceID,
                key: wrapKey)
            var g = GrantData.make(deviceID: device.deviceID, itemID: row.itemID, kind: grant.kind,
                              hpkeEnc: enc, wrappedKey: ct, expiresAt: grant.expiresAt,
                              revision: grant.revision + 1, signature: Data(), deleted: false)
            g.signature = try owner.signer.sign(g.transcript(vaultID: vaultID).buildBytes())
            newGrants.append(g)
            if grant.kind == GrantKind.use { rewrapped += 1 }
        }
        if !newGrants.isEmpty {
            try await api.putGrants(PutGrantsRequest.make(grants: newGrants))
            for g in newGrants { try? stateStore.upsertGrant(g) }
        }
        return rewrapped
    }

    /// §6.1 掩码：前缀表 + 长度下限在 KeyrefCore.ItemMasking（规则与设计
    /// 文档一致；password/note 永远 ***）。
    func maskOf(_ value: String, type: String) -> String {
        ItemMasking.mask(value, type: type)
    }

    func nowMillis() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    // MARK: - sync & account (§2.4, §2.17)

    @discardableResult
    public func syncNow() async throws -> SyncOutcomeInfo {
        // Session renewal (§8.2): the token lives only in memory (12 h
        // validity) — after a cold start or expiry every bearer call
        // would 401. Re-run the two-step challenge when there is no
        // live token before syncing; failures fall through to the sync
        // error path so the UI keeps its existing failure surfaces.
        await renewSessionIfNeeded()
        let engine = SyncEngine(api: api)
        do {
            let outcome = try await engine.run(store: stateStore)
            frozen = false
            cachedItemCount = stateStore.allItems().count
            persistSyncCursor()   // 重启后不必从 0 重新引导（§10.6）
            return SyncOutcomeInfo(applied: outcome.applied, deleted: outcome.deleted,
                                   revokedSelf: outcome.revokedSelf)
        } catch let e as APIError {
            if case .vaultFrozen = e { frozen = true }
            throw e
        }
    }

    /// Re-establishes the bearer session when none is held (§8.2: renewal
    /// is the same two-step path). No-op when unlocked state is absent or
    /// a token is already set.
    func renewSessionIfNeeded() async {
        guard sessionBox.get() == nil, let owner, let deviceID = ownDeviceID else { return }
        if let session = try? await SessionClient(api: api).start(deviceID: deviceID,
                                                                  signer: owner.signer) {
            sessionBox.set(session.token)
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
                             fingerprint: d.fingerprint, grants: dg,
                             receiverRole: d.receiverRole)
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
        // The device's public keys are trusted exclusively from the
        // signed directory (design §9.1): after the pair lands, re-sign
        // the directory with the new CLI appended (revision + 1) and PUT
        // it — the server upserts the device row from the directory.
        // Skipping this leaves the CLI invisible to loadDevices, grant
        // editing, revocation and approval validation.
        let dirRevision = stateStore.currentDirectory()?.directoryRevision ?? 0
        let newDevice = KeyrefDirectoryDevice(
            deviceID: device.deviceID, kind: DeviceKind.cli, status: DeviceStatus.active,
            hpkeKEM: device.hpkeKEM, hpkePublicKey: device.hpkePublicKey,
            signAlg: device.signAlg, signPublicKey: device.signPublicKey,
            renewalSignPublicKey: device.renewalSignPublicKey,
            grantsDigest: try grantsDigest(grants.map { $0.transcript(vaultID: vaultID) }))
        var devices = directoryDevices() ?? []
        devices.append(newDevice)
        try await publishDirectory(devices, revision: dirRevision + 1,
                                   owner: owner, vaultID: vaultID)
        scheduleGrantNotices(grants, vaultID: vaultID, vmk: vmk)
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
        try await api.putGrants(PutGrantsRequest.make(grants: rows))
        for g in rows { try? stateStore.upsertGrant(g) }
        // Keep the signed directory's per-device grants_digest fresh
        // (§3.3): the CLI compares GET /v1/grants/self against it.
        try? await refreshDeviceGrantsDigest(deviceID: deviceID, owner: owner, vaultID: vaultID)
        scheduleGrantNotices(rows, vaultID: vaultID, vmk: vmk)
    }

    /// Re-signs the directory after a device's grant set changed, so the
    /// per-device grants_digest matches what GET /v1/grants/self returns.
    /// Best effort: the digest is re-derived from local state; failures
    /// leave the old digest and are reconciled on the next change.
    func refreshDeviceGrantsDigest(deviceID: String, owner: OwnerKeys, vaultID: String) async throws {
        guard var devices = directoryDevices(),
              let idx = devices.firstIndex(where: { $0.deviceID == deviceID }) else { return }
        let live = stateStore.allGrants().filter { $0.deviceID == deviceID && !$0.deleted }
        devices[idx].grantsDigest = try grantsDigest(live.map { $0.transcript(vaultID: vaultID) })
        let rev = stateStore.currentDirectory()?.directoryRevision ?? 0
        try await publishDirectory(devices, revision: rev + 1, owner: owner, vaultID: vaultID)
    }

    /// §8.4 到期预警（S14）：授予落库后为每条非永久授权排 7 天/1 天前的
    /// 本地通知。通知 identifier 用 deviceID（与 cancelExpiryNotices 对齐）。
    func scheduleGrantNotices(_ grants: [GrantData], vaultID: String, vmk: Data) {
        for g in grants where g.expiresAt > 0 {
            let ref = stateStore.itemByID(g.itemID).flatMap {
                try? decryptMeta($0, vmk: vmk, vaultID: vaultID)
            }?.ref ?? g.itemID
            let label = stateStore.info(for: g.deviceID)?.label ?? g.deviceID
            notifications.scheduleExpiryNotices(
                deviceLabel: label, deviceID: g.deviceID, itemRef: ref,
                expiresAt: Date(timeIntervalSince1970: Double(g.expiresAt) / 1000))
        }
    }

    func cancelGrantNotices(_ grants: [GrantData], vaultID: String, vmk: Data) {
        for g in grants {
            let ref = stateStore.itemByID(g.itemID).flatMap {
                try? decryptMeta($0, vmk: vmk, vaultID: vaultID)
            }?.ref ?? g.itemID
            notifications.cancelExpiryNotices(itemRef: ref, deviceID: g.deviceID)
        }
    }

    // MARK: grant renewal (§8.4 授权生命周期)

    /// §8.4 续期（前台解锁路径）：把 7 天内到期（含已过期）的 use/view 授予
    /// 用 VMK 重包顺延——新包裹、expiresAt 顺延 30 天、revision + 1，
    /// owner 签名 PUT /v1/grants（服务器校验 owner 签名与 revision 严格递增，
    /// protocol §6.12，已接受这种更新）。已撤销/不在目录的设备跳过。
    /// 返回顺延的授予条数；网络失败静默（下次解锁再试）。
    @discardableResult
    public func renewExpiringGrants() async -> Int {
        guard let (vmk, owner, vaultID) = try? guardUnlocked() else { return 0 }
        let now = nowMillis()
        let horizon = now + 7 * 86_400_000
        let devices = directoryDevices() ?? []
        var rows: [GrantData] = []
        for grant in stateStore.allGrants()
        where !grant.deleted && grant.expiresAt != 0 && grant.expiresAt <= horizon {
            guard grant.deviceID != ownDeviceID else { continue }  // 本机不持有授予
            guard let device = devices.first(where: { $0.deviceID == grant.deviceID }),
                  device.status == DeviceStatus.active else { continue }
            guard let row = stateStore.itemByID(grant.itemID) else { continue }
            // §6.6：仅本机条目上的 use 授予本就不存在（拦截只防脏数据）；
            // view 授予是仅本机条目唯一合法授予——metaKey 在行上，照常续期。
            if grant.kind == GrantKind.use, StorageClass.of(row) == .localOnly { continue }
            let key: Data
            do {
                if grant.kind == GrantKind.use {
                    key = try ItemCrypto.unwrapItemKey(vmk: vmk, blob: row.vaultWrappedItemKey,
                                                       vaultID: vaultID, itemID: row.itemID)
                } else if grant.kind == GrantKind.view {
                    key = try ItemCrypto.unwrapMetaKey(vmk: vmk, blob: row.vaultWrappedMetaKey,
                                                       vaultID: vaultID, itemID: row.itemID)
                } else {
                    continue
                }
            } catch {
                continue
            }
            let (enc, ct): (Data, Data)
            do {
                (enc, ct) = try ItemCrypto.wrapGrantKey(
                    kemName: device.hpkeKEM, recipientPublicKey: device.hpkePublicKey,
                    kind: grant.kind, vaultID: vaultID,
                    recipientDeviceID: grant.deviceID, key: key)
            } catch {
                continue
            }
            var g = GrantData.make(deviceID: grant.deviceID, itemID: grant.itemID,
                              kind: grant.kind, hpkeEnc: enc, wrappedKey: ct,
                              expiresAt: now + 30 * 86_400_000,
                              revision: grant.revision + 1, signature: Data(), deleted: false)
            guard let signature = try? owner.signer.sign(g.transcript(vaultID: vaultID).buildBytes()) else {
                continue
            }
            g.signature = signature
            rows.append(g)
        }
        guard !rows.isEmpty else { return 0 }
        do {
            _ = try await api.putGrants(PutGrantsRequest.make(grants: rows))
        } catch {
            return 0  // 下次解锁重试；UI 不因此阻塞
        }
        for g in rows { try? stateStore.upsertGrant(g) }
        scheduleGrantNotices(rows, vaultID: vaultID, vmk: vmk)
        return rows.count
    }

    public func revokeGrant(deviceID: String, itemID: String, kind: String) async throws {
        let (vmk, owner, vaultID) = try guardUnlocked()
        guard let grant = stateStore.allGrants().first(where: {
            $0.deviceID == deviceID && $0.itemID == itemID && $0.kind == kind && !$0.deleted
        }) else { throw APIError.notFound }
        let revision = grant.revision + 1
        let t = GrantTranscript.deletion(vaultID: vaultID, deviceID: deviceID,
                                         itemID: itemID, kind: kind, revision: revision)
        let signature = try owner.signer.sign(t.buildBytes())
        // 服务器确认成功才动本地行（§2.16 同一原则：失败可重试）。
        try await api.deleteGrant(DeleteGrantRequest.make(deviceID: deviceID, itemID: itemID,
                                                          kind: kind, revision: revision,
                                                          signature: signature))
        try stateStore.deleteGrant(deviceID: deviceID, itemID: itemID, kind: kind)
        cancelGrantNotices([grant], vaultID: vaultID, vmk: vmk)
    }

    public func renameDevice(deviceID: String, label: String) async throws {
        var info = stateStore.info(for: deviceID) ?? UIStateStore.DeviceInfo(label: label, createdAt: nowMillis())
        info.label = label
        stateStore.setDeviceInfo(info, for: deviceID)
    }

    public func revokeDevice(deviceID: String, rotate: Bool,
                             progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> RevokeSummary {
        let (_, owner, vaultID) = try guardUnlocked()
        // 0. Snapshot the item ids the device could use BEFORE any grant
        // is deleted (§8.4 step 3): rotation must cover exactly the items
        // whose keys the revoked device held — deleting the grants first
        // would leave the set empty and the rotation a no-op.
        let revocableItemIDs = Set(stateStore.allGrants()
            .filter { $0.deviceID == deviceID && $0.kind == GrantKind.use && !$0.deleted }
            .map { $0.itemID })
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
                rotated = try await rotateItems(itemIDs: revocableItemIDs, progress: progress)
                pendingRotation.removeValue(forKey: deviceID)
            } catch {
                // 撤销已生效、轮换可重入（§2.10 失败态）：记录剩余数。
                pendingRotation[deviceID] = pendingRotation[deviceID] ?? revocableItemIDs.count
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
            grantsDigest: old.grantsDigest,
            // A revoked device can no longer receive pushes (design §14.4).
            receiverRole: ReceiverRole.none)
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
                            grantsDigest: $0.grantsDigest,
                            receiverRole: $0.receiverRole)
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
        let vmk = try guardUnlocked().vmk
        var deleted: [GrantData] = []
        for grant in stateStore.allGrants()
        where grant.deviceID == deviceID && !grant.deleted {
            let revision = grant.revision + 1
            let t = GrantTranscript.deletion(vaultID: vaultID, deviceID: deviceID,
                                             itemID: grant.itemID, kind: grant.kind,
                                             revision: revision)
            let signature = try owner.signer.sign(t.buildBytes())
            try await api.deleteGrant(DeleteGrantRequest.make(deviceID: deviceID,
                                                              itemID: grant.itemID,
                                                              kind: grant.kind,
                                                              revision: revision,
                                                              signature: signature))
            try stateStore.deleteGrant(deviceID: grant.deviceID, itemID: grant.itemID, kind: grant.kind)
            deleted.append(grant)
        }
        cancelGrantNotices(deleted, vaultID: vaultID, vmk: vmk)
    }

    /// Rotation of every item the device held a `use` grant on (§8.4).
    /// Resumable: directory + grant deletion landed first (§2.10 失败态).
    /// The item set is snapshotted by the caller BEFORE the grants are
    /// deleted — deriving it here would always be empty (§8.4 step 3).
    func rotateGrantedItems(deviceID: String,
                            progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> Int {
        let itemIDs = Set(stateStore.allGrants()
            .filter { $0.deviceID == deviceID && $0.kind == GrantKind.use && !$0.deleted }
            .map { $0.itemID })
        return try await rotateItems(itemIDs: itemIDs, progress: progress)
    }

    /// Re-encrypts each item in `itemIDs` under a fresh item key and
    /// re-wraps grants for the remaining active devices (§8.4 step 3).
    func rotateItems(itemIDs: Set<String>,
                     progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> Int {
        let (vmk, owner, vaultID) = try guardUnlocked()
        let ownDevice = ownDeviceID ?? ""
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
            setOrigin(newOrigin)
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
        var create = CreateVaultRequest.make(
            vaultID: vaultID, device: device,
            recoveryWrap: materials.recoveryWrap,
            recoveryKDFJSON: materials.recoveryKDFJSON,
            recoverySignPub: materials.recoverySignPub,
            directoryRevision: 1, directorySigned: dirBytes,
            signature: try owner.signer.sign(dirBytes), pow: nil)
        do {
            _ = try await newAPI.createVault(create)
        } catch APIError.powRequired(let challenge, _) {
            // Hosted targets gate creation behind PoW (protocol §10.1).
            let nonce = try await Task.detached(priority: .userInitiated) {
                try PoW.solve(challenge: challenge, vaultID: vaultID)
            }.value
            create.pow = PoWSolution(challenge: challenge, nonce: nonce)
            _ = try await newAPI.createVault(create)
        }

        // Full upload. Per-item revision restarts at 1 on the fresh vault
        // (server contract: a new item's first PUT is revision 1), and the
        // writer must be this device (the only active iOS row in the new
        // directory). 仅本机行按 §6.6 分流：只投 meta 材料（重签 revision-1
        // 誊本），secret 密文与 item key 包裹留在本机，不落到新服务器。
        await progress(.fullUpload)
        let vmk = try guardUnlocked().vmk
        for row in stateStore.allItems() where !row.tombstone {
            if StorageClass.of(row) == .localOnly {
                let t = ItemTranscript(vaultID: vaultID, itemID: row.itemID, revision: 1,
                                       metaCiphertext: row.metaCiphertext,
                                       secretCiphertext: Data(),
                                       vaultWrappedMetaKey: row.vaultWrappedMetaKey,
                                       vaultWrappedItemKey: Data(),
                                       writerDeviceID: deviceID)
                let signature = try owner.signer.sign(t.buildBytes())
                let put = PutItemRequest.make(revision: 1, tombstone: false,
                                         metaCiphertext: row.metaCiphertext,
                                         secretCiphertext: Data(),
                                         vaultWrappedMetaKey: row.vaultWrappedMetaKey,
                                         vaultWrappedItemKey: Data(),
                                         writerDeviceID: deviceID, signature: signature)
                _ = try await newAPI.putItem(itemID: row.itemID, put)
                continue
            }
            guard let meta = try? decryptMeta(row, vmk: vmk, vaultID: vaultID),
                  let secret = try? decryptSecret(row, vmk: vmk, vaultID: vaultID) else { continue }
            let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: row.itemID,
                                                 revision: 1, writerDeviceID: deviceID,
                                                 vmk: vmk, signer: owner.signer,
                                                 meta: meta, secret: secret)
            _ = try await newAPI.putItem(itemID: row.itemID,
                                         putRequest(sealed, revision: 1, deviceID: deviceID))
        }

        await progress(.verify)
        try stateStore.setCursor(0)
        persistSyncCursor()
        setOrigin(newOrigin)
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

    /// 续转被中断的轮换：rotateRecovery 在任何服务器写入之前把新 VMK 的
    /// HPKE 包裹存进 .pendingVMKWrap——进程中途被杀后，服务器上可能已有
    /// 用该 VMK 包裹的行（重启后 sync 会把它们拉回本地），轮换必须复用这
    /// 把 VMK 才能继续/收尾。轮换完成后移除该槽。
    func resumedRotationVMK(owner: OwnerKeys, vaultID: String, deviceID: String) -> Data? {
        guard let blob = try? keyStore.retrieve(.pendingVMKWrap), !blob.isEmpty else { return nil }
        return try? VaultFlows.unwrapLocalVMK(owner: owner, wrap: blob,
                                              vaultID: vaultID, ownerDeviceID: deviceID)
    }

    func stashPendingRotationVMK(_ vmk: Data, owner: OwnerKeys, vaultID: String,
                                 deviceID: String) throws {
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID,
                                recipientDeviceID: deviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                               recipientPublicKey: owner.kemPublicKey,
                                               info: info, plaintext: vmk)
        try keyStore.store(.pendingVMKWrap, enc + ct)
    }

    /// §8.4: 只换包裹层 (layerOnly) vs B5 全套 (rotate every item key and
    /// re-encrypt). Both publish a new recovery code, shown exactly once (S9).
    ///
    /// 提交顺序是「先服务器、后本地」：本地行在任何 PUT 成功前绝不改写
    /// （本地行始终可用旧 VMK 解开）。逐条 PUT 带 revision-conflict 重签
    /// （服务器要求恰好 current+1；上次中断/补偿轮可能已把存储行推到更高
    /// revision）。中途失败对「已 PUT 成功」的条目做服务器侧回滚——用旧
    /// 行材料在更高 revision 重签传回，使服务器回到与旧 VMK 一致的包裹，
    /// 本地与服务器保持一致、整轮可重试；个别补偿失败也由下次重试的
    /// conflict-bump 自愈。仅本机行按 §6.6 分流：服务器行只换 meta 包裹
    /// （secret/vwItem 字段保持空），item key 包裹在本地加密存储里换新 VMK。
    func rotateRecovery(layerOnly: Bool) async throws -> String {
        guard let owner, let vaultID, let deviceID = ownDeviceID else { throw LockError.noVault }
        let currentVMK = try guardUnlocked().vmk
        // 中断续转：复用暂存的 VMK（若有），否则生成新的并在任何 PUT 之前
        // 暂存——这是「失败可重试」的关键（重启后本地行可能已被 sync 换成
        // 服务器的新包裹，只有这把 VMK 解得开）。
        let newVMK: Data
        if let resumed = resumedRotationVMK(owner: owner, vaultID: vaultID, deviceID: deviceID) {
            newVMK = resumed
        } else {
            newVMK = randomKey()
            try stashPendingRotationVMK(newVMK, owner: owner, vaultID: vaultID, deviceID: deviceID)
        }

        struct RowPlan {
            var itemID: String
            var oldRow: ItemData
            /// 新包裹材料（签名字段不参与誊本重签，仅四个密文字段被使用）。
            var newRowMaterial: ItemData
            var newRecord: LocalSecretRecord?
            var put: PutItemRequest?
        }
        func materialRow(itemID: String, metaCT: Data, secretCT: Data,
                         vwMeta: Data, vwItem: Data) -> ItemData {
            ItemData.make(vaultID: vaultID, itemID: itemID, revision: 0, tombstone: false,
                          metaCiphertext: metaCT, secretCiphertext: secretCT,
                          vaultWrappedMetaKey: vwMeta, vaultWrappedItemKey: vwItem,
                          writerDeviceID: deviceID, signature: Data(), updatedAt: 0)
        }
        var plans: [RowPlan] = []
        for row in stateStore.allItems() where !row.tombstone {
            func unwrapMeta(_ vmk: Data) throws -> Data {
                try ItemCrypto.unwrapMetaKey(vmk: vmk, blob: row.vaultWrappedMetaKey,
                                             vaultID: vaultID, itemID: row.itemID)
            }
            // 行的 metaKey 用旧 VMK 解；解不开说明该行在上次中断的尝试里
            // 已被推上服务器（重启后被 sync 拉回）——用暂存的新 VMK 解。
            let metaKey: Data
            do {
                metaKey = try unwrapMeta(currentVMK)
            } catch {
                metaKey = try unwrapMeta(newVMK)
            }
            let vwMeta = try ItemCrypto.wrapMetaKeyWithVMK(vmk: newVMK, metaKey: metaKey,
                                                           vaultID: vaultID, itemID: row.itemID)
            let metaCT = row.metaCiphertext
            var secretCT = row.secretCiphertext
            var vwItem = row.vaultWrappedItemKey
            var newRecord: LocalSecretRecord?
            if StorageClass.of(row) == .localOnly {
                // 仅本机（§6.6）：item key 包裹在本地记录里，不在行上。
                // 记录从不被服务器覆写，始终可用旧 VMK 解开。
                guard let record = try localSecrets.record(itemID: row.itemID),
                      !record.vaultWrappedItemKey.isEmpty else {
                    throw KeyrefCryptoError.invalidBlob
                }
                let itemKey = try ItemCrypto.unwrapItemKey(vmk: currentVMK, blob: record.vaultWrappedItemKey,
                                                           vaultID: vaultID, itemID: row.itemID)
                if layerOnly {
                    newRecord = LocalSecretRecord(
                        itemID: row.itemID, secretCiphertext: record.secretCiphertext,
                        vaultWrappedItemKey: try ItemCrypto.wrapItemKeyWithVMK(
                            vmk: newVMK, itemKey: itemKey, vaultID: vaultID, itemID: row.itemID),
                        revision: record.revision, updatedAt: nowMillis())
                } else {
                    // B5：新 item key + 重加密 + 换新 VMK 包裹（本地 revision + 1），
                    // 与 ItemCrypto.rotateLocalOnlySecret 同一语义（meta 不动）。
                    let plain = try ItemCrypto.openSecret(key: itemKey, blob: record.secretCiphertext,
                                                          vaultID: vaultID, itemID: row.itemID)
                    let newItemKey = randomKey()
                    let secretCTNew = try ItemCrypto.sealSecret(key: newItemKey, secret: plain,
                                                                vaultID: vaultID, itemID: row.itemID)
                    newRecord = LocalSecretRecord(
                        itemID: row.itemID, secretCiphertext: secretCTNew,
                        vaultWrappedItemKey: try ItemCrypto.wrapItemKeyWithVMK(
                            vmk: newVMK, itemKey: newItemKey, vaultID: vaultID, itemID: row.itemID),
                        revision: record.revision + 1, updatedAt: nowMillis())
                }
                // 行上保持 §6.6 形状：secret 与 vwItem 为空（签名的就是空字段）。
                secretCT = Data()
                vwItem = Data()
            } else {
                let itemKey: Data
                do {
                    itemKey = try ItemCrypto.unwrapItemKey(vmk: currentVMK, blob: row.vaultWrappedItemKey,
                                                           vaultID: vaultID, itemID: row.itemID)
                } catch {
                    itemKey = try ItemCrypto.unwrapItemKey(vmk: newVMK, blob: row.vaultWrappedItemKey,
                                                           vaultID: vaultID, itemID: row.itemID)
                }
                if !layerOnly {
                    // B5 (§8.4): the item key itself must rotate — reusing
                    // it would leave every holder of the old key (e.g. a
                    // leaked recovery code's derived item keys) able to
                    // decrypt the "rotated" ciphertext.
                    let plain = try ItemCrypto.openSecret(key: itemKey, blob: row.secretCiphertext,
                                                          vaultID: vaultID, itemID: row.itemID)
                    let newItemKey = randomKey()
                    secretCT = try ItemCrypto.sealSecret(key: newItemKey, secret: plain,
                                                         vaultID: vaultID, itemID: row.itemID)
                    vwItem = try ItemCrypto.wrapItemKeyWithVMK(vmk: newVMK, itemKey: newItemKey,
                                                               vaultID: vaultID, itemID: row.itemID)
                } else {
                    vwItem = try ItemCrypto.wrapItemKeyWithVMK(vmk: newVMK, itemKey: itemKey,
                                                               vaultID: vaultID, itemID: row.itemID)
                }
            }
            plans.append(RowPlan(
                itemID: row.itemID, oldRow: row,
                newRowMaterial: materialRow(itemID: row.itemID, metaCT: metaCT,
                                            secretCT: secretCT, vwMeta: vwMeta, vwItem: vwItem),
                newRecord: newRecord, put: nil))
        }

        // 组装阶段（纯内存）到这里为止——任何失败都还没写过任何状态。

        func makePut(_ p: RowPlan, revision: UInt64, material: ItemData) throws -> PutItemRequest {
            let t = ItemTranscript(vaultID: vaultID, itemID: p.itemID, revision: revision,
                                   metaCiphertext: material.metaCiphertext,
                                   secretCiphertext: material.secretCiphertext,
                                   vaultWrappedMetaKey: material.vaultWrappedMetaKey,
                                   vaultWrappedItemKey: material.vaultWrappedItemKey,
                                   writerDeviceID: deviceID)
            let signature = try owner.signer.sign(t.buildBytes())
            return PutItemRequest.make(revision: revision, tombstone: false,
                                       metaCiphertext: material.metaCiphertext,
                                       secretCiphertext: material.secretCiphertext,
                                       vaultWrappedMetaKey: material.vaultWrappedMetaKey,
                                       vaultWrappedItemKey: material.vaultWrappedItemKey,
                                       writerDeviceID: deviceID, signature: signature)
        }

        /// PUT with re-signing on revision_conflict: the server wants exactly
        /// current+1; a previous interrupted/compensated round may already
        /// have advanced the stored revision past `base`. Re-signs the same
        /// material at the next revision, bounded (3 extra attempts).
        func putItemResilient(_ p: RowPlan, baseRevision: UInt64,
                              material: ItemData) async throws -> PutItemRequest {
            var revision = baseRevision
            while true {
                let put = try makePut(p, revision: revision, material: material)
                do {
                    _ = try await api.putItem(itemID: p.itemID, put)
                    return put
                } catch let e as APIError {
                    guard case .revisionConflict = e,
                          revision < baseRevision + 3 else { throw e }
                    revision += 1
                }
            }
        }

        // 提交阶段：先服务器，全部成功才写本地。
        do {
            for i in plans.indices {
                plans[i].put = try await putItemResilient(plans[i],
                                                          baseRevision: plans[i].oldRow.revision + 1,
                                                          material: plans[i].newRowMaterial)
            }
        } catch {
            // 服务器侧回滚：把已 PUT 成功的条目用旧行材料重签传回（服务器
            // 存的是 put.revision，want = +1），恢复与旧 VMK 一致的包裹；
            // 本地行从未写入，仍可用旧 VMK 解开。补偿逐条尽力（失败静默：
            // 下次重试靠 conflict-bump 收敛）。
            for p in plans where p.put != nil {
                _ = try? await putItemResilient(p, baseRevision: (p.put?.revision ?? 0) + 1,
                                                material: p.oldRow)
            }
            throw error
        }

        // 全部行已用 newVMK 包裹并同步——现在才写本地行/记录并提交新包裹层
        // （同步代码，无 await，中途不存在不一致窗口）。
        for p in plans {
            guard let put = p.put else {
                throw APIError.transport("rotation row \(p.itemID) missing its commit PUT")
            }
            try stateStore.upsertItem(ItemData.make(
                vaultID: vaultID, itemID: p.itemID, revision: put.revision, tombstone: false,
                metaCiphertext: put.metaCiphertext, secretCiphertext: put.secretCiphertext,
                vaultWrappedMetaKey: put.vaultWrappedMetaKey,
                vaultWrappedItemKey: put.vaultWrappedItemKey,
                writerDeviceID: put.writerDeviceID, signature: put.signature,
                updatedAt: nowMillis()))
            if let nr = p.newRecord { try localSecrets.save(nr) }
        }
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID, recipientDeviceID: deviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                               recipientPublicKey: owner.kemPublicKey,
                                               info: info, plaintext: newVMK)
        try keyStore.store(.vmkWrap, enc + ct)
        vmk = newVMK
        try? keyStore.remove(.pendingVMKWrap)

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
                    grantsDigest: d.grantsDigest,
                    receiverRole: d.receiverRole))
            } else {
                devices.append(DirectoryDevice(
                    deviceID: d.deviceID, kind: d.kind, status: d.status,
                    hpkeKEM: d.hpkeKEM, hpkePublicKey: d.hpkePublicKey,
                    signAlg: d.signAlg, signPublicKey: d.signPublicKey,
                    renewalSignPublicKey: d.renewalSignPublicKey,
                    grantsDigest: d.grantsDigest,
                    receiverRole: d.receiverRole))
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
        persistLocalStateSeeds(vaultID: prep.vaultID, ownDeviceID: pending.newDeviceID,
                               pinnedOwnerKey: owner.signPublicKey, cursor: 0)
        // Keychain 的「保险库存在」事实与 VMK 包裹必须现在落盘（§9.3，
        // 创建/加入路径同样写这两项）：loadLocalState 以 .vaultID 判定
        // hasVault——漏写的话，接管成功后杀掉 App 重启就回到欢迎页（保险库
        // 「消失」），本机重建场景回到 S4 循环。owner 私钥已由 prepareRecovery
        // 落盘，这里用新 owner 公钥 HPKE 包裹 prep.vmk（照加入路径模式）。
        try keyStore.store(.vaultID, Data(prep.vaultID.utf8))
        let vmkWrapInfo = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: prep.vaultID,
                                       recipientDeviceID: pending.newDeviceID)
        let (vmkWrapEnc, vmkWrapCT) = try KeyrefHPKE.wrapKey(
            kemName: owner.kemKEMName, recipientPublicKey: owner.kemPublicKey,
            info: vmkWrapInfo, plaintext: prep.vmk)
        try keyStore.store(.vmkWrap, vmkWrapEnc + vmkWrapCT)
        try? keyStore.remove(.pendingVMKWrap)   // 旧 owner 的中断轮换残留随之失效
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
        // §6.7 恢复路径：接管 / 本机重建完成后拉取 iCloud 快照（先验签再
        // 入库，按 revision 合并）——仅本机条目靠它找回。没有快照或验签
        // 不过都不阻塞恢复流程（降级为「快照不可用」）。
        _ = try? await restoreCloudSnapshot()

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
        // Message subjects need the SMS itself on the same screen
        // (design §14.5): pull the inbox once, lazily.
        var messageRowsByID: [String: MessageRow]?
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
                try ApprovalFlows.verifyRequestSignature(row, vaultID: vaultID, device: device)
                try ApprovalFlows.validatePlaintext(plaintext, pending: row)

                if row.isMessageSubject {
                    // The decision seals the message's plaintext JSON (D18)
                    // and the screen shows it beside the command; both come
                    // from opening the envelope for this device.
                    if messageRowsByID == nil {
                        messageRowsByID = Dictionary(
                            uniqueKeysWithValues: ((try? await api.listMessages())?.messages ?? [])
                                .map { ($0.messageID, $0) })
                    }
                    guard let messageRow = messageRowsByID?[row.messageID] else {
                        out.append(.invalid(row, cliDeviceLabel: label))
                        continue
                    }
                    let sourceDevice = devices.first { $0.deviceID == messageRow.sourceDeviceID }
                    let sourceLabel = infos[messageRow.sourceDeviceID]?.label
                        ?? sourceDevice?.fingerprint
                        ?? messageRow.sourceDeviceID
                    // The message row is verified under the source device's
                    // signed-directory entry BEFORE anything is decrypted
                    // (protocol v2 C): a row the server fabricated must
                    // never reach the screen or an approval. A missing
                    // directory entry fails closed through the same throw.
                    if let sourceDevice {
                        try MessageEnvelope.verifyUploadSignature(
                            row: messageRow, vaultID: vaultID, device: sourceDevice)
                    } else {
                        throw KeyrefWireError.badSignature
                    }
                    let raw = try MessageEnvelope.openRaw(
                        envelope: messageRow.envelope, vaultID: vaultID,
                        sourceDeviceID: messageRow.sourceDeviceID,
                        ownerDeviceID: deviceID, owner: owner)
                    let sms = try MessagePlaintext.decode(raw)
                    let entry = MessageInboxEntry(
                        messageID: messageRow.messageID,
                        sourceDeviceID: messageRow.sourceDeviceID,
                        sourceLabel: sourceLabel,
                        sender: sms.sender, body: sms.body, sim: sms.sim ?? "",
                        receivedAt: sms.receivedAt, createdAt: messageRow.createdAt,
                        expiresAt: messageRow.expiresAt, status: messageRow.status)
                    approvalRecords[row.approvalID] = ApprovalRecord(
                        row: row, plaintext: plaintext, messagePayload: raw, message: entry)
                    out.append(ApprovalInboxEntry(
                        approvalID: row.approvalID,
                        cliDeviceID: row.cliDeviceID,
                        cliDeviceLabel: label,
                        itemID: "",
                        itemName: "验证码",
                        itemRef: "",
                        argv: plaintext.argv,
                        refs: plaintext.refs,
                        injection: plaintext.injection,
                        hosts: plaintext.hosts,
                        createdAt: row.createdAt,
                        expiresAt: row.expiresAt,
                        valid: true,
                        messageID: messageRow.messageID,
                        messageSender: sms.sender,
                        messageBody: sms.body,
                        messageSourceLabel: sourceLabel,
                        messageReceivedAt: sms.receivedAt))
                    continue
                }

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

    // MARK: - messages (design v0.8 §14.4)

    /// Pulls the inbox and opens every envelope for this device. Requires
    /// an unlocked vault: the message key is HPKE-sealed to this device's
    /// key, so nothing here is readable before the enclave wrap is open.
    public func loadMessages() async -> [MessageInboxEntry] {
        guard let vaultID, let owner, let deviceID = ownDeviceID, vmk != nil else {
            return []
        }
        let rows: [MessageRow]
        do {
            rows = try await api.listMessages().messages
        } catch {
            return []
        }
        let infos = stateStore.allDeviceInfo()
        let devices = directoryDevices() ?? []
        var out: [MessageInboxEntry] = []
        for row in rows where row.isActive {
            let device = devices.first { $0.deviceID == row.sourceDeviceID }
            let label = infos[row.sourceDeviceID]?.label
                ?? device?.fingerprint
                ?? row.sourceDeviceID
            do {
                // Verify the upload signature under the source device's
                // signed-directory entry before anything is decrypted
                // (protocol v2 C); an unverifiable row is skipped below
                // with the rest of the unreadable ones.
                if let device {
                    try MessageEnvelope.verifyUploadSignature(
                        row: row, vaultID: vaultID, device: device)
                } else {
                    throw KeyrefWireError.badSignature
                }
                let plaintext = try MessageEnvelope.open(
                    envelope: row.envelope, vaultID: vaultID,
                    sourceDeviceID: row.sourceDeviceID,
                    ownerDeviceID: deviceID, owner: owner)
                out.append(MessageInboxEntry(
                    messageID: row.messageID,
                    sourceDeviceID: row.sourceDeviceID,
                    sourceLabel: label,
                    sender: plaintext.sender,
                    body: plaintext.body,
                    sim: plaintext.sim ?? "",
                    receivedAt: plaintext.receivedAt,
                    createdAt: row.createdAt,
                    expiresAt: row.expiresAt,
                    status: row.status))
            } catch {
                // Not sealed to this device (it paired after the message
                // landed) or corrupt: skip rather than show garbage. The
                // 24-hour TTL is the documented self-heal (§14.3).
                continue
            }
        }
        // Newest first, by the server's created_at — never the
        // sender-reported received_at (§6.29).
        return out.sorted { $0.createdAt > $1.createdAt }
    }

    public func deleteMessage(messageID: String) async throws {
        try await api.deleteMessage(messageID: messageID)
    }

    /// 设为主接收端（design v0.8 §14.4）。nil 表示取消。角色改动只能随目录
    /// 重签下发（服务器只递送目录），所以这里改一个字节、revision+1。
    public func setPrimaryReceiver(deviceID: String?) async throws {
        let (_, owner, vaultID) = try guardUnlocked()
        guard let dir = stateStore.currentDirectory(),
              let devices = directoryDevices() else {
            throw APIError.notFound
        }
        if let deviceID {
            guard devices.contains(where: {
                $0.deviceID == deviceID && $0.kind == DeviceKind.ios
                    && $0.status == DeviceStatus.active
            }) else {
                throw APIError.notFound
            }
        }
        let updated = devices.map { d -> KeyrefDirectoryDevice in
            var copy = d
            copy.receiverRole = (deviceID != nil && d.deviceID == deviceID)
                ? ReceiverRole.primary : ReceiverRole.none
            return copy
        }
        try await publishDirectory(updated, revision: dir.directoryRevision + 1,
                                   owner: owner, vaultID: vaultID)
    }

    public func clearMessages() async throws {
        let rows = (try? await api.listMessages().messages) ?? []
        for row in rows {
            // Best effort per row: one failure must not strand the rest.
            try? await api.deleteMessage(messageID: row.messageID)
        }
    }

    public func decideApproval(approvalID: String, approve: Bool) async throws {
        guard let vaultID else { throw LockError.noVault }
        guard let record = approvalRecords[approvalID] else {
            throw APIError.notFound
        }
        // The decision is signed over the approval-decision transcript
        // (§3.12, v2 B): HPKE base mode authenticates nobody, so the CLI
        // must be able to tell a real decision from a server-made one.
        guard let owner, let deviceID = ownDeviceID else { throw LockError.noVault }
        let signer = owner.signer
        let decision: ApprovalDecisionRequest
        if approve {
            // §14.5: an SMS consumption delivers the message's plaintext
            // JSON to the CLI's ephemeral key (D18) — the message key never
            // crosses over, and the CLI has no endpoint to fetch the
            // envelope. The VMK is not needed: the payload was decrypted
            // when the request was loaded (the vault is unlocked by then).
            if record.row.isMessageSubject {
                guard let payload = record.messagePayload else {
                    throw APIError.notFound
                }
                decision = try ApprovalFlows.approveMessageDecision(
                    vaultID: vaultID, pending: record.row,
                    plaintext: record.plaintext, messagePlaintext: payload,
                    decisionDeviceID: deviceID, signer: signer)
                try await api.submitApprovalDecision(approvalID: approvalID, decision)
                approvalRecords.removeValue(forKey: approvalID)
                return
            }
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
                // 载荷换成 secret **值本身**——先解开本地包裹得到明文，再
                // HPKE 给请求的临时公钥；info 绑定不变。CLI 的 RequestSecret
                // 把解开的结果直接当注入值，所以这里送明文字节、不是密文，
                // 也不是 §3.7 的 secret JSON 包装（与 CLI e2e 契约一致）。
                let secretValue = try decryptSecret(itemRow, vmk: vmkValue, vaultID: vaultID)
                decision = try ApprovalFlows.approveSecretDeliveryDecision(
                    vaultID: vaultID, pending: record.row,
                    plaintext: record.plaintext, secretValueBytes: Data(secretValue.value.utf8),
                    decisionDeviceID: deviceID, signer: signer)
            } else {
                let itemKey = try ItemCrypto.unwrapItemKey(vmk: vmkValue,
                                                           blob: itemRow.vaultWrappedItemKey,
                                                           vaultID: vaultID,
                                                           itemID: record.plaintext.itemID)
                decision = try ApprovalFlows.approveDecision(vaultID: vaultID,
                                                             pending: record.row,
                                                             plaintext: record.plaintext,
                                                             itemKey: itemKey,
                                                             decisionDeviceID: deviceID,
                                                             signer: signer)
            }
        } else {
            decision = try ApprovalFlows.denyDecision(vaultID: vaultID, pending: record.row,
                                                       decisionDeviceID: deviceID,
                                                       signer: signer)
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
                                  grantsDigest: $0.grantsDigest,
                                  receiverRole: $0.receiverRole)
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
        persistLocalStateSeeds(vaultID: handoff.vaultID, ownDeviceID: pending.deviceID,
                               pinnedOwnerKey: handoff.ownerSignPublicKey, cursor: 0)
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
        // §6.7 恢复路径：接入后同时拉一次 iCloud 快照（验签、按 revision
        // 合并）——交接码里没带的条目从云端补齐。失败不阻塞。
        _ = try? await restoreCloudSnapshot()
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
            rows: stateStore.allItems(), secrets: localSecrets,
            exclusions: Array(snapshotExclusions.values), signer: signer)
    }

    func uploadSnapshotNow(vaultID: String, owner: OwnerKeys) async throws -> SnapshotManifest? {
        guard let store = snapshotStore else { return nil }
        return try await SnapshotEngine.uploadMerged(
            vaultID: vaultID, rows: stateStore.allItems(), state: stateStore,
            secrets: localSecrets, exclusions: Array(snapshotExclusions.values),
            signer: owner.signer, store: store,
            trustedOwnerKeys: trustedOwnerKeys())
    }

    /// §6.7 每条目覆盖：把一条仅本机条目排除出 / 放回 iCloud 副本。写入带
    /// 时间戳——快照 manifest 里的排除集按 LWW 合并，两台 owner 设备互不
    /// 静默翻转对方的选择（后写的决定胜出）。
    public func setSnapshotExcluded(itemID: String, excluded: Bool) {
        snapshotExclusions[itemID] = SnapshotExclusion(itemID: itemID, excluded: excluded,
                                                       atMillis: nowMillis())
        persistSnapshotExclusions()
        snapshotDirty = true
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

    // MARK: auto-approval delegation (design v0.8 §14.8, §6.31)

    /// `GET /v1/delegation`, parsed. nil when the server has never had
    /// one (revision 0) or when the stored bytes do not parse — the
    /// caller then shows "未开启" and the next save PUTs revision 1,
    /// which the server accepts only if the revision really is free.
    public func loadDelegation() async -> DelegationState? {
        guard let vaultID else { return nil }
        guard let resp = try? await api.getDelegation() else { return nil }
        let signed = resp.delegationSigned ?? Data()
        guard resp.delegationRevision >= 1, !signed.isEmpty else { return nil }
        guard let t = try? KeyrefDelegationTranscript.parse(signed, wantVaultID: vaultID),
              let policy = try? KeyrefDelegationPolicy.decode(json: t.policyJSON) else {
            return nil
        }
        return DelegationState(revision: resp.delegationRevision, policy: policy)
    }

    /// Signs the §3.10 transcript with THIS device's owner signing key —
    /// the same `owner.signer.sign(bytes)` primitive and the same key
    /// that signs the device directory, so the ASN.1 DER ECDSA signature
    /// is exactly what the server verifies for §6.15 — then PUTs it.
    public func putDelegation(revision: UInt64, policy: KeyrefDelegationPolicy) async throws {
        let (_, owner, vaultID) = try guardUnlocked()
        let transcript = KeyrefDelegationTranscript(
            vaultID: vaultID, delegationRevision: revision,
            policyJSON: try policy.encodedJSONString())
        let bytes = try transcript.buildBytes()
        let signature = try owner.signer.sign(bytes)
        try await api.putDelegation(DelegationPutRequest(
            delegationRevision: revision, delegationSigned: bytes,
            signature: signature))
    }
}
