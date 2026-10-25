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
    /// Device ids whose §8.4 rotation is mid-flight (§2.10 失败态).
    var pendingRotation: [String: Int] = [:]
    var auditCursor: Int64 = 0
    var encryptedAudit: [EncryptedAuditRow] = []

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

    public init(keyStore: KeyStore, stateStore: UIStateStore,
                origin: URL = URL(string: "https://sync.keyref.app")!) {
        self.keyStore = keyStore
        self.stateStore = stateStore
        self.origin = origin
    }

    var api: APIClient {
        APIClient(baseURL: origin, bearerToken: { [sessionBox] in sessionBox.get() })
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
                ciphertextBytes: row.metaCiphertext.count + row.secretCiphertext.count))
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

    func decryptSecret(_ row: ItemData, vmk: Data, vaultID: String) throws -> SecretPlaintext {
        let itemKey = try ItemCrypto.unwrapItemKey(vmk: vmk, blob: row.vaultWrappedItemKey,
                                                   vaultID: vaultID, itemID: row.itemID)
        return try ItemCrypto.openSecret(key: itemKey, blob: row.secretCiphertext,
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
        let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: itemID, revision: 1,
                                             writerDeviceID: deviceID, vmk: vmk,
                                             signer: owner.signer, meta: meta,
                                             secret: SecretPlaintext(v: 1, value: draft.value))
        storeSealed(sealed, itemID: itemID, revision: 1, vaultID: vaultID, deviceID: deviceID)
        _ = try? await api.putItem(itemID: itemID, putRequest(sealed, revision: 1, deviceID: deviceID))
    }

    public func updateItem(id: String, _ draft: ItemEditDraft) async throws {
        let (vmk, owner, vaultID) = try guardUnlocked()
        let deviceID = ownDeviceID ?? ""
        guard let row = stateStore.itemByID(id),
              let oldMeta = try? decryptMeta(row, vmk: vmk, vaultID: vaultID),
              let oldSecret = try? decryptSecret(row, vmk: vmk, vaultID: vaultID) else {
            throw APIError.notFound
        }
        let value = draft.value.isEmpty ? oldSecret.value : draft.value
        let meta = ItemMeta(v: 1, ref: oldMeta.ref, name: draft.name,
                            description: draft.itemDescription, type: oldMeta.type,
                            masked: maskOf(value, type: oldMeta.type),
                            injectable: draft.injectable, policy: draft.policy)
        let revision = row.revision + 1
        let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: id, revision: revision,
                                             writerDeviceID: deviceID, vmk: vmk,
                                             signer: owner.signer, meta: meta,
                                             secret: SecretPlaintext(v: 1, value: value))
        storeSealed(sealed, itemID: id, revision: revision, vaultID: vaultID, deviceID: deviceID)
        _ = try? await api.putItem(itemID: id, putRequest(sealed, revision: revision, deviceID: deviceID))
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
        try await reencryptItem(row, meta: meta,
                                value: newValue.isEmpty ? old.value : newValue,
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
        vmk = nil
        self.owner = nil
        hasVault = false
        self.vaultID = nil
        ownDeviceID = nil
        cachedItemCount = 0
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
}
