// The one seam between the @Observable stores and KeyrefCore. The app shell
// injects a LiveBackend (real crypto, Keychain, network); tests and previews
// inject a MemoryBackend. @MainActor keeps the store state machine simple;
// every network-touching method is async.
import Foundation
import KeyrefCore

/// Why a biometric-confirmed unlock attempt could not complete. S2/S3/S4
/// (docs/ios-ui.md §2.3) are exactly these cases.
public enum LockError: Error, Equatable {
    /// Face ID failed; the wrap is intact (S3).
    case biometricFailed
    /// The local VMK wrap can no longer be opened — biometric set changed
    /// (S4). Rebuild with the recovery code (§9.5).
    case wrapInvalid
    /// No local vault (S1).
    case noVault
}

@MainActor
public protocol AppBackend: AnyObject {
    // MARK: lifecycle / phase

    /// Whether a vault exists locally (S1 gate).
    var hasVault: Bool { get }
    var vaultID: String? { get }
    var ownDeviceID: String? { get }
    /// Cached, non-sensitive count shown on the lock screen (S2).
    var cachedItemCount: Int { get }
    /// True after the local wrap was detected as permanently invalid (S4).
    var localWrapInvalid: Bool { get }
    /// Current server origin (settings → server row, §2.14).
    var origin: URL { get }
    var plan: String { get }

    /// Reads local state at boot: whether the wrap exists, cached counts.
    func loadLocalState() async
    /// After a successful Face ID: unwrap the VMK. Throws LockError.wrapInvalid
    /// when the enclave wrap is permanently dead (S4).
    func unlockAfterBiometrics() async throws
    /// Drops the VMK from memory (manual lock or background).
    func lock()

    // MARK: creation (§2.2)

    /// 设备密码已设置、Face ID 已录入 — both required (§9.3).
    func checkPrerequisites() -> [Prerequisite]
    /// Generates owner keys, VMK, recovery code and the revision-1 directory.
    /// The recovery code is shown exactly once (S9).
    func prepareCreation(label: String) async throws -> CreatedVaultDraft
    /// Uploads a previously prepared vault. Retry keeps the same code (§2.2).
    func uploadCreatedVault(_ draft: CreatedVaultDraft) async throws

    // MARK: items (§2.4–§2.6)

    func loadItems() async -> [ItemRow]
    /// Decrypts the secret for the Face ID–gated reveal layer.
    func revealSecret(_ itemID: String) throws -> String
    func createItem(_ draft: ItemDraft) async throws
    func updateItem(id: String, _ draft: ItemEditDraft) async throws
    func deleteItem(id: String) async throws
    /// 替换值（轮换）: new item key, re-encrypt, re-wrap grants (§2.5).
    func rotateItem(id: String, newValue: String) async throws

    // MARK: sync & account (§2.4, §2.17)

    func syncNow() async throws -> SyncOutcomeInfo
    func fetchAccount() async -> AccountSnapshot?
    /// 未登录的 recovery 端点探测（S11 切换前先探测, §8.5）。
    func probeVaultExists(onOrigin: URL) async -> Bool

    // MARK: devices & grants (§2.7–§2.10)

    func loadDevices() async -> [DeviceRow]
    /// Completes a scanned pairing: signs the pair transcript with the
    /// selected grants (empty until the human checks boxes, design §15).
    func completePairing(offer: PairingOffer, deviceLabel: String,
                         selections: [GrantSelection]) async throws
    func appendGrants(deviceID: String, _ selections: [GrantSelection]) async throws
    func revokeGrant(deviceID: String, itemID: String, kind: String) async throws
    func renameDevice(deviceID: String, label: String) async throws
    /// 撤销（默认含轮换, §8.4）。Reports progress for the checklist page.
    func revokeDevice(deviceID: String, rotate: Bool,
                      progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> RevokeSummary
    /// Resumes an interrupted rotation (§2.10 失败态: 撤销先于轮换生效).
    func resumeRotation(deviceID: String,
                        progress: @Sendable @escaping (RevokeStep) async -> Void) async throws -> RevokeSummary
    /// Whether a rotation for this device is mid-flight and resumable.
    func hasPendingRotation(deviceID: String) -> Bool

    // MARK: audit (§2.11)

    /// Loads encrypted rows from the local cache (no decryption).
    func loadEncryptedAuditRows() async -> [AuditRow]
    /// Decrypts a batch with one Face ID (§7.7). Rows that fail individually
    /// stay marked decryptFailed.
    func decryptAuditRows() async -> [AuditRow]

    // MARK: settings (§2.14–§2.17)

    func fetchAccountSnapshot() async -> AccountSnapshot?
    /// Applies a new origin. With a vault present the caller confirms first:
    /// rebuild on the new origin + full upload (§8.5 迁移).
    func switchOrigin(to newOrigin: URL,
                      progress: @Sendable @escaping (MigrationStep) async -> Void) async throws
    /// Two-step delete (§2.16): challenge, then owner-signed confirmation.
    /// Never reports success unless the server confirmed.
    func deleteVault() async throws
    /// 「轮换 VMK 与恢复码」— new wrap layer + new recovery code (§8.4).
    func rotateVMKAndRecovery() async throws -> String
    /// 「怀疑恢复码泄露」— same + rotate every item key and re-encrypt (B5).
    func rotateRecoveryCodeFull() async throws -> String

    // MARK: recovery (§2.12, §2.13)

    /// Parses the code, fetches materials, unwraps the VMK and builds the
    /// signed directory. Everything before the irreversible commit.
    func prepareRecovery(code: String, mode: RecoveryMode) async throws -> RecoveryPreparation
    /// Commits. Takeover revokes all old devices and re-downloads; local
    /// rebuild only refreshes this device's row (§8.5, §9.5).
    func commitRecovery(_ prep: RecoveryPreparation,
                        progress: @Sendable @escaping (RecoveryStep) async -> Void) async throws -> TakeoverSummary

    // MARK: approvals (Phase 2, §8.3)

    /// `GET /v1/approvals?status=pending`, then opens and signature-verifies
    /// each request against the signed directory. Requests that fail to
    /// decrypt or verify come back with valid == false (显示为无效并可忽略).
    func loadPendingApprovals() async -> [ApprovalInboxEntry]
    /// Submits the §6.21 decision. Approve requires the unlocked VMK: the
    /// item key is wrapped one-time to the request's ephemeral key (§8.3
    /// step 3); deny carries no key material. The Face ID gate is the
    /// caller's (one authentication, one semantic, §3.3).
    func decideApproval(approvalID: String, approve: Bool) async throws

    // MARK: second iPhone (Phase 2, §9.4 path 2)

    /// 新手机：generates this device's owner identity, keeps it pending and
    /// returns the join offer to render as a QR.
    func prepareJoinOffer(label: String) async throws -> JoinOffer
    /// 旧手机（Face ID by caller）：signs a directory revision with both
    /// owners (PUT /v1/directory, revision + 1) and wraps the VMK to the
    /// new phone's key. Returns the handoff payload to display as a QR.
    func admitSecondDevice(offer: JoinOffer, label: String) async throws -> String
    /// 新手机：parses the handoff, unwraps the VMK (AEAD tag = verdict),
    /// persists local state, starts a session and bootstraps from cursor 0.
    func adoptSecondDevice(handoffPayload: String) async throws

    // MARK: push (Phase 2, §13)

    /// 上传本机 APNs token（PUT /v1/devices/push-token）。true = 服务器已
    /// 确认（204）；false = 当前无有效会话或上传失败——注册状态机在下次
    /// 解锁后重试，前台轮询兜底不受影响（失败静默，§13）。
    func putPushToken(token: String, env: String) async -> Bool

    // MARK: rotation ritual (v0.7, §8.4 定期轮换)

    /// 立即轮换全部条目（同步条目原子 PUT：新 item key、重包裹、重加密、
    /// revision + 1；仅本机条目只轮换本地包裹，不动服务器）。逐条自洽：
    /// 中途失败可整轮重试。仅统计同步条目的轮换数（§8.4）。
    func rotateAllItems(progress: @Sendable @escaping (RotationProgress) async -> Void) async throws -> RotationSummary

    // MARK: iCloud whole-file copy (v0.7, §6.7)

    /// 全局开关（默认开）。关闭后不再上传，已有副本保留在 iCloud。
    func setCloudBackupEnabled(_ enabled: Bool)
    /// 编辑后去抖上传：退后台 / 解锁合并时调用；没有待传内容时是 no-op。
    func uploadSnapshotIfDirty() async
    /// 「副本」状态（设置页显示；绝不阻塞本地功能，§6.7 降级）。
    func cloudBackupStatus() async -> CloudBackupStatus
    /// 恢复接管 / 双机加入完成后：拉取云端快照、验签、按 revision 合并入库
    /// （§6.7 恢复路径）。云端没有快照或验签不过时抛错/返回 0。
    @discardableResult
    func restoreCloudSnapshot() async throws -> SnapshotRestoreSummary
}

/// A freshly created vault, before upload. The recovery code is displayed
/// exactly once and grouped for the backfill check (S9).
public struct CreatedVaultDraft: Equatable, Sendable {
    public var vaultID: String
    public var recoveryCode: String
    /// Grouped display form (5 symbols per group).
    public var recoveryGroups: [String]
    public var uploaded: Bool

    public init(vaultID: String, recoveryCode: String, recoveryGroups: [String], uploaded: Bool) {
        self.vaultID = vaultID
        self.recoveryCode = recoveryCode
        self.recoveryGroups = recoveryGroups
        self.uploaded = uploaded
    }
}

public enum MigrationStep: Equatable, Sendable {
    case createVaultOnNewOrigin
    case fullUpload
    case verify
}

public enum RecoveryStep: Equatable, Sendable {
    case fetchMaterials       // 取回恢复材料
    case unwrapVMK            // 解开主密钥
    case generateOwnerKeys    // 生成这台手机的新隔区密钥
    case signTranscript       // 签署接管誊本 / 更新本机在设备目录中的登记
    case download             // 下载全部密文 / 校验本地密文
    case rotateItems(remaining: Int)  // 轮换条目密钥并重加密
}
