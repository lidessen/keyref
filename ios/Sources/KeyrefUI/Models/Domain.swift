// UI-domain models shared by the stores and views (docs/ios-ui.md). Plain
// value types — the stores translate KeyrefCore rows into these.
import Foundation
import KeyrefCore

// MARK: - items

public struct GrantSummary: Identifiable, Equatable, Sendable {
    public var deviceID: String
    public var itemID: String
    public var kind: String  // "view" | "use"
    /// Unix millis; 0 = never expires.
    public var expiresAt: Int64

    public init(deviceID: String, itemID: String, kind: String, expiresAt: Int64) {
        self.deviceID = deviceID
        self.itemID = itemID
        self.kind = kind
        self.expiresAt = expiresAt
    }

    public var id: String { "\(deviceID)|\(itemID)|\(kind)" }
}

/// One decrypted list row (§2.4): only meta is decrypted here — the secret
/// stays sealed until the Face ID–gated reveal.
public struct ItemRow: Identifiable, Equatable, Sendable {
    public var id: String
    public var ref: String
    public var name: String
    public var itemDescription: String
    public var type: String
    public var masked: String
    public var policy: ItemPolicy
    public var injectable: Bool
    public var createdAt: Int64
    public var updatedAt: Int64
    public var grants: [GrantSummary]
    public var ciphertextBytes: Int

    public init(id: String, ref: String, name: String, itemDescription: String,
                type: String, masked: String, policy: ItemPolicy, injectable: Bool,
                createdAt: Int64, updatedAt: Int64, grants: [GrantSummary],
                ciphertextBytes: Int = 0) {
        self.id = id
        self.ref = ref
        self.name = name
        self.itemDescription = itemDescription
        self.type = type
        self.masked = masked
        self.policy = policy
        self.injectable = injectable
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.grants = grants
        self.ciphertextBytes = ciphertextBytes
    }
}

/// Draft for a new item (§2.6). `value` is required on create.
public struct ItemDraft: Equatable, Sendable {
    public var ref: String
    public var name: String
    public var itemDescription: String
    public var type: String
    public var value: String
    public var policy: ItemPolicy
    public var injectable: Bool

    public init(ref: String, name: String, itemDescription: String, type: String,
                value: String, policy: ItemPolicy, injectable: Bool = false) {
        self.ref = ref
        self.name = name
        self.itemDescription = itemDescription
        self.type = type
        self.value = value
        self.policy = policy
        self.injectable = injectable
    }
}

/// Draft for an edit; `value` empty = leave unchanged (§2.6).
public struct ItemEditDraft: Equatable, Sendable {
    public var name: String
    public var itemDescription: String
    public var value: String
    public var policy: ItemPolicy
    public var injectable: Bool

    public init(name: String, itemDescription: String, value: String,
                policy: ItemPolicy, injectable: Bool) {
        self.name = name
        self.itemDescription = itemDescription
        self.value = value
        self.policy = policy
        self.injectable = injectable
    }
}

// MARK: - devices

public struct DeviceRow: Identifiable, Equatable, Sendable {
    public var id: String
    public var kind: String       // "ios" | "cli"
    public var status: String     // pending | active | revoked
    public var label: String
    public var createdAt: Int64
    public var revokedAt: Int64?
    public var fingerprint: String
    public var grants: [GrantSummary]

    public init(id: String, kind: String, status: String, label: String,
                createdAt: Int64, revokedAt: Int64? = nil,
                fingerprint: String, grants: [GrantSummary]) {
        self.id = id
        self.kind = kind
        self.status = status
        self.label = label
        self.createdAt = createdAt
        self.revokedAt = revokedAt
        self.fingerprint = fingerprint
        self.grants = grants
    }

    public var isCLI: Bool { kind == "cli" }
    public var isActive: Bool { status == "active" }
    public var isPending: Bool { status == "pending" }
    public var isRevoked: Bool { status == "revoked" }
}

// MARK: - audit

public struct AuditRow: Identifiable, Equatable, Sendable {
    public var seq: Int64
    public var createdAt: Int64
    public var deviceID: String
    /// nil when decryption failed for this single row (§2.11 失败态).
    public var payload: AuditEventPayload?
    public var decryptFailed: Bool

    public init(seq: Int64, createdAt: Int64, deviceID: String,
                payload: AuditEventPayload?, decryptFailed: Bool) {
        self.seq = seq
        self.createdAt = createdAt
        self.deviceID = deviceID
        self.payload = payload
        self.decryptFailed = decryptFailed
    }

    public var id: Int64 { seq }
}

// MARK: - account / plan (S12, S13)

public struct AccountSnapshot: Equatable, Sendable {
    public var plan: String
    public var origin: String
    public var limits: PlanLimits?
    public var usage: AccountUsage?

    public init(plan: String, origin: String, limits: PlanLimits?, usage: AccountUsage?) {
        self.plan = plan
        self.origin = origin
        self.limits = limits
        self.usage = usage
    }

    /// S12: any hard limit reached.
    public var isOverQuota: Bool {
        guard let limits, let usage else { return false }
        if let items = limits.items, usage.items >= items { return true }
        if let storage = limits.storageBytes, usage.storageBytes >= storage { return true }
        if let requests = limits.requestsPerDay, usage.requestsToday >= requests { return true }
        return false
    }

    /// Which quota tripped (§2.17 原因行).
    public var overQuotaReason: String? {
        guard let limits, let usage else { return nil }
        if let items = limits.items, usage.items >= items {
            return "条目数已达上限（\(usage.items)/\(items)）"
        }
        if let storage = limits.storageBytes, usage.storageBytes >= storage {
            return "存储已达上限（\(Format.bytes(usage.storageBytes))/\(Format.bytes(storage))）"
        }
        if let requests = limits.requestsPerDay, usage.requestsToday >= requests {
            return "今日请求数已达上限（\(usage.requestsToday)/\(requests)）"
        }
        return nil
    }

    /// S13: frozen = read-only after 180 idle days; any successful login
    /// unfreezes, so the server reports it via `vault_frozen` until then.
    public var isFrozen: Bool { plan == "frozen" }

    public var isHosted: Bool {
        origin.hasPrefix("https://sync.keyref.app") || origin.hasPrefix("https://keys.example.com")
    }
}

// MARK: - creation prerequisites (§2.2)

public struct Prerequisite: Identifiable, Equatable, Sendable {
    public var id: String
    public var title: String
    public var satisfied: Bool

    public init(id: String, title: String, satisfied: Bool) {
        self.id = id
        self.title = title
        self.satisfied = satisfied
    }
}

// MARK: - sync

public struct SyncOutcomeInfo: Equatable, Sendable {
    public var applied: Int
    public var deleted: Int
    public var revokedSelf: Bool

    public init(applied: Int = 0, deleted: Int = 0, revokedSelf: Bool = false) {
        self.applied = applied
        self.deleted = deleted
        self.revokedSelf = revokedSelf
    }
}

// MARK: - recovery flows (§2.12, §2.13)

public enum RecoveryMode: Equatable, Sendable {
    /// 接管：旧设备全部撤销（§8.5）。
    case takeover
    /// 本机重建：只更新本机登记，其他设备不动（§9.5）。
    case localRebuild
}

public enum RecoveryInputError: Error, Equatable {
    /// 「恢复码不正确。」
    case badCode
    /// 「在当前服务器上找不到这个保险库。」
    case vaultNotFound
    /// 「尝试太频繁，请稍后再试。」
    case rateLimited
    case network(String)
}

/// Everything computed before the irreversible commit point.
public struct RecoveryPreparation: Sendable {
    public var mode: RecoveryMode
    public var vaultID: String
    public var vmk: Data
    public var deviceCountToRevoke: Int
}

public struct TakeoverSummary: Equatable, Sendable {
    public var itemCount: Int
    public var revokedDeviceCount: Int
}

// MARK: - revoke (§2.10)

public enum RevokeStep: Equatable, Sendable {
    case directory          // 重签设备目录
    case grants             // 删除授权
    case rotation(remaining: Int)  // 重新加密（逐条，剩余 K 条）
}

public struct RevokeSummary: Equatable, Sendable {
    public var deviceID: String
    public var rotatedCount: Int
}

// MARK: - pair completion

public struct GrantSelection: Equatable, Sendable {
    public var itemID: String
    public var kind: String

    public init(itemID: String, kind: String) {
        self.itemID = itemID
        self.kind = kind
    }
}
