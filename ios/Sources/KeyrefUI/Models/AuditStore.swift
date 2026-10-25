// Audit tab state (docs/ios-ui.md §2.11): locally decrypted event stream
// (§7.7 — the server only ever sees ciphertext), device/ref/result filters,
// and the two failure faces (single row / whole batch).
import Foundation
import KeyrefCore

public enum AuditResultFilter: String, CaseIterable, Equatable, Sendable {
    case all
    case passed
    case denied

    public var label: String {
        switch self {
        case .all: return "全部"
        case .passed: return "通过"
        case .denied: return "拒绝"
        }
    }
}

@Observable
@MainActor
public final class AuditStore {
    let backend: any AppBackend
    let haptics: any Haptics

    public private(set) var rows: [AuditRow] = []
    public var deviceFilter: String?
    public var refFilter: String?
    public var resultFilter: AuditResultFilter = .all
    public private(set) var batchFailed = false
    public private(set) var loading = false

    /// 保留期脚注（§7.7、§10.5）。
    public static let retentionFootnote = "免费档保留 7 天、最多 100 条，到期由服务器删除。"

    public init(backend: any AppBackend, haptics: any Haptics) {
        self.backend = backend
        self.haptics = haptics
    }

    public var deviceNames: [String] {
        var names: [String] = []
        for row in rows {
            let name = deviceLabel(row.deviceID)
            if !names.contains(name) { names.append(name) }
        }
        return names
    }

    public var refs: [String] {
        var refs: [String] = []
        for row in rows {
            for ref in row.payload?.refs ?? [] where !refs.contains(ref) {
                refs.append(ref)
            }
        }
        return refs
    }

    public func deviceLabel(_ deviceID: String) -> String {
        deviceID
    }

    public var filtered: [AuditRow] {
        rows.filter { row in
            if let deviceFilter, row.deviceID != deviceFilter { return false }
            if let refFilter, !(row.payload?.refs.contains(refFilter) ?? false) { return false }
            switch resultFilter {
            case .all: return true
            case .passed:
                return row.payload.map { $0.policyResult == "allow" || $0.policyResult == "pass" } == true
            case .denied:
                return row.payload.map { $0.policyResult != "allow" && $0.policyResult != "pass" } == true
            }
        }
    }

    /// Loads encrypted rows, then decrypts one batch behind one Face ID
    /// (§7.7: 每个事件随机事件密钥、分别 HPKE 给每台 owner，本机只解发给自己的).
    public func refresh(authenticator: any BiometricAuthenticator) async {
        loading = true
        defer { loading = false }
        let encrypted = await backend.loadEncryptedAuditRows()
        guard !encrypted.isEmpty else {
            rows = []
            batchFailed = false
            return
        }
        if encrypted.contains(where: { $0.payload == nil && !$0.decryptFailed }) {
            let result = await authenticator.authenticate(reason: "解密审计记录")
            guard case .success = result else {
                batchFailed = true
                return
            }
        }
        rows = await backend.decryptAuditRows()
        batchFailed = rows.allSatisfy { $0.decryptFailed }
    }
}
