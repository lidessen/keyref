// Shared display formatters (docs/ios-ui.md §2.5 S14, §2.11, §3.6): expiry
// markers, byte and time formatting, VoiceOver readings for masks, recovery
// codes, fingerprints and argv placeholders.
import Foundation

public enum ExpiryMark: Equatable, Sendable {
    case none
    /// 黄色「7 天后到期」。
    case inSevenDays
    /// 红色「明天到期」。
    case tomorrow

    public var text: String {
        switch self {
        case .none: return ""
        case .inSevenDays: return "7 天后到期"
        case .tomorrow: return "明天到期"
        }
    }

    public static func mark(expiresAt: Date, now: Date = Date()) -> ExpiryMark {
        guard expiresAt > now else { return .tomorrow }
        let seconds = expiresAt.timeIntervalSince(now)
        if seconds <= 86_400 { return .tomorrow }
        if seconds <= 7 * 86_400 { return .inSevenDays }
        return .none
    }
}

public enum Format {
    /// 紧凑的本地时间戳（`2026-11-01 04:27`）。中文长日期
    /// （`2026年11月1日 04:27`）在条目详情的标签—值行里放不下，会被截成
    /// 「2026年11月1日 04:…」；紧凑写法单行放得下、和其它元数据一样等宽，
    /// 字典序也就是时间序。§2.5 只要求「创建与修改时间」出现在条目详情里，
    /// 没有钉死格式。
    static let isoFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm"
        return f
    }()

    public static func dateTime(_ millis: Int64) -> String {
        guard millis > 0 else { return "—" }
        return isoFormatter.string(from: Date(timeIntervalSince1970: Double(millis) / 1000))
    }

    public static func bytes(_ count: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: count, countStyle: .binary)
    }

    /// Fingerprint split into per-group VoiceOver labels (§3.6: 按组朗读).
    public static func fingerprintSpokenGroups(_ fingerprint: String) -> [String] {
        fingerprint.split(separator: "-").map(String.init)
    }

    /// `{{keyref:openai-prod}}` reads as 「占位符 openai-prod」 (§3.6), never
    /// character-by-character through the braces.
    public static func argvSpokenForm(_ arg: String) -> String {
        guard arg.hasPrefix("{{keyref:"), arg.hasSuffix("}}") else { return arg }
        let ref = arg.dropFirst("{{keyref:".count).dropLast(2)
        return "占位符 \(ref)"
    }

    /// Type badge labels (§2.4: KEY / TOKEN / 密码 / 笔记 / 通用).
    public static func typeBadge(_ type: String) -> String {
        switch type {
        case "api_key": return "KEY"
        case "token": return "TOKEN"
        case "password": return "密码"
        case "note": return "笔记"
        default: return "通用"
        }
    }

    /// Mask VoiceOver reading (§3.6): api_key/token read 「已隐藏，末四位 abcd」;
    /// password/note read 「已完全隐藏」. Never reads `*` or hyphens.
    public static func maskSpoken(masked: String, type: String) -> String {
        switch type {
        case "password", "note":
            return "已完全隐藏"
        default:
            let tail = String(masked.suffix(4)).replacingOccurrences(of: "*", with: "")
            if tail.isEmpty { return "已完全隐藏" }
            return "已隐藏，末四位 \(tail)"
        }
    }

    /// Audit result badge (§2.11: 策略通过 / 被拒绝 / 退出码 N).
    public static func auditResultBadge(policyResult: String, childExit: Int) -> String {
        switch policyResult {
        case "allow", "pass", "policy_allow": return "策略通过"
        case "deny", "reject", "policy_deny": return "被拒绝"
        default: return childExit == 0 ? "策略通过" : "退出码 \(childExit)"
        }
    }

    public static func grantLevelLabel(_ kind: String) -> String {
        kind == "use" ? "使用" : "查看"
    }
}

// MARK: - recovery code groups

public enum RecoveryCodeGroups {
    /// Splits a full code into 5-symbol groups (display form uses '-' and
    /// spaces; Crockford folding happens on input).
    public static func groups(of code: String) -> [String] {
        code.split(whereSeparator: { $0 == "-" || $0 == " " }).map(String.init)
    }

    /// Normalizes one group for comparison: uppercase, Crockford folding
    /// (0/O、1/I/L 视为同字符), separators stripped.
    public static func normalize(_ group: String) -> String {
        String(group.uppercased().compactMap { ch -> Character? in
            switch ch {
            case "-", " ": return nil
            case "I", "L": return "1"
            case "O": return "0"
            default: return ch
            }
        })
    }

    /// Splits a pasted blob into groups: strips spaces and hyphens, folds
    /// confusables, and chunks into 5-symbol groups (§2.2 支持整段粘贴).
    public static func parsePasted(_ raw: String, groupSize: Int = 5) -> [String] {
        var symbols = raw.uppercased().compactMap { ch -> Character? in
            switch ch {
            case "-", " ": return nil
            case "I", "L": return "1"
            case "O": return "0"
            default: return ("0"..."9").contains(ch) || ("A"..."Z").contains(ch) ? ch : nil
            }
        }
        guard !symbols.isEmpty else { return [] }
        var groups: [String] = []
        while !symbols.isEmpty {
            let n = min(groupSize, symbols.count)
            groups.append(String(symbols.prefix(n)))
            symbols.removeFirst(n)
        }
        return groups
    }
}
