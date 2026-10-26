// Masked-value derivation (design §6.1): computed by iOS at save time and
// sealed into item meta. `list`/`get` only decrypt meta, so a view-granted
// agent sees exactly this string and no plaintext — the prefix table below
// is the deliberate, documented leak (§6.1: 有意接受的小泄露).
import Foundation

public enum ItemMasking {
    /// §6.1 前缀表，按最长前缀匹配。命中且总长度足够时，masked 保留前缀
    /// 与末四位（例如 `sk-****abcd`）；否则一律 `***`。
    public static let prefixes: [String] = [
        "github_pat_", "sk-proj-", "sk-ant-", "glpat-", "xoxb-", "xoxp-", "xoxa-",
        "ghp_", "gho_", "sk-", "AKIA",
    ]

    /// Longest matching §6.1 prefix, or "" when nothing matches.
    public static func longestPrefix(of value: String) -> String {
        var best = ""
        for p in prefixes where value.hasPrefix(p) && p.count > best.count {
            best = p
        }
        return best
    }

    /// §6.1 掩码规则：
    /// - `password` / `note` 永远 `***`（口令通常更短，末几位本身就能用）。
    /// - 其余类型（api_key / token / generic）按最长前缀匹配；总长度至少
    ///   比前缀多 8 个字符时保留「前缀 + **** + 末四位」，否则 `***`。
    ///   无前缀命中时前缀按空串处理（下限即总长 ≥ 8）。
    public static func mask(_ value: String, type: String) -> String {
        guard !value.isEmpty else { return "***" }
        switch type {
        case "password", "note":
            return "***"
        default:
            let prefix = longestPrefix(of: value)
            guard value.count >= prefix.count + 8 else { return "***" }
            return prefix + "****" + String(value.suffix(4))
        }
    }
}
