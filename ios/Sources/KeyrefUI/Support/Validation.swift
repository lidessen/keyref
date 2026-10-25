// Field validation for the item editor (docs/ios-ui.md §2.6): ref syntax
// (design §6.1), the §7.3 default-deny list, and the §7.4 paste-leak
// matchers used by the save-time check.
import Foundation

// MARK: - ref syntax (design §6.1)

public enum RefValidation {
    /// `^[a-z][a-z0-9-]{0,62}[a-z0-9]$` or a single lowercase char.
    public static func isValid(_ ref: String) -> Bool {
        if ref.count == 1 {
            return ref.first.map { "a"..."z" ~= $0 || "0"..."9" ~= $0 } == true
        }
        guard (2...64).contains(ref.count), let first = ref.first, let last = ref.last else {
            return false
        }
        guard ("a"..."z").contains(first) else { return false }
        guard ("a"..."z").contains(last) || ("0"..."9").contains(last) else { return false }
        for ch in ref {
            if ("a"..."z").contains(ch) || ("0"..."9").contains(ch) || ch == "-" { continue }
            return false
        }
        return true
    }
}

// MARK: - §7.3 default-deny list

public enum DefaultDeny {
    /// The §7.3 argv0 set (deny-shells policy). Adding a name from here to
    /// `allowCommands` triggers the one-time save-time confirmation.
    public static let commands: Set<String> = [
        "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "busybox",
        "env", "printenv",
        "echo", "printf",
        "cat", "tee", "dd", "od", "xxd", "hexdump", "base64", "base32",
        "openssl",
        "python", "python2", "python3", "node", "nodejs", "deno", "bun",
        "perl", "ruby", "php", "lua",
        "osascript", "socat",
    ]

    /// Case-insensitive basename check (the CLI also resolves shebangs and
    /// symlinks; the UI flags the literal names the human typed).
    public static func isDenied(_ argv0: String) -> Bool {
        let base = argv0.split(separator: "/").last.map(String.init) ?? argv0
        return commands.contains(base.lowercased())
    }
}

// MARK: - §7.4 matchers (paste-leak check at save time)

public enum SecretLeak {
    /// Checks `candidate` (a name or description) against the secret value
    /// and its common encodings (design §12.1 flow 3: 与 §7.4 同一套匹配器 —
    /// 原文、Base64、hex、percent-encoding). Values shorter than 8 bytes are
    /// still matched (matching §7.4's behaviour) but only reported for
    /// non-trivial candidates.
    public static func leaks(secret: String, in candidate: String) -> Bool {
        let secret = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !secret.isEmpty, !candidate.isEmpty else { return false }
        let needle = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = secret.data(using: .utf8) else { return false }

        let forms: [String] = [
            secret,                                       // 原文
            data.base64EncodedString(),                   // Base64
            base64Unpadded(data.base64EncodedString()),   // Base64 去掉填充
            urlSafeBase64(data.base64EncodedString(), padded: true),
            urlSafeBase64(data.base64EncodedString(), padded: false),
            hexLower(data),                               // 小写 hex
            hexLower(data).uppercased(),                  // 大写 hex
            percentEncoded(data),                         // RFC 3986 percent-encoding
        ]
        return forms.contains { form in
            !form.isEmpty && form.count >= 8 && needle.localizedCaseInsensitiveContains(form)
        }
    }

    /// Which label matched, for the alert body wording.
    public static func leakKind(secret: String, in candidate: String) -> String? {
        let secret = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = secret.data(using: .utf8) else { return nil }
        if candidate.localizedCaseInsensitiveContains(secret), secret.count >= 8 { return "原文" }
        let b64 = data.base64EncodedString()
        if b64.count >= 8 && candidate.localizedCaseInsensitiveContains(b64) { return "Base64" }
        if base64Unpadded(b64).count >= 8 && candidate.localizedCaseInsensitiveContains(base64Unpadded(b64)) { return "Base64" }
        let h = hexLower(data)
        if h.count >= 8 && candidate.localizedCaseInsensitiveContains(h) { return "hex" }
        if h.uppercased().count >= 8 && candidate.localizedCaseInsensitiveContains(h.uppercased()) { return "hex" }
        let pe = percentEncoded(data)
        if pe.count >= 8 && candidate.localizedCaseInsensitiveContains(pe) { return "URL" }
        return nil
    }

    private static func base64Unpadded(_ s: String) -> String {
        s.replacingOccurrences(of: "=", with: "")
    }

    private static func urlSafeBase64(_ s: String, padded: Bool) -> String {
        var t = s.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        if !padded { t = base64Unpadded(t) }
        return t
    }

    private static func hexLower(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func percentEncoded(_ data: Data) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        let s = String(decoding: data, as: UTF8.self)
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }
}
