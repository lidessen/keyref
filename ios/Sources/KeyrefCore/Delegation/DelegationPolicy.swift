// The owner-signed auto-approval delegation policy (docs/protocol.md
// §3.10, design v0.8 §14.8).
//
// The policy is the plaintext JSON inside the signed delegation
// transcript. The server only verifies the signature and relays the
// bytes; the decider is the only party that reads it. An empty
// delegation — `{"v":1}` — revokes: no sender allowlist, so nothing can
// ever be auto-approved. There is no separate null form.
//
// The decider may only narrow: every field is an additional constraint,
// and an unknown field is a parse error rather than something to ignore
// (a policy the decider half-understands must never be treated as wider
// than it is). Decoding therefore rejects unknown keys outright.
//
// Encoding is byte-stable on purpose: the transcript carries these bytes
// verbatim and the decider re-parses them, so Swift and Go must emit the
// same JSON for the same policy. That means a fixed key order — not
// JSONEncoder's — and Go's `omitempty` omission rules.
import Foundation

public struct KeyrefDelegationPolicy: Equatable, Sendable, Decodable {
    /// Protocol version carried in every policy (§3.10). Always 1.
    public static let version = 1

    /// Allowlist of SMS senders. Byte-exact: a policy listing "10086"
    /// does not cover "+8610086". Empty = nothing can be auto-approved.
    public var senders: [String]
    /// Message age bound in minutes, measured by the SERVER's clock
    /// (§6.29). 0 = no bound.
    public var maxAgeMin: Int64
    /// Auto-approval cap per CLI device per rolling hour. 0 = no cap.
    public var perCLIHourly: Int64
    /// Auto-approval cap per CLI device per rolling day. 0 = no cap.
    public var perCLIDaily: Int64
    /// CLI devices that may be auto-approved at all; empty = no
    /// restriction (every CLI is eligible, still subject to the rest).
    public var cliDevices: [String]

    public init(senders: [String] = [], maxAgeMin: Int64 = 0,
                perCLIHourly: Int64 = 0, perCLIDaily: Int64 = 0,
                cliDevices: [String] = []) {
        self.senders = senders
        self.maxAgeMin = maxAgeMin
        self.perCLIHourly = perCLIHourly
        self.perCLIDaily = perCLIDaily
        self.cliDevices = cliDevices
    }

    /// The revocation policy `{"v":1}`: no sender allowlist, so no
    /// auto-approval is possible (design §14.8 撤销).
    public static let revocation = KeyrefDelegationPolicy()

    /// True for the empty/revoking policy — the same predicate as Go's
    /// `DelegationPolicy.IsEmpty`.
    public var isEmpty: Bool { senders.isEmpty }

    /// Readable name for `isEmpty` in the UI: an installed-but-empty
    /// policy is a completed withdrawal, not a missing one.
    public var isRevocation: Bool { isEmpty }

    // MARK: validation (mirrors wire.ParseDelegationPolicy)

    /// Field-by-field bounds, in Go's check order. Throws
    /// `KeyrefWireError.invalidField`.
    public func validate() throws {
        for s in senders {
            let n = s.utf8.count
            guard n >= 1 && n <= 64 else {
                throw KeyrefWireError.invalidField("policy sender must be 1..64 bytes")
            }
        }
        for d in cliDevices {
            guard KeyrefEncoding.isValidID(d) else {
                throw KeyrefWireError.invalidField("policy cli_devices must be 32 lowercase hex")
            }
        }
        guard maxAgeMin >= 0, perCLIHourly >= 0, perCLIDaily >= 0 else {
            throw KeyrefWireError.invalidField("policy limits must not be negative")
        }
    }

    // MARK: encoding (byte-stable)

    /// `policy_json` bytes: fixed key order
    /// (v, senders, max_age_min, per_cli_hourly, per_cli_daily,
    /// cli_devices) and Go's `omitempty` rules — empty arrays and zero
    /// limits are omitted, so Swift and Go produce the same bytes for
    /// the same policy.
    public func encodedJSONString() throws -> String {
        try validate()
        var out = "{\"v\":\(Self.version)"
        if !senders.isEmpty {
            out += ",\"senders\":["
            for (i, s) in senders.enumerated() {
                if i > 0 { out += "," }
                out += "\"\(Self.escapeJSON(s))\""
            }
            out += "]"
        }
        if maxAgeMin != 0 { out += ",\"max_age_min\":\(maxAgeMin)" }
        if perCLIHourly != 0 { out += ",\"per_cli_hourly\":\(perCLIHourly)" }
        if perCLIDaily != 0 { out += ",\"per_cli_daily\":\(perCLIDaily)" }
        if !cliDevices.isEmpty {
            out += ",\"cli_devices\":["
            for (i, d) in cliDevices.enumerated() {
                if i > 0 { out += "," }
                out += "\"\(d)\""
            }
            out += "]"
        }
        out += "}"
        return out
    }

    /// Go's `encoding/json` string escaping (`json.Marshal`): `"` and
    /// `\` quoted, the five short control escapes, other C0 controls as
    /// lowercase `\u00xx`, plus the HTML-sensitive `<`, `>`, `&` and the
    /// two JSON line separators. Everything else — including U+007F and
    /// all non-ASCII — is emitted raw.
    private static func escapeJSON(_ s: String) -> String {
        let hex = Array("0123456789abcdef")
        var out = ""
        out.reserveCapacity(s.utf8.count + 2)
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "<": out += "\\u003c"
            case ">": out += "\\u003e"
            case "&": out += "\\u0026"
            case "\u{2028}": out += "\\u2028"
            case "\u{2029}": out += "\\u2029"
            default:
                let v = scalar.value
                if v < 0x20 {
                    out += "\\u00"
                    out.append(hex[Int(v >> 4)])
                    out.append(hex[Int(v & 0xf)])
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }

    // MARK: decoding (strict)

    /// Decodes `policy_json`, rejecting unknown fields, a wrong `v`,
    /// out-of-range senders/ids and negative limits — the same rules as
    /// Go's `ParseDelegationPolicy`.
    public static func decode(json: String) throws -> KeyrefDelegationPolicy {
        guard let data = json.data(using: .utf8) else {
            throw KeyrefWireError.invalidField("policy_json must be valid utf-8")
        }
        do {
            return try WireJSON.decoder.decode(KeyrefDelegationPolicy.self, from: data)
        } catch let e as KeyrefWireError {
            throw e
        } catch {
            throw KeyrefWireError.invalidField("policy_json: \(error)")
        }
    }

    /// A CodingKey that accepts any string, so `allKeys` actually lists
    /// what the JSON contains — an enum-backed key silently drops
    /// unknown members and would defeat the strictness rule.
    fileprivate struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }

        init(_ string: String) { self.stringValue = string }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    private static let knownKeys: Set<String> = [
        "v", "senders", "max_age_min", "per_cli_hourly", "per_cli_daily",
        "cli_devices",
    ]

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: AnyKey.self)
        // Unknown field first: a policy the decider half-understands
        // must never be treated as wider than it is.
        for key in c.allKeys where !Self.knownKeys.contains(key.stringValue) {
            throw KeyrefWireError.invalidField(
                "policy_json: unknown field \"\(key.stringValue)\"")
        }
        guard let v = try? c.decode(Int.self, forKey: AnyKey("v")),
              v == Self.version else {
            throw KeyrefWireError.invalidField("policy_json v must be 1")
        }
        self.senders = try c.decodeIfPresent([String].self, forKey: AnyKey("senders")) ?? []
        self.maxAgeMin = try c.decodeIfPresent(Int64.self, forKey: AnyKey("max_age_min")) ?? 0
        self.perCLIHourly = try c.decodeIfPresent(Int64.self, forKey: AnyKey("per_cli_hourly")) ?? 0
        self.perCLIDaily = try c.decodeIfPresent(Int64.self, forKey: AnyKey("per_cli_daily")) ?? 0
        self.cliDevices = try c.decodeIfPresent([String].self, forKey: AnyKey("cli_devices")) ?? []
        try validate()
    }
}

// MARK: - helpers used by the decider's gates (design §14.8)

public extension KeyrefDelegationPolicy {
    /// Byte-exact sender match — never a substring or prefix match.
    func allowsSender(_ sender: String) -> Bool {
        senders.contains(sender)
    }

    /// Empty `cli_devices` means no restriction.
    func allowsCLI(_ deviceID: String) -> Bool {
        if cliDevices.isEmpty { return true }
        return cliDevices.contains(deviceID)
    }
}
