// NEW FILE (v0.7, design §9.4 转移即分叉): the second-iPhone handoff
// payload extended with the 仅本机 snapshot blob. The base `JoinHandoff`
// stays untouched; this envelope adds an OPTIONAL `snap` query field to the
// same `keyref://handoff?…` URL carrying the owner-signed snapshot file
// (SnapshotCodec format, §6.7). `JoinHandoff.parse` ignores unknown query
// fields, so payloads written by this envelope still parse on pre-0.7
// receivers and vice versa.
//
// 转移即分叉：the snapshot is a one-time copy — after the transfer both
// phones edit their own 仅本机 entries independently and nothing ever
// re-syncs them (single-device artifact, §6.6 双 owner row).
import Foundation

public struct JoinHandoffEnvelope: Equatable, Sendable {
    public var handoff: JoinHandoff
    /// Owner-signed snapshot file of the old phone's 仅本机 entries (§6.7
    /// format), or nil when the old phone had none.
    public var snapshot: Data?

    public init(handoff: JoinHandoff, snapshot: Data?) {
        self.handoff = handoff
        self.snapshot = snapshot
    }

    public enum ParseError: Error, Equatable {
        case badHandoff
        case badField(String)
    }

    public static func parse(_ payload: String) throws -> JoinHandoffEnvelope {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let handoff = try? JoinHandoff.parse(trimmed) else {
            throw ParseError.badHandoff
        }
        var snapshot: Data?
        if let url = URL(string: trimmed),
           let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let raw = (comps.queryItems ?? []).first(where: { $0.name == "snap" })?.value,
           !raw.isEmpty {
            guard let data = Data(base64Encoded: raw), !data.isEmpty else {
                throw ParseError.badField("snap")
            }
            snapshot = data
        }
        return JoinHandoffEnvelope(handoff: handoff, snapshot: snapshot)
    }

    public func payload() -> String {
        var out = handoff.payload()
        if let snapshot, !snapshot.isEmpty {
            let enc = { (s: String) -> String in
                var allowed = CharacterSet.alphanumerics
                allowed.insert(charactersIn: "-._~")
                return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
            }
            out += "&snap=" + enc(KeyrefEncoding.base64Encode(snapshot))
        }
        return out
    }
}

// MARK: - §8.4 定期轮换 policy

/// Pure decision helpers for the periodic rotation ritual (§8.4 定期轮换，
/// v0.7): manual "立即轮换全部同步条目" plus an optional 90-day cycle that
/// defaults OFF. It fights key-age fatigue, not expiry — the server never
/// invalidates ciphertexts on a timer (§10.5 第 8 条不变).
public enum RotationPolicy {
    public static let defaultPeriodDays = 90

    /// Whether a rotation is due: the cycle must be enabled and the last
    /// rotation (if any) older than the period. Never rotated = not due
    /// until the period passes from the moment the cycle was enabled.
    public static func due(lastRotationAtMillis: Int64?, enabledAtMillis: Int64?,
                           nowMillis: Int64, periodDays: Int = defaultPeriodDays) -> Bool {
        let period = Int64(periodDays) * 86_400_000
        guard nowMillis > 0 else { return false }
        if let last = lastRotationAtMillis, last > 0 {
            return nowMillis - last >= period
        }
        guard let enabled = enabledAtMillis, enabled > 0 else { return false }
        return nowMillis - enabled >= period
    }
}
