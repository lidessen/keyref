// The §3.10 delegation transcript (docs/protocol.md §3.10, design v0.8
// §14.8):
//
//     "KEYREF1" NUL "delegation" NUL vault_id(hex) NUL
//     u64be(delegation_revision) NUL policy_json(utf-8)
//
// The policy JSON is plaintext by design: the decider must read it, the
// server only verifies the signature (the one new plaintext surface the
// feature adds, recorded in design §6.4).
//
// Parsing follows the repo's §1.5 rule — rebuild-and-compare, never a
// naive split. The parse is positional, not split-based: the revision is
// fixed-width u64be and its zero bytes would poison any NUL-counting
// splitter. The transcript carries no binary fields beyond that, so a
// tampered byte shows up as a rebuild mismatch or an invalid field.
import Foundation

public struct KeyrefDelegationTranscript: Equatable, Sendable {
    public var vaultID: String
    public var delegationRevision: UInt64
    /// `policy_json` exactly as it will be signed — the bytes travel
    /// verbatim, they are not re-serialized by the verifier.
    public var policyJSON: String

    public init(vaultID: String, delegationRevision: UInt64, policyJSON: String) {
        self.vaultID = vaultID
        self.delegationRevision = delegationRevision
        self.policyJSON = policyJSON
    }

    /// Protocol cap on `policy_json` (Go: 1..16384 bytes).
    public static let policyMaxBytes = 16 << 10

    // MARK: assembly

    public func buildBytes() throws -> Data {
        guard KeyrefEncoding.isValidID(vaultID) else {
            throw KeyrefWireError.invalidField(
                "vault_id must be 32 lowercase hex characters")
        }
        // Swift strings are always well-formed Unicode scalars, so the
        // UTF-8 validity half of Go's check is vacuous here; the byte
        // bounds are not.
        let policy = Data(policyJSON.utf8)
        guard !policy.isEmpty, policy.count <= Self.policyMaxBytes else {
            throw KeyrefWireError.invalidField(
                "policy_json must be 1..\(Self.policyMaxBytes) bytes")
        }
        var b = Data()
        b.append(contentsOf: transcriptPrefix.utf8)
        b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: "delegation".utf8)
        b.append(KeyrefEncoding.fieldSeparator)
        b.append(contentsOf: vaultID.utf8)
        b.append(KeyrefEncoding.fieldSeparator)
        KeyrefEncoding.appendU64BE(delegationRevision, to: &b)
        b.append(KeyrefEncoding.fieldSeparator)
        b.append(policy)
        return b
    }

    // MARK: verification-side parse

    private static let prefix: [UInt8] = Array(
        "\(transcriptPrefix)\u{00}delegation\u{00}".utf8)

    /// Rebuilds the structured form of a signed delegation transcript and
    /// verifies it round-trips byte-for-byte. `wantVaultID` is the vault
    /// the caller already trusts — a transcript naming another vault is
    /// rejected even when it is otherwise well-formed.
    public static func parse(_ signed: Data, wantVaultID: String) throws -> KeyrefDelegationTranscript {
        let bytes = [UInt8](signed)
        guard bytes.count >= prefix.count + 1,
              Array(bytes[0..<prefix.count]) == prefix else {
            throw KeyrefWireError.invalidField("malformed delegation transcript")
        }
        var p = prefix.count
        guard let nul = bytes[p...].firstIndex(of: KeyrefEncoding.fieldSeparator) else {
            throw KeyrefWireError.invalidField("malformed delegation transcript")
        }
        let vaultID = String(decoding: bytes[p..<nul], as: UTF8.self)
        p = nul + 1
        // 8 bytes of u64be revision, then the separator that precedes
        // policy_json. Anything shorter cannot be a well-formed
        // transcript.
        guard bytes.count >= p + 8 + 1,
              bytes[p + 8] == KeyrefEncoding.fieldSeparator else {
            throw KeyrefWireError.invalidField("malformed delegation transcript")
        }
        let revision = try KeyrefEncoding.readU64BE(Data(bytes), offset: p)
        let policy = String(decoding: bytes[(p + 9)...], as: UTF8.self)
        guard vaultID == wantVaultID else {
            throw KeyrefWireError.invalidField("malformed delegation transcript")
        }
        let parsed = KeyrefDelegationTranscript(vaultID: vaultID,
                                                delegationRevision: revision,
                                                policyJSON: policy)
        // §1.5: rebuild-and-compare. A tampered byte — including one
        // inside the fixed-width revision — fails here rather than
        // silently splitting.
        guard try parsed.buildBytes() == signed else {
            throw KeyrefWireError.invalidField("malformed delegation transcript")
        }
        return parsed
    }
}
