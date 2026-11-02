// Wire shapes of `PUT` / `GET /v1/delegation` (docs/protocol.md §6.31)
// and the decoded state the UI renders.
//
// The server only verifies the signature and relays the bytes — it never
// parses the policy. `delegation_signed` is the §3.10 transcript and
// `signature` is the owner signing key over exactly those bytes, so a
// reader can "先验后用" without trusting the server (the server is not a
// trust anchor).
import Foundation

/// `PUT /v1/delegation` body. `delegationRevision` must strictly exceed
/// the value already stored or the server answers `409
/// revision_conflict`.
public struct DelegationPutRequest: Codable, Equatable, Sendable {
    public var delegationRevision: UInt64
    public var delegationSigned: Data
    public var signature: Data

    public init(delegationRevision: UInt64, delegationSigned: Data, signature: Data) {
        self.delegationRevision = delegationRevision
        self.delegationSigned = delegationSigned
        self.signature = signature
    }

    enum CodingKeys: String, CodingKey {
        case delegationRevision = "delegation_revision"
        case delegationSigned = "delegation_signed"
        case signature
    }
}

/// `GET /v1/delegation` body. With no delegation the server reports
/// revision 0 and empty blobs (the protocol spells them `null`; Go's
/// `Blob` marshals a nil slice as `""` — both decode to nil/empty here
/// and both mean "never installed").
public struct DelegationGetResponse: Codable, Equatable, Sendable {
    public var delegationRevision: UInt64
    public var delegationSigned: Data?
    public var signature: Data?

    public init(delegationRevision: UInt64, delegationSigned: Data? = nil,
                signature: Data? = nil) {
        self.delegationRevision = delegationRevision
        self.delegationSigned = delegationSigned
        self.signature = signature
    }

    enum CodingKeys: String, CodingKey {
        case delegationRevision = "delegation_revision"
        case delegationSigned = "delegation_signed"
        case signature
    }
}

/// The delegation as the owner-side UI holds it: the revision the server
/// has (the basis for the next PUT) and the policy that revision
/// carries.
public struct DelegationState: Equatable, Sendable {
    /// Server-side `delegation_revision`. The next PUT must be `+1` or
    /// larger (§6.31: strictly greater).
    public var revision: UInt64
    public var policy: KeyrefDelegationPolicy

    public init(revision: UInt64, policy: KeyrefDelegationPolicy) {
        self.revision = revision
        self.policy = policy
    }

    /// An installed policy that actually narrows something. Revision ≥ 1
    /// with an empty policy is a completed withdrawal (设计 §14.8:
    /// 撤回委托 = 签署新的空委托).
    public var isActive: Bool { !policy.isEmpty }
}
