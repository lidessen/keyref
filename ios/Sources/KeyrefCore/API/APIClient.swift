// HTTP client for the keyref sync API (docs/protocol.md §5–§6): one async
// method per endpoint, Bearer-token auth (§8.2), the §1.3 error-code →
// typed-error mapping, and the §1.2 request-body limits enforced before
// sending.
import Foundation

// MARK: - errors

public enum APIError: Error, Equatable {
    case invalidJSON
    case invalidField
    case unauthorized
    case powRequired(challenge: Data, expiresAt: Int64)
    case deleteChallengeRequired(challenge: Data, expiresAt: Int64)
    case forbidden
    case deviceRevoked
    case badSignature
    case vaultFrozen
    case notFound
    case revisionConflict
    case cursorStale
    case approvalNotPending
    case pairExpired
    case bodyTooLarge
    case rateLimited
    case quotaExceeded
    /// A status/code combination outside the §1.3 table.
    case unexpected(status: Int, code: String?)
    /// Transport or decoding failure.
    case transport(String)
    /// A locally enforced request-body limit was exceeded (§1.2).
    case requestBodyTooLarge(limit: Int)

    public static func from(code: String, status: Int, body: Data) -> APIError {
        switch code {
        case "invalid_json": return .invalidJSON
        case "invalid_field": return .invalidField
        case "unauthorized": return .unauthorized
        case "pow_required":
            if let ch = challenge(of: body) {
                return .powRequired(challenge: ch.challenge, expiresAt: ch.expiresAt)
            }
            return .unexpected(status: status, code: code)
        case "delete_challenge_required":
            if let ch = challenge(of: body) {
                return .deleteChallengeRequired(challenge: ch.challenge, expiresAt: ch.expiresAt)
            }
            return .unexpected(status: status, code: code)
        case "forbidden": return .forbidden
        case "device_revoked": return .deviceRevoked
        case "bad_signature": return .badSignature
        case "vault_frozen": return .vaultFrozen
        case "not_found": return .notFound
        case "revision_conflict": return .revisionConflict
        case "cursor_stale": return .cursorStale
        case "approval_not_pending": return .approvalNotPending
        case "pair_expired": return .pairExpired
        case "body_too_large": return .bodyTooLarge
        case "rate_limited": return .rateLimited
        case "quota_exceeded": return .quotaExceeded
        default: return .unexpected(status: status, code: code)
        }
    }

    private static func challenge(of body: Data) -> (challenge: Data, expiresAt: Int64)? {
        struct Ch: Decodable {
            let challenge: Data
            let expires_at: Int64
        }
        guard let ch = try? WireJSON.decoder.decode(Ch.self, from: body) else { return nil }
        return (ch.challenge, ch.expires_at)
    }
}

// MARK: - client

/// Async client for one server origin. `bearerToken` supplies the current
/// session token (nil when unauthenticated).
public struct APIClient: Sendable {
    /// §1.2 request-body limits (bytes).
    public enum Limits {
        public static let itemBody = 256 * 1024
        public static let auditBody = 4 * 1024
        public static let approvalBody = 8 * 1024
    }

    public let baseURL: URL
    public let session: URLSession
    public let bearerToken: @Sendable () -> String?

    public init(baseURL: URL, session: URLSession = .shared,
                bearerToken: @escaping @Sendable () -> String? = { nil }) {
        var base = baseURL
        if !base.path.hasSuffix("/v1") {
            base = base.appendingPathComponent("v1")
        }
        self.baseURL = base
        self.session = session
        self.bearerToken = bearerToken
    }

    // MARK: plumbing

    private enum Method: String {
        case get = "GET", post = "POST", put = "PUT", delete = "DELETE"
    }

    private func request(_ method: Method, _ path: String,
                         query: [URLQueryItem] = []) -> URLRequest? {
        var comps = URLComponents(url: baseURL.appendingPathComponent(path),
                                  resolvingAgainstBaseURL: false)
        if !query.isEmpty {
            comps?.queryItems = query
        }
        guard let url = comps?.url else { return nil }
        var req = URLRequest(url: url)
        req.httpMethod = method.rawValue
        if let token = bearerToken() {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        req.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        return req
    }

    /// Sends a JSON body, enforcing `limit` bytes before any network I/O.
    private func send<Body: Encodable>(_ method: Method, _ path: String,
                                       body: Body, limit: Int? = nil,
                                       query: [URLQueryItem] = []) async throws -> (Int, Data) {
        var encoded: Data
        do {
            encoded = try WireJSON.encoder.encode(body)
        } catch {
            throw APIError.transport("encode: \(error)")
        }
        if let limit, encoded.count > limit {
            throw APIError.requestBodyTooLarge(limit: limit)
        }
        guard var req = request(method, path, query: query) else {
            throw APIError.transport("bad url")
        }
        req.httpBody = encoded
        return try await perform(req)
    }

    private func sendEmpty(_ method: Method, _ path: String,
                           query: [URLQueryItem] = []) async throws -> (Int, Data) {
        guard let req = request(method, path, query: query) else {
            throw APIError.transport("bad url")
        }
        return try await perform(req)
    }

    private func get(_ path: String, query: [URLQueryItem] = []) async throws -> (Int, Data) {
        guard let req = request(.get, path, query: query) else {
            throw APIError.transport("bad url")
        }
        return try await perform(req)
    }

    private func perform(_ req: URLRequest) async throws -> (Int, Data) {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw APIError.transport("\(error)")
        }
        guard let http = response as? HTTPURLResponse else {
            throw APIError.transport("non-HTTP response")
        }
        return (http.statusCode, data)
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        guard !data.isEmpty else {
            throw APIError.transport("empty body")
        }
        do {
            return try WireJSON.decoder.decode(T.self, from: data)
        } catch {
            throw APIError.invalidJSON
        }
    }

    /// Accepts any of the given statuses, otherwise maps the error body.
    private func expect(_ statuses: Set<Int>, _ status: Int, _ data: Data) throws {
        guard !statuses.contains(status) else { return }
        struct ErrBody: Decodable { let error: String }
        let code = (try? WireJSON.decoder.decode(ErrBody.self, from: data))?.error
        throw code.map { APIError.from(code: $0, status: status, body: data) }
            ?? APIError.unexpected(status: status, code: nil)
    }

    // MARK: 5.1 vaults (§6.1)

    public func createVault(_ req: CreateVaultRequest) async throws -> CreateVaultResponse {
        let (status, data) = try await send(.post, "vaults", body: req)
        try expect([201], status, data)
        return try decode(CreateVaultResponse.self, data)
    }

    // MARK: 5.2 recovery materials (§6.2)

    public func getRecoveryMaterials(vaultID: String) async throws -> RecoveryMaterialsResponse {
        let (status, data) = try await get("vaults/\(vaultID)/recovery")
        try expect([200], status, data)
        return try decode(RecoveryMaterialsResponse.self, data)
    }

    // MARK: 5.3 recovery takeover (§6.3) — responds with the new owner session

    public func submitRecoveryDirectory(_ req: RecoveryDirectoryRequest) async throws -> SessionResponse {
        let (status, data) = try await send(.post, "recovery/directory", body: req)
        try expect([200], status, data)
        return try decode(SessionResponse.self, data)
    }

    // MARK: 5.4 replace recovery material (§6.4)

    public func putVaultRecovery(_ req: PutVaultRecoveryRequest) async throws {
        let (status, data) = try await send(.put, "vault/recovery", body: req)
        try expect([204], status, data)
    }

    // MARK: 5.5 delete vault, two steps (§6.5)

    /// Step one: no body → the challenge error carries the challenge.
    public func requestVaultDeleteChallenge(vaultID: String) async throws -> (challenge: Data, expiresAt: Int64) {
        let (status, data) = try await sendEmpty(.delete, "vaults/\(vaultID)")
        switch APIError.from(code: "delete_challenge_required", status: status, body: data) {
        case .deleteChallengeRequired(let ch, let exp): return (ch, exp)
        default: break
        }
        try expect([401], status, data)
        throw APIError.unexpected(status: status, code: nil)
    }

    /// Step two: signed challenge → 204, server cascades all rows.
    public func deleteVault(vaultID: String, challenge: Data, signature: Data) async throws {
        let (status, data) = try await send(.delete, "vaults/\(vaultID)",
                                            body: DeleteVaultRequest(challenge: challenge, signature: signature))
        try expect([204], status, data)
    }

    // MARK: 5.7 session two-step (§6.7)

    public func requestSessionChallenge(deviceID: String) async throws -> SessionChallengeResponse {
        let (status, data) = try await send(.post, "session", body: SessionRequest(deviceID: deviceID))
        try expect([200], status, data)
        return try decode(SessionChallengeResponse.self, data)
    }

    public func completeSession(deviceID: String, challenge: Data, signature: Data) async throws -> SessionResponse {
        let (status, data) = try await send(.post, "session",
                                            body: SessionRequest(deviceID: deviceID, challenge: challenge, signature: signature))
        try expect([200], status, data)
        return try decode(SessionResponse.self, data)
    }

    // MARK: 5.8 sync (§8.1)

    public func sync(cursor: Int64) async throws -> SyncResponse {
        let (status, data) = try await get("sync", query: [URLQueryItem(name: "cursor", value: String(cursor))])
        try expect([200], status, data)
        return try decode(SyncResponse.self, data)
    }

    // MARK: 5.9 items (§6.9)

    public func getItem(itemID: String) async throws -> ItemData {
        let (status, data) = try await get("items/\(itemID)")
        try expect([200], status, data)
        return try decode(ItemData.self, data)
    }

    // MARK: 5.10 put item (§6.10)

    public func putItem(itemID: String, _ req: PutItemRequest) async throws -> PutItemResponse {
        let (status, data) = try await send(.put, "items/\(itemID)", body: req, limit: Limits.itemBody)
        try expect([200], status, data)
        return try decode(PutItemResponse.self, data)
    }

    // MARK: 5.11 tombstone (§6.11)

    public func deleteItem(itemID: String, _ req: DeleteItemRequest) async throws {
        let (status, data) = try await send(.delete, "items/\(itemID)", body: req)
        try expect([204], status, data)
    }

    // MARK: 5.12 grants (§6.12)

    public func putGrants(_ req: PutGrantsRequest) async throws -> PutGrantsResponse {
        let (status, data) = try await send(.put, "grants", body: req)
        try expect([200], status, data)
        return try decode(PutGrantsResponse.self, data)
    }

    // MARK: 5.13 delete grant (§6.13)

    public func deleteGrant(_ req: DeleteGrantRequest) async throws {
        let (status, data) = try await send(.delete, "grants", body: req)
        try expect([204], status, data)
    }

    // MARK: 5.14 grants/self reconciliation (§6.14)

    public func grantsSelf() async throws -> GrantsSelfResponse {
        let (status, data) = try await get("grants/self")
        try expect([200], status, data)
        return try decode(GrantsSelfResponse.self, data)
    }

    // MARK: 5.15 directory (§6.15)

    public func putDirectory(_ req: PutDirectoryRequest) async throws -> PutDirectoryResponse {
        let (status, data) = try await send(.put, "directory", body: req)
        try expect([200], status, data)
        return try decode(PutDirectoryResponse.self, data)
    }

    // MARK: 5.16 pair register (§6.16)

    public func pairRegister(_ req: PairRegisterRequest) async throws -> PairRegisterResponse {
        let (status, data) = try await send(.post, "pair/register", body: req)
        try expect([201], status, data)
        return try decode(PairRegisterResponse.self, data)
    }

    // MARK: 5.17 pair complete (§6.17)

    public func pairComplete(_ req: PairCompleteRequest) async throws {
        let (status, data) = try await send(.post, "pair/complete", body: req)
        try expect([204], status, data)
    }

    // MARK: 5.18 pair status (§6.18)

    public func pairStatus(nonce: String) async throws -> PairStatusResponse {
        let (status, data) = try await get("pair/status", query: [URLQueryItem(name: "nonce", value: nonce)])
        try expect([200], status, data)
        return try decode(PairStatusResponse.self, data)
    }

    // MARK: 5.19 approvals (§6.19)

    public func createApproval(_ req: CreateApprovalRequest) async throws -> CreateApprovalResponse {
        let (status, data) = try await send(.post, "approvals", body: req, limit: Limits.approvalBody)
        try expect([201], status, data)
        return try decode(CreateApprovalResponse.self, data)
    }

    // MARK: 5.20 pending approvals (§6.20)

    public func listApprovals(status: String = "pending") async throws -> ApprovalListResponse {
        let (status, data) = try await get("approvals", query: [URLQueryItem(name: "status", value: status)])
        try expect([200], status, data)
        return try decode(ApprovalListResponse.self, data)
    }

    // MARK: 5.21 approval decision (§6.21)

    public func submitApprovalDecision(approvalID: String, _ req: ApprovalDecisionRequest) async throws {
        let (status, data) = try await send(.post, "approvals/\(approvalID)/decision", body: req)
        try expect([204], status, data)
    }

    // MARK: 5.22 approval poll (§6.22)

    public func getApproval(approvalID: String) async throws -> ApprovalStatusResponse {
        let (status, data) = try await get("approvals/\(approvalID)")
        try expect([200], status, data)
        return try decode(ApprovalStatusResponse.self, data)
    }

    // MARK: 5.23 audit (§6.23)

    public func postAudit(_ req: AuditEnvelopeRequest) async throws -> AuditEnvelopeResponse {
        let (status, data) = try await send(.post, "audit", body: req, limit: Limits.auditBody)
        try expect([201], status, data)
        return try decode(AuditEnvelopeResponse.self, data)
    }

    // MARK: 5.24 audit page (§6.24)

    public func getAuditPage(cursor: Int64) async throws -> AuditPageResponse {
        let (status, data) = try await get("audit", query: [URLQueryItem(name: "cursor", value: String(cursor))])
        try expect([200], status, data)
        return try decode(AuditPageResponse.self, data)
    }

    // MARK: 5.25 account (§6.25)

    public func account() async throws -> AccountResponse {
        let (status, data) = try await get("account")
        try expect([200], status, data)
        return try decode(AccountResponse.self, data)
    }

    // MARK: 5.28–5.31 messages (§6.28–§6.31, design v0.8 §14)

    /// `GET /v1/messages?since=` — unexpired messages for this device,
    /// oldest first, `since` being the server `created_at` cursor (§6.29).
    public func listMessages(since: Int64 = 0) async throws -> MessageListResponse {
        let (status, data) = try await get("messages", query: [
            URLQueryItem(name: "since", value: String(since)),
        ])
        try expect([200], status, data)
        return try decode(MessageListResponse.self, data)
    }

    /// `DELETE /v1/messages/:id` — the inbox's manual delete (§6.31).
    public func deleteMessage(messageID: String) async throws {
        let (status, data) = try await sendEmpty(.delete, "messages/\(messageID)")
        try expect([204], status, data)
    }

    /// `PUT /v1/messages/:id/wraps` — re-wrap a message key for a decider
    /// that paired after the message landed (§6.30, D17).
    public func putMessageWraps(messageID: String, _ req: MessageWrapsRequest) async throws {
        let (status, data) = try await send(.put, "messages/\(messageID)/wraps", body: req)
        try expect([204], status, data)
    }

    // MARK: 5.32 delegation (§6.31, design v0.8 §14.8)

    /// `GET /v1/delegation` — the owner-signed policy any active device
    /// may read. Revision 0 with empty blobs means "never installed".
    public func getDelegation() async throws -> DelegationGetResponse {
        let (status, data) = try await get("delegation")
        try expect([200], status, data)
        return try decode(DelegationGetResponse.self, data)
    }

    /// `PUT /v1/delegation` — installs the next revision. The server
    /// requires `delegation_revision` strictly greater than the stored
    /// one and verifies the owner signature over the transcript.
    public func putDelegation(_ req: DelegationPutRequest) async throws {
        let (status, data) = try await send(.put, "delegation", body: req)
        try expect([204], status, data)
    }

    // MARK: 5.26 billing (§6.26)

    public func postBillingApple(_ req: BillingAppleRequest) async throws -> BillingAppleResponse {
        let (status, data) = try await send(.post, "billing/apple", body: req)
        try expect([200], status, data)
        return try decode(BillingAppleResponse.self, data)
    }
}
