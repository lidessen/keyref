// Minimal in-process keyref-server double for LiveBackend flow tests
// (second-iPhone join §9.4, approvals §8.3): vault creation, the two-step
// session, item puts, directory puts (device rows follow the directory, as
// server/internal/api/directory.go does), sync bootstrap, grants/self and
// the approval endpoints. Client-side signatures are NOT re-verified here —
// the crypto under test is the client's, covered by the Core tests; the
// revision rules ARE enforced. Sync `data` is transported as an embedded
// JSON object, matching protocol §8.1 and the real Go server.
import Foundation
@testable import KeyrefCore

/// URLProtocol double for the KeyrefUI test target (the Core target has its
/// own MockURLProtocol; two test bundles are separate modules). Routes every
/// request through the shared static handler.
final class UITestURLProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: (@Sendable (URLRequest, Data) throws -> (Int, Data))?
    nonisolated(unsafe) static var calls: [(method: String, url: String, status: Int)] = []

    static func reset() {
        handler = nil
        calls = []
    }

    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [UITestURLProtocol.self]
        return URLSession(configuration: config)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var body = Data()
        if let stream = request.httpBodyStream {
            stream.open()
            defer { stream.close() }
            let bufSize = 16384
            let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
            defer { buf.deallocate() }
            while stream.hasBytesAvailable {
                let n = stream.read(buf, maxLength: bufSize)
                if n <= 0 { break }
                body.append(buf, count: n)
            }
        } else {
            body = request.httpBody ?? Data()
        }
        let (status, data): (Int, Data)
        do {
            (status, data) = try Self.handler?(request, body) ?? (404, Data("{\"error\":\"not_found\"}".utf8))
        } catch {
            (status, data) = (599, Data("handler threw: \(error)".utf8))
        }
        Self.calls.append((request.httpMethod ?? "?", request.url?.absoluteString ?? "?", status))
        let response = HTTPURLResponse(url: request.url!, statusCode: status,
                                       httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

final class FakeKeyrefServer: @unchecked Sendable {
    struct Device {
        var kind: String
        var status: String
        var hpkeKEM: String
        var hpkePublicKey: Data
        var signAlg: String
        var signPublicKey: Data
        var label: String
    }

    private let lock = NSLock()
    private var vaultID: String?
    private var directoryRevision: UInt64 = 0
    private var directorySigned = Data()
    private var directorySignature = Data()
    private var devices: [String: Device] = [:]
    private var items: [String: ItemData] = [:]
    private var seq: Int64 = 0
    private var challenges: [String: String] = [:]  // challenge b64 → deviceID
    private var tokens: [String: String] = [:]      // token → deviceID
    var pendingApprovals: [PendingApproval] = []
    var decisions: [String: ApprovalDecisionRequest] = [:]

    var currentDirectoryRevision: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return directoryRevision
    }

    func device(_ id: String) -> Device? {
        lock.lock(); defer { lock.unlock() }
        return devices[id]
    }

    func item(_ id: String) -> ItemData? {
        lock.lock(); defer { lock.unlock() }
        return items[id]
    }

    func decision(for approvalID: String) -> ApprovalDecisionRequest? {
        lock.lock(); defer { lock.unlock() }
        return decisions[approvalID]
    }

    // MARK: handler

    lazy var handler: @Sendable (URLRequest, Data) throws -> (Int, Data) = { [weak self] request, body in
        guard let self else { return (500, Data()) }
        return self.route(request, body)
    }

    private func route(_ request: URLRequest, _ body: Data) -> (Int, Data) {
        lock.lock(); defer { lock.unlock() }
        let path = request.url?.path ?? ""
        let method = request.httpMethod ?? ""

        switch (method, path) {
        case ("POST", "/v1/vaults"):
            return createVault(body)
        case ("POST", "/v1/session"):
            return session(body)
        case ("PUT", let p) where p.hasPrefix("/v1/items/"):
            return putItem(String(p.dropFirst("/v1/items/".count)), body)
        case ("PUT", "/v1/directory"):
            return putDirectory(body)
        case ("GET", "/v1/sync"):
            return sync(request)
        case ("GET", "/v1/grants/self"):
            let resp = GrantsSelfResponse(grants: [], grantsDigest: Data(),
                                          directoryRevision: directoryRevision)
            return (200, tryJSON(resp))
        case ("GET", "/v1/approvals"):
            return (200, tryJSON(ApprovalListResponse.make(approvals: pendingApprovals)))
        case ("POST", let p) where p.hasSuffix("/decision"):
            let approvalID = String(p.dropFirst("/v1/approvals/".count).dropLast("/decision".count))
            return decide(approvalID, body)
        default:
            return (404, Data("{\"error\":\"not_found\"}".utf8))
        }
    }

    private func createVault(_ body: Data) -> (Int, Data) {
        guard let req = try? WireJSON.decoder.decode(CreateVaultRequest.self, from: body) else {
            return (400, err("invalid_field"))
        }
        vaultID = req.vaultID
        directoryRevision = req.directoryRevision
        directorySigned = req.directorySigned
        directorySignature = req.signature
        devices[req.device.deviceID] = Device(kind: req.device.kind, status: DeviceStatus.active,
                                              hpkeKEM: req.device.hpkeKEM,
                                              hpkePublicKey: req.device.hpkePublicKey,
                                              signAlg: req.device.signAlg,
                                              signPublicKey: req.device.signPublicKey,
                                              label: req.device.label)
        seq += 1
        return (201, tryJSON(CreateVaultResponse(vaultID: req.vaultID)))
    }

    private func session(_ body: Data) -> (Int, Data) {
        guard let req = try? WireJSON.decoder.decode(SessionRequest.self, from: body) else {
            return (401, err("unauthorized"))
        }
        guard devices[req.deviceID] != nil else {
            return (401, err("unauthorized"))
        }
        let deviceID = req.deviceID
        if req.challenge == nil {
            // §6.7：挑战是 32 字节随机数，60 秒有效、单次。
            var raw = Data(count: 32)
            _ = raw.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
            let b64 = raw.base64EncodedString()
            challenges[b64] = deviceID
            return (200, tryJSON(SessionChallengeResponse(challenge: raw,
                                                          expiresAt: 1790000000000)))
        }
        let challengeB64 = req.challenge!.base64EncodedString()
        guard challenges[challengeB64] == deviceID else {
            return (401, err("unauthorized"))
        }
        let token = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let hex = token.map { String(format: "%02x", $0) }.joined()
        tokens[hex] = deviceID
        return (200, tryJSON(SessionResponse(token: hex, expiresAt: 1790000000000,
                                             origin: "https://fake.test",
                                             plan: "unlimited", limits: nil)))
    }

    private func authenticatedDevice(_ request: URLRequest) -> String? {
        guard let header = request.value(forHTTPHeaderField: "Authorization"),
              header.hasPrefix("Bearer ") else { return nil }
        return tokens[String(header.dropFirst("Bearer ".count))]
    }

    private func putItem(_ itemID: String, _ body: Data) -> (Int, Data) {
        guard let req = try? WireJSON.decoder.decode(PutItemRequest.self, from: body) else {
            return (400, err("invalid_field"))
        }
        if let old = items[itemID], req.revision <= old.revision {
            return (409, err("revision_conflict"))
        }
        let row = ItemData.make(vaultID: vaultID ?? "", itemID: itemID,
                                revision: req.revision, tombstone: req.tombstone,
                                metaCiphertext: req.metaCiphertext,
                                secretCiphertext: req.secretCiphertext,
                                vaultWrappedMetaKey: req.vaultWrappedMetaKey,
                                vaultWrappedItemKey: req.vaultWrappedItemKey,
                                writerDeviceID: req.writerDeviceID,
                                signature: req.signature, updatedAt: 1790000000000)
        items[itemID] = row
        seq += 1
        return (200, tryJSON(PutItemResponse(revision: req.revision, updatedAt: 1790000000000)))
    }

    private func putDirectory(_ body: Data) -> (Int, Data) {
        guard let req = try? WireJSON.decoder.decode(PutDirectoryRequest.self, from: body) else {
            return (400, err("invalid_field"))
        }
        guard req.directoryRevision > directoryRevision else {
            return (409, err("revision_conflict"))
        }
        // 设备行随目录落库（server/api/directory.go 的行为）。结构化解析失败
        // 视为 invalid_field —— 与服务器一致。
        guard let parsed = try? VaultFlows.parseVerifiedDevices(req.directorySigned,
                                                                vaultID: vaultID ?? "") else {
            return (400, err("invalid_field"))
        }
        for d in parsed {
            devices[d.deviceID] = Device(kind: d.kind, status: d.status,
                                         hpkeKEM: d.hpkeKEM, hpkePublicKey: d.hpkePublicKey,
                                         signAlg: d.signAlg, signPublicKey: d.signPublicKey,
                                         label: devices[d.deviceID]?.label ?? "")
        }
        directoryRevision = req.directoryRevision
        directorySigned = req.directorySigned
        directorySignature = req.signature
        seq += 1
        return (200, tryJSON(PutDirectoryResponse(directoryRevision: req.directoryRevision)))
    }

    /// Bootstrap-style sync: the current visible state as one synthetic
    /// batch (cursor=0 semantics, §10.6) whenever the client asks from 0.
    private func sync(_ request: URLRequest) -> (Int, Data) {
        guard authenticatedDevice(request) != nil else {
            return (401, err("unauthorized"))
        }
        let cursorValue = request.url?.queryItems()["cursor"] ?? "0"
        let cursor = Int64(cursorValue) ?? 0
        guard cursor <= seq else {
            return (409, err("cursor_stale"))
        }
        var changes: [[String: Any]] = []
        if cursor == 0 {
            for (id, row) in items.sorted(by: { $0.key < $1.key }) {
                changes.append(changeDict(entity: "item", entityID: "item:\(id)",
                                          dataJSON: (try? WireJSON.encoder.encode(row)) ?? Data()))
            }
            let dir = DirectoryData.make(directoryRevision: directoryRevision,
                                         signed: directorySigned,
                                         signature: directorySignature)
            changes.append(changeDict(entity: "directory",
                                      entityID: "directory:\(vaultID ?? "")",
                                      dataJSON: (try? WireJSON.encoder.encode(dir)) ?? Data()))
        }
        let resp: [String: Any] = [
            "cursor": seq,
            "has_more": false,
            "changes": changes,
        ]
        return (200, (try? JSONSerialization.data(withJSONObject: resp)) ?? Data())
    }

    private func decide(_ approvalID: String, _ body: Data) -> (Int, Data) {
        guard let req = try? WireJSON.decoder.decode(ApprovalDecisionRequest.self, from: body) else {
            return (400, err("invalid_field"))
        }
        guard pendingApprovals.contains(where: { $0.approvalID == approvalID }) else {
            return (409, err("approval_not_pending"))
        }
        decisions[approvalID] = req
        pendingApprovals.removeAll { $0.approvalID == approvalID }
        return (204, Data())
    }

    // MARK: helpers

    private func changeDict(entity: String, entityID: String, dataJSON: Data) -> [String: Any] {
        // The protocol transports change.data as an embedded JSON object
        // (protocol §8.1), matching the real Go server.
        ["seq": Int(seq), "entity": entity, "entity_id": entityID,
         "created_at": 1,
         "data": (try? JSONSerialization.jsonObject(with: dataJSON)) ?? NSNull()]
    }

    private func err(_ code: String) -> Data {
        Data("{\"error\":\"\(code)\"}".utf8)
    }

    private func tryJSON<T: Encodable>(_ value: T) -> Data {
        (try? WireJSON.encoder.encode(value)) ?? Data()
    }
}

private extension String {
    func dropSuffix(_ suffix: String) -> String {
        hasSuffix(suffix) ? String(dropLast(suffix.count)) : self
    }
}

private extension URL {
    func queryItems() -> [String: String] {
        guard let comps = URLComponents(url: self, resolvingAgainstBaseURL: false) else { return [:] }
        var out: [String: String] = [:]
        for item in comps.queryItems ?? [] {
            out[item.name] = item.value ?? ""
        }
        return out
    }
}
