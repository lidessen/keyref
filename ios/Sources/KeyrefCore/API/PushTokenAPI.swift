// APNs push-token registration (Phase 2, design §13): after unlock the
// owner device uploads its APNs token so the server can deliver approval
// pushes. Contract: PUT /v1/devices/push-token, body
// {"token":"<hex>","env":"sandbox|production"}, 204 on success. Kept in its
// own file as an APIClient extension so the existing API/APIClient.swift
// stays byte-for-byte untouched.
import Foundation

/// Body of `PUT /v1/devices/push-token` (§13). `token` is the hex-encoded
/// APNs device token; `env` is "sandbox" (development builds) or
/// "production" (App Store builds).
public struct PushTokenRequest: Codable, Equatable, Sendable {
    public var token: String
    public var env: String

    enum CodingKeys: String, CodingKey {
        case token
        case env
    }

    public init(token: String, env: String) {
        self.token = token
        self.env = env
    }
}

public extension APIClient {
    /// `PUT /v1/devices/push-token` (§13). 204 = the server accepted the
    /// token; every other status maps through the §1.3 error-code table
    /// (e.g. 401 unauthorized when the session expired — the caller treats
    /// it as "retry on the next registration").
    func putPushToken(token: String, env: String) async throws {
        let body: Data
        do {
            body = try WireJSON.encoder.encode(PushTokenRequest(token: token, env: env))
        } catch {
            throw APIError.transport("encode: \(error)")
        }
        let url = baseURL.appendingPathComponent("devices/push-token")
        var req = URLRequest(url: url)
        req.httpMethod = "PUT"
        if let bearer = bearerToken() {
            req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        }
        req.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        req.httpBody = body
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
        guard http.statusCode == 204 else {
            struct ErrBody: Decodable { let error: String }
            let code = (try? WireJSON.decoder.decode(ErrBody.self, from: data))?.error
            throw code.map { APIError.from(code: $0, status: http.statusCode, body: data) }
                ?? APIError.unexpected(status: http.statusCode, code: nil)
        }
    }
}
