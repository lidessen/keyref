// putPushToken tests (Phase 2, §13) over MockURLProtocol: the request line
// (PUT /v1/devices/push-token), the bearer + JSON body contract
// {"env":"...","token":"<hex>"}, and the §1.3 error mapping / 204-only
// success. The registration state machine lives in KeyrefUITests.
import XCTest

@testable import KeyrefCore

final class PushTokenAPITests: XCTestCase {
    override func tearDown() {
        MockURLProtocol.reset()
    }

    private func makeAPI(token: String? = nil) -> APIClient {
        APIClient(baseURL: URL(string: "https://sync.example")!,
                  session: MockURLProtocol.makeSession(),
                  bearerToken: { token })
    }

    func testPutPushTokenRequestLineBodyAndHeaders() async throws {
        MockURLProtocol.handler = { _, _ in (204, Data()) }
        try await makeAPI(token: "sess-abc").putPushToken(token: "aabbccdd00ff", env: "sandbox")
        let calls = MockURLProtocol.recorded()
        XCTAssertEqual(calls.count, 1)
        XCTAssertEqual(calls[0].request.httpMethod, "PUT")
        XCTAssertEqual(calls[0].request.url?.absoluteString,
                       "https://sync.example/v1/devices/push-token")
        XCTAssertEqual(calls[0].request.value(forHTTPHeaderField: "Authorization"), "Bearer sess-abc")
        XCTAssertEqual(calls[0].request.value(forHTTPHeaderField: "Content-Type"),
                       "application/json; charset=utf-8")
        // 契约 body：{"env":"sandbox","token":"aabbccdd00ff"}（WireJSON sortedKeys）。
        let body = String(decoding: calls[0].body, as: UTF8.self)
        XCTAssertEqual(body, "{\"env\":\"sandbox\",\"token\":\"aabbccdd00ff\"}")
        let decoded = try WireJSON.decoder.decode(PushTokenRequest.self, from: calls[0].body)
        XCTAssertEqual(decoded, PushTokenRequest(token: "aabbccdd00ff", env: "sandbox"))
    }

    func testPutPushTokenCarriesProductionEnv() async throws {
        MockURLProtocol.handler = { _, _ in (204, Data()) }
        try await makeAPI(token: "t").putPushToken(token: "feed", env: "production")
        let calls = MockURLProtocol.recorded()
        XCTAssertEqual(calls.count, 1)
        let decoded = try WireJSON.decoder.decode(PushTokenRequest.self, from: calls[0].body)
        XCTAssertEqual(decoded.token, "feed")
        XCTAssertEqual(decoded.env, "production")
    }

    func testPutPushTokenBearerOmittedWithoutToken() async throws {
        MockURLProtocol.handler = { _, _ in (204, Data()) }
        try await makeAPI().putPushToken(token: "aabb", env: "sandbox")
        let calls = MockURLProtocol.recorded()
        XCTAssertEqual(calls.count, 1)
        XCTAssertNil(calls[0].request.value(forHTTPHeaderField: "Authorization"))
    }

    func testPutPushTokenMapsErrorCodes() async throws {
        for (status, code, expected) in [
            (401, "unauthorized", APIError.unauthorized),
            (403, "device_revoked", APIError.deviceRevoked),
            (429, "rate_limited", APIError.rateLimited),
        ] {
            MockURLProtocol.handler = { _, _ in (status, Data("{\"error\":\"\(code)\"}".utf8)) }
            do {
                try await makeAPI(token: "t").putPushToken(token: "aabb", env: "sandbox")
                XCTFail("\(code) should have thrown")
            } catch let e as APIError {
                XCTAssertEqual(e, expected, code)
            }
        }
    }

    func testPutPushTokenAcceptsOnly204() async throws {
        MockURLProtocol.handler = { _, _ in (200, Data()) }
        do {
            try await makeAPI(token: "t").putPushToken(token: "aabb", env: "sandbox")
            XCTFail("200 should have thrown")
        } catch let e as APIError {
            guard case .unexpected(let status, _) = e else { return XCTFail("\(e)") }
            XCTAssertEqual(status, 200)
        }
    }
}
