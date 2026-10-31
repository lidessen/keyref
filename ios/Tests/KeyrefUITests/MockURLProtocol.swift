// Mock URLProtocol for APIClient/PairingClient/SyncEngine tests: records
// requests and serves canned responses.
import Foundation

final // Shared copy of the KeyrefCoreTests mock (per-target modules cannot
// see each other). Renamed to avoid a duplicate symbol if both targets
// are linked into one test run.
class UITestMockURLProtocol: URLProtocol {
    struct Call {
        var request: URLRequest
        var body: Data
    }

    /// The route handler: returns (status, body) for a request.
    nonisolated(unsafe) static var handler: (@Sendable (URLRequest, Data) throws -> (Int, Data))?
    nonisolated(unsafe) static var calls: [Call] = []
    private static let lock = NSLock()

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        handler = nil
        calls = []
    }

    static func recorded() -> [Call] {
        lock.lock(); defer { lock.unlock() }
        return calls
    }

    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [UITestMockURLProtocol.self]
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
        Self.lock.lock()
        Self.calls.append(Call(request: request, body: body))
        let handler = Self.handler
        Self.lock.unlock()

        let (status, data): (Int, Data)
        do {
            (status, data) = try handler?(request, body) ?? (404, Data("{\"error\":\"not_found\"}".utf8))
        } catch {
            // A throwing handler means the test's server-side verification
            // failed — surface it loudly instead of a plausible status.
            (status, data) = (599, Data("handler threw: \(error)".utf8))
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: status,
                                       httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
