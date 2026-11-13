// Real cross-language integration: a real keyref-server process driven by
// the real iOS client code (LiveBackend + APIClient) — the link the audit
// found had never been exercised (every other iOS test uses
// MockURLProtocol or the in-memory backend).
//
// Flow: hosted-style create with PoW (KEYREF_ENFORCE_QUOTAS=1) → session →
// bootstrap sync → create item → CLI pair (register + complete) → assert
// the CLI landed in the SIGNED directory at revision+1 → CLI session and
// grants/self → revoke-with-rotation → assert one item key actually
// rotated and the revoked device can no longer mint a session.
//
// macOS-only: Process is unavailable on iOS. Skips cleanly when `go` or
// the server sources are absent (e.g. a CI image without Go).
#if os(macOS)
import CryptoKit
import Darwin
import Foundation
import XCTest

@testable import KeyrefCore
@testable import KeyrefUI

final class RealServerIntegrationTests: XCTestCase {
    private struct ServerFailure: Error, CustomStringConvertible {
        let description: String
    }

    private struct ServerHandle {
        let process: Process
        let baseURL: URL
        let dataDir: URL
        let logURL: URL
    }

    @MainActor
    func testIosClientAgainstRealServer() async throws {
        let handle = try await Self.startServer()
        defer { Self.stopServer(handle) }
        let baseURL = handle.baseURL

        // --- create a vault on a quota-enforcing (hosted-style) server:
        // the client must solve the PoW challenge and retry (protocol §10.1).
        let keyStore = InMemoryKeyStore()
        let stateStore = UIStateStore()
        let backend = LiveBackend(keyStore: keyStore, stateStore: stateStore,
                                  origin: baseURL, urlSession: .shared)
        let draft = try await backend.prepareCreation(label: "integration-iphone")
        do {
            try await backend.uploadCreatedVault(draft)
        } catch {
            XCTFail("create vault against real server failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        XCTAssertTrue(backend.hasVault)
        let vaultID = try XCTUnwrap(backend.vaultID)

        // --- create one item through the normal client path.
        let draftItem = ItemDraft(ref: "openai-prod", name: "OpenAI production",
                                  itemDescription: "", type: "api_key",
                                  value: "sk-live-integration-secret",
                                  policy: ItemPolicy(), injectable: true)
        do {
            try await backend.createItem(draftItem)
        } catch {
            XCTFail("create item failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        let row = try XCTUnwrap(stateStore.allItems().first)
        XCTAssertEqual(row.revision, 1)

        // --- simulate the CLI side of pairing: register a fresh CLI
        // identity (X25519 HPKE + Ed25519) and let the owner complete it.
        let cliHPKE = Curve25519.KeyAgreement.PrivateKey()
        let cliSigner = try Ed25519Signer()
        let nonceData = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let ownerAPI = backend.api
        let pairing = PairingClient(api: ownerAPI)
        do {
            _ = try await pairing.register(nonce: nonceData, proposedName: "build-bot",
                                           signer: cliSigner, hpkeKEM: KEMName.x25519,
                                           hpkePublicKey: cliHPKE.publicKey.rawRepresentation)
        } catch {
            XCTFail("pair/register failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        let offer = PairingOffer(hpkeKEM: KEMName.x25519,
                                 hpkePublicKey: cliHPKE.publicKey.rawRepresentation,
                                 signAlg: SignAlg.ed25519,
                                 signPublicKey: cliSigner.signPublicKey,
                                 nonce: KeyrefEncoding.hexEncode(nonceData),
                                 label: "build-bot", origin: baseURL,
                                 kind: DeviceKind.cli,
                                 confirmSecret: Data((0..<KeyrefSizes.pairConfirmKey)
                                     .map { _ in UInt8.random(in: 0...255) }))
        do {
            try await backend.completePairing(
                offer: offer, deviceLabel: "build-bot",
                selections: [GrantSelection(itemID: row.itemID, kind: "view"),
                             GrantSelection(itemID: row.itemID, kind: "use")])
        } catch {
            XCTFail("pairing failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }

        // --- the paired CLI must be visible through the signed directory
        // (this is the regression the pairing-directory fix addresses).
        let devices = await backend.loadDevices()
        let cliRow = try XCTUnwrap(devices.first { $0.kind == DeviceKind.cli },
                                   "paired CLI missing from the signed directory")
        XCTAssertEqual(cliRow.status, DeviceStatus.active)

        // The server's signed directory must be at revision 2 and contain
        // the CLI record, signed by the owner.
        let sync: SyncResponse
        do {
            sync = try await ownerAPI.sync(cursor: 0)
        } catch {
            XCTFail("owner sync failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        let directories: [DirectoryData] = sync.changes.compactMap { change in
            guard case .directory(let d)? = try? change.decodedData() else { return nil }
            return d
        }
        let latestDir = try XCTUnwrap(directories.last, "no directory in sync bootstrap")
        XCTAssertEqual(latestDir.directoryRevision, 2)
        try verifyOwnerSignature(transcript: latestDir.signed, signature: latestDir.signature,
                                 ownerSignPublicKey: try XCTUnwrap(backend.owner?.signPublicKey))
        let parsed = try VaultFlows.parseVerifiedDevices(latestDir.signed, vaultID: vaultID)
        XCTAssertTrue(parsed.contains { $0.deviceID == cliRow.id && $0.status == DeviceStatus.active },
                      "server directory lacks the CLI device")

        // --- the CLI can mint its own session and read its grants.
        let cliAPIBase = APIClient(baseURL: baseURL)
        let cliSession: SessionResponse
        do {
            cliSession = try await SessionClient(api: cliAPIBase)
                .start(deviceID: cliRow.id, signer: cliSigner)
        } catch {
            XCTFail("CLI session failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        let cliAPI = APIClient(baseURL: baseURL, bearerToken: { cliSession.token })
        let selfGrants: GrantsSelfResponse
        do {
            selfGrants = try await cliAPI.grantsSelf()
        } catch {
            XCTFail("CLI grants/self failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        XCTAssertEqual(selfGrants.grants.count, 2, "view + use grants must reach the CLI")

        // --- revoke with rotation: exactly the one use-grant item rotates,
        // the server row advances, and the ciphertext changes (§8.4).
        let before: ItemData
        do {
            before = try await ownerAPI.getItem(itemID: row.itemID)
        } catch {
            XCTFail("owner getItem failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        let summary: RevokeSummary
        do {
            summary = try await backend.revokeDevice(deviceID: cliRow.id, rotate: true) { _ in }
        } catch {
            XCTFail("revoke failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        XCTAssertEqual(summary.rotatedCount, 1, "revocation must rotate the item the CLI could use")
        let after = try await ownerAPI.getItem(itemID: row.itemID)
        XCTAssertEqual(after.revision, before.revision + 1)
        XCTAssertNotEqual(after.secretCiphertext, before.secretCiphertext,
                          "rotation must re-encrypt the secret under a fresh item key")

        // --- a revoked device cannot obtain a new session (design §8.2).
        do {
            _ = try await SessionClient(api: cliAPIBase)
                .start(deviceID: cliRow.id, signer: cliSigner)
            XCTFail("revoked CLI minted a new session")
        } catch let e as APIError {
            guard case .deviceRevoked = e else {
                XCTFail("expected device_revoked, got \(e)")
                return
            }
        }
    }

    /// The headline feature end-to-end with the REAL CLI binary: a
    /// local-only item, a real `keyref pair`, a real approval round and a
    /// real `keyref exec`. The injected value is captured through a
    /// child-side file (the redactor only covers stdout/stderr), which is
    /// what distinguishes "the CLI injected the secret" from "the CLI
    /// injected the AES-GCM ciphertext" — the exact contract fixed in this
    /// round.
    @MainActor
    func testRealCliLocalOnlyApproval() async throws {
        let handle = try await Self.startServer()
        defer { Self.stopServer(handle) }

        let keyStore = InMemoryKeyStore()
        let stateStore = UIStateStore()
        let backend = LiveBackend(keyStore: keyStore, stateStore: stateStore,
                                  origin: handle.baseURL, urlSession: .shared)
        try await backend.uploadCreatedVault(await backend.prepareCreation(label: "integration-iphone"))
        let localDraft = ItemDraft(ref: "totp-seed", name: "TOTP seed",
                                   itemDescription: "", type: "note",
                                   value: "totp-seed-1234567890", policy: ItemPolicy(),
                                   injectable: true, storageClass: .localOnly)
        do {
            try await backend.createItem(localDraft)
        } catch {
            XCTFail("create local-only item failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        let localRow = try XCTUnwrap(stateStore.allItems().first)

        // Build and run the real CLI.
        let cliBin: URL
        do {
            cliBin = try Self.buildCLI()
        } catch {
            throw XCTSkip("\(error)") // no Go toolchain / sources: environment skip
        }
        let cliHome = FileManager.default.temporaryDirectory
            .appendingPathComponent("keyref-cli-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: cliHome, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: cliHome) }
        var cliEnv = ProcessInfo.processInfo.environment
        cliEnv["KEYREF_HOME"] = cliHome.appendingPathComponent("home").path
        cliEnv["KEYREF_KEYRING_DIR"] = cliHome.appendingPathComponent("keyring").path
        cliEnv["KEYREF_SERVER"] = handle.baseURL.absoluteString

        let pair = Process()
        pair.executableURL = cliBin
        pair.arguments = ["pair", "--print-payload", "--name", "build-bot"]
        pair.environment = cliEnv
        let pairPipe = Pipe()
        pair.standardOutput = pairPipe
        pair.standardError = pairPipe
        do {
            try pair.run()
        } catch {
            XCTFail("CLI pair did not start: \(error)")
            return
        }
        defer { if pair.isRunning { pair.terminate() } }

        let payload: String
        do {
            payload = try await Self.waitForPairPayload(from: pairPipe, timeout: 20)
        } catch {
            XCTFail("no QR payload from CLI: \(error)")
            return
        }
        let offer: PairingOffer
        do {
            offer = try PairingOffer.parse(payload)
        } catch {
            XCTFail("bad CLI payload: \(error)")
            return
        }
        do {
            // Only a view grant: 仅本机 items never get a use grant (§6.6).
            try await backend.completePairing(
                offer: offer, deviceLabel: "build-bot",
                selections: [GrantSelection(itemID: localRow.itemID, kind: "view")])
        } catch {
            XCTFail("completePairing failed: \(error)\nserver log:\n\(Self.logTail(handle))")
            return
        }
        do {
            try await Self.waitForExit(pair, timeout: 30)
        } catch {
            XCTFail("CLI pair did not finish: \(error)")
            return
        }
        XCTAssertEqual(pair.terminationStatus, 0, "CLI pairing failed")

        // Sync pulls the item row (empty secret) + view grant + directory.
        let sync = try await Self.runCLI(cliBin, ["sync"], env: cliEnv, timeout: 60)
        XCTAssertEqual(sync.status, 0, "CLI sync failed: \(sync.output)")

        // Exec: the value reaches the child only through the approved
        // one-time wrap; the child writes it to a file so redaction cannot
        // mask which payload kind was delivered.
        let injectedFile = cliHome.appendingPathComponent("injected.txt")
        let exec = Process()
        exec.executableURL = cliBin
        exec.arguments = ["exec", "--env", "K=totp-seed", "--", "/usr/bin/awk",
                          "-v", "out=\(injectedFile.path)",
                          "BEGIN { printf \"%s\", ENVIRON[\"K\"] > out }"]
        exec.environment = cliEnv
        let execOut = Pipe()
        exec.standardOutput = execOut
        exec.standardError = execOut
        do {
            try exec.run()
        } catch {
            XCTFail("CLI exec did not start: \(error)")
            return
        }
        defer { if exec.isRunning { exec.terminate() } }

        var approved = false
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline {
            let inbox = await backend.loadPendingApprovals()
            if let entry = inbox.first(where: { $0.valid && $0.itemID == localRow.itemID }) {
                do {
                    try await backend.decideApproval(approvalID: entry.approvalID, approve: true)
                    approved = true
                } catch {
                    XCTFail("approve failed: \(error)")
                }
                break
            }
            try? await Task.sleep(for: .milliseconds(250))
        }
        guard approved else {
            XCTFail("no approval request reached the iOS inbox\nserver log:\n\(Self.logTail(handle))")
            return
        }
        do {
            try await Self.waitForExit(exec, timeout: 30)
        } catch {
            XCTFail("CLI exec did not finish: \(error)")
            return
        }
        let execOutput = Self.drain(execOut)
        XCTAssertEqual(exec.terminationStatus, 0, "CLI exec failed: \(execOutput)")
        let injected = try String(contentsOf: injectedFile, encoding: .utf8)
        XCTAssertEqual(injected, "totp-seed-1234567890",
                       "the owner must deliver the secret VALUE, not its ciphertext")
    }

    @MainActor
    private static func buildCLI() throws -> URL {
        guard let go = goBinary() else { throw XCTSkip("`go` toolchain not found") }
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: repoRoot.appendingPathComponent("cli/go.mod").path) else {
            throw XCTSkip("keyref CLI sources not found")
        }
        let out = FileManager.default.temporaryDirectory
            .appendingPathComponent("keyref-cli-bin-\(UUID().uuidString)/keyref")
        try FileManager.default.createDirectory(at: out.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let build = Process()
        build.executableURL = URL(fileURLWithPath: go)
        build.currentDirectoryURL = repoRoot
        build.arguments = ["build", "-C", "cli", "-o", out.path, "./cmd/keyref"]
        try build.run()
        build.waitUntilExit()
        guard build.terminationStatus == 0 else {
            throw ServerFailure(description: "CLI build failed (go exit \(build.terminationStatus))")
        }
        return out
    }

    private static func waitForPairPayload(from pipe: Pipe, timeout: TimeInterval) async throws -> String {
        let box = LineBox()
        pipe.fileHandleForReading.readabilityHandler = { fh in
            let data = fh.availableData
            if data.isEmpty { return }
            box.append(data)
        }
        defer { pipe.fileHandleForReading.readabilityHandler = nil }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let line = box.lines().first(where: { $0.hasPrefix("payload: ") }) {
                return String(line.dropFirst("payload: ".count))
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        throw ServerFailure(description: "pair payload timeout; output so far:\n\(box.lines().joined(separator: "\n"))")
    }

    private static func waitForExit(_ process: Process, timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            try? await Task.sleep(for: .milliseconds(100))
        }
        if process.isRunning {
            throw ServerFailure(description: "process did not exit within \(timeout)s")
        }
    }

    private static func runCLI(_ executable: URL, _ args: [String],
                               env: [String: String], timeout: TimeInterval) async throws -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = executable
        process.arguments = args
        process.environment = env
        let out = Pipe()
        process.standardOutput = out
        process.standardError = out
        try process.run()
        try await waitForExit(process, timeout: timeout)
        return (process.terminationStatus, drain(out))
    }

    private static func drain(_ pipe: Pipe) -> String {
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? "<non-utf8 output>"
    }

    // MARK: - server process management

    @MainActor
    private static func startServer() async throws -> ServerHandle {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // KeyrefUITests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // ios
            .deletingLastPathComponent() // repo root
        guard FileManager.default.fileExists(atPath: repoRoot.appendingPathComponent("server/go.mod").path) else {
            throw XCTSkip("keyref server sources not found next to the test file")
        }
        guard let go = goBinary() else {
            throw XCTSkip("`go` toolchain not found; skipping real-server integration test")
        }

        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("keyref-integration-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let binary = tmp.appendingPathComponent("keyref-server")
        let dataDir = tmp.appendingPathComponent("data", isDirectory: true)
        let logURL = tmp.appendingPathComponent("server.log")
        _ = FileManager.default.createFile(atPath: logURL.path, contents: nil)

        // Build the server once (go.work at the repo root resolves proto).
        let build = Process()
        build.executableURL = URL(fileURLWithPath: go)
        build.currentDirectoryURL = repoRoot
        build.arguments = ["build", "-C", "server", "-o", binary.path, "./cmd/keyref-server"]
        try build.run()
        build.waitUntilExit()
        guard build.terminationStatus == 0 else {
            throw ServerFailure(description: "server build failed (go exit \(build.terminationStatus))\n\(logTail(url: logURL))")
        }

        let port = try freePort()
        let baseURL = URL(string: "http://127.0.0.1:\(port)")!
        let process = Process()
        process.executableURL = binary
        process.arguments = ["serve", "--listen", "127.0.0.1:\(port)"]
        var env = ProcessInfo.processInfo.environment
        env["KEYREF_DATA"] = dataDir.path
        env["KEYREF_ENFORCE_QUOTAS"] = "1" // hosted-style: PoW + quotas
        env["KEYREF_DOMAIN"] = ""
        process.environment = env
        process.standardOutput = try FileHandle(forWritingTo: logURL)
        process.standardError = try FileHandle(forWritingTo: logURL)
        try process.run()

        // Wait for liveness (ACME off → plain HTTP loopback).
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline {
            if !process.isRunning {
                throw ServerFailure(description: "server exited during startup\n\(logTail(url: logURL))")
            }
            if let (status, _) = try? await httpStatus(baseURL.appendingPathComponent("v1/healthz")),
               status == 200 {
                return ServerHandle(process: process, baseURL: baseURL,
                                    dataDir: dataDir, logURL: logURL)
            }
            try? await Task.sleep(for: .milliseconds(150))
        }
        stop(process)
        throw ServerFailure(description: "server did not become healthy\n\(logTail(url: logURL))")
    }

    private static func stopServer(_ handle: ServerHandle) {
        stop(handle.process)
        try? FileManager.default.removeItem(at: handle.dataDir.deletingLastPathComponent())
    }

    private static func stop(_ process: Process) {
        guard process.isRunning else { return }
        process.terminate()
        let deadline = Date().addingTimeInterval(3)
        while process.isRunning && Date() < deadline {
            usleep(50_000)
        }
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    }

    private static func goBinary() -> String? {
        for path in ["/opt/homebrew/bin/go", "/usr/local/bin/go", "/usr/bin/go"]
        where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        return nil
    }

    private static func freePort() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ServerFailure(description: "socket() failed") }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, len)
            }
        }
        guard bindResult == 0 else { throw ServerFailure(description: "bind() failed") }
        let nameResult = withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        guard nameResult == 0 else { throw ServerFailure(description: "getsockname() failed") }
        return UInt16(bigEndian: addr.sin_port)
    }

    private static func httpStatus(_ url: URL) async throws -> (Int, Data) {
        var request = URLRequest(url: url)
        request.timeoutInterval = 2
        let (data, response) = try await URLSession.shared.data(for: request)
        return ((response as? HTTPURLResponse)?.statusCode ?? 0, data)
    }

    private static func logTail(_ handle: ServerHandle) -> String {
        logTail(url: handle.logURL)
    }

    private static func logTail(url: URL) -> String {
        String(((try? String(contentsOf: url, encoding: .utf8)) ?? "<no server log>").suffix(4000))
    }
}

/// Thread-safe line accumulator for live pipe output.
private final class LineBox: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = Data()
    func append(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        buffer.append(data)
    }
    func lines() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return String(decoding: buffer, as: UTF8.self).split(separator: "\n").map(String.init)
    }
}
#endif
