// APIClient tests over MockURLProtocol: bearer injection, the §1.3
// error-code mapping, §1.2 body limits, and the two-step flows (session,
// vault delete, PoW challenge). Pairing client and QR payload tests live
// here too (§6.16–§6.18, §9.1).
import CryptoKit
import XCTest

@testable import KeyrefCore

private struct ChallengeErrorBody: Codable {
    let error: String
    let challenge: Data
    let expires_at: Int64
}

final class APIClientTests: XCTestCase {
    override func tearDown() {
        MockURLProtocol.reset()
    }

    private func makeAPI(token: String? = nil) -> APIClient {
        APIClient(baseURL: URL(string: "https://sync.example")!,
                  session: MockURLProtocol.makeSession(),
                  bearerToken: { token })
    }

    func testBearerHeaderAndBasePath() async throws {
        MockURLProtocol.handler = { _, _ in (200, Data("{\"cursor\":0,\"has_more\":false,\"changes\":[]}".utf8)) }
        _ = try await makeAPI(token: "tok123").sync(cursor: 7)
        let calls = MockURLProtocol.recorded()
        XCTAssertEqual(calls.count, 1)
        XCTAssertEqual(calls[0].request.url?.absoluteString, "https://sync.example/v1/sync?cursor=7")
        XCTAssertEqual(calls[0].request.value(forHTTPHeaderField: "Authorization"), "Bearer tok123")
        XCTAssertEqual(calls[0].request.value(forHTTPHeaderField: "Content-Type"), "application/json; charset=utf-8")
    }

    func testErrorMapping() async throws {
        let cases: [(String, Int, APIError)] = [
            ("revision_conflict", 409, .revisionConflict),
            ("device_revoked", 403, .deviceRevoked),
            ("quota_exceeded", 429, .quotaExceeded),
            ("rate_limited", 429, .rateLimited),
            ("cursor_stale", 409, .cursorStale),
            ("body_too_large", 413, .bodyTooLarge),
            ("bad_signature", 403, .badSignature),
            ("not_found", 404, .notFound),
            ("forbidden", 403, .forbidden),
            ("unauthorized", 401, .unauthorized),
            ("pair_expired", 410, .pairExpired),
            ("approval_not_pending", 409, .approvalNotPending),
            ("vault_frozen", 403, .vaultFrozen),
            ("invalid_field", 400, .invalidField),
            ("invalid_json", 400, .invalidJSON),
        ]
        for (code, status, expected) in cases {
            MockURLProtocol.handler = { _, _ in (status, Data("{\"error\":\"\(code)\"}".utf8)) }
            let api = makeAPI(token: "t")
            do {
                _ = try await api.sync(cursor: 0)
                XCTFail("\(code) should have thrown")
            } catch let e as APIError {
                XCTAssertEqual(e, expected, code)
            }
        }
    }

    func testPoWChallengeErrorCarriesChallenge() async throws {
        let challenge = Data(repeating: 0xab, count: 32)
        MockURLProtocol.handler = { _, _ in
            (401, try WireJSON.encoder.encode(ChallengeErrorBody(error: "pow_required",
                                                                 challenge: challenge, expires_at: 1790000000000)))
        }
        do {
            _ = try await makeAPI().createVault(CreateVaultRequest(
                vaultID: "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
                device: DeviceInput(deviceID: "99998888777766665555444433332222", kind: "ios",
                                    hpkeKEM: "P-256", hpkePublicKey: Data(repeating: 1, count: 65),
                                    signAlg: "ecdsa-p256", signPublicKey: Data(repeating: 2, count: 65),
                                    label: "iPhone", renewalSignPublicKey: Data()),
                recoveryWrap: Data(), recoveryKDFJSON: "{}", recoverySignPub: Data(),
                directoryRevision: 1, directorySigned: Data(), signature: Data(), pow: nil))
            XCTFail("pow_required should have thrown")
        } catch let e as APIError {
            guard case .powRequired(let ch, let exp) = e else { return XCTFail("\(e)") }
            XCTAssertEqual(ch, challenge)
            XCTAssertEqual(exp, 1790000000000)
        }
    }

    func testBodyLimitEnforcedBeforeNetwork() async {
        MockURLProtocol.handler = { _, _ in (200, Data()) }
        let api = makeAPI(token: "t")
        let big = PutItemRequest(revision: 1, tombstone: false,
                                 metaCiphertext: Data(count: 300 * 1024), secretCiphertext: Data(),
                                 vaultWrappedMetaKey: Data(), vaultWrappedItemKey: Data(),
                                 writerDeviceID: "99998888777766665555444433332222", signature: Data())
        do {
            _ = try await api.putItem(itemID: "deadbeefdeadbeefdeadbeefdeadbeef", big)
            XCTFail("oversized body should be rejected locally")
        } catch let e as APIError {
            guard case .requestBodyTooLarge(let limit) = e else { return XCTFail("\(e)") }
            XCTAssertEqual(limit, APIClient.Limits.itemBody)
        } catch {
            XCTFail("\(error)")
        }
        // Nothing hit the network.
        XCTAssertTrue(MockURLProtocol.recorded().isEmpty)
    }

    func testSessionTwoStep() async throws {
        let signer = try Ed25519Signer()
        let deviceID = "aaaabbbbccccddddeeeeffff00001111"
        let challenge = Data(repeating: 0x33, count: 32)
        MockURLProtocol.handler = { request, body in
            if request.url!.path.hasSuffix("/session") {
                let req = try WireJSON.decoder.decode(SessionRequest.self, from: body)
                if req.challenge == nil {
                    return (200, try WireJSON.encoder.encode(SessionChallengeResponse(
                        challenge: challenge, expiresAt: 1790000000000)))
                }
                // Verify the signature the client produced (round trip).
                let tb = try buildSessionTranscript(deviceID: deviceID, challenge: challenge)
                try verifyDeviceSignature(transcript: tb, signature: req.signature!, signAlg: signer.signAlg,
                                          publicKey: signer.signPublicKey)
                return (200, try WireJSON.encoder.encode(SessionResponse(
                    token: String(repeating: "a", count: 64), expiresAt: 1790003600000,
                    origin: "https://sync.example", plan: "unlimited", limits: nil)))
            }
            return (404, Data("{\"error\":\"not_found\"}".utf8))
        }
        let session = try await SessionClient(api: makeAPI()).start(deviceID: deviceID, signer: signer)
        XCTAssertEqual(session.token.count, 64)
        XCTAssertEqual(session.plan, "unlimited")
        let calls = MockURLProtocol.recorded()
        XCTAssertEqual(calls.count, 2)
        // Step 1 carries only device_id; step 2 carries challenge + signature.
        XCTAssertTrue(String(decoding: calls[0].body, as: UTF8.self).contains("\"device_id\""))
        XCTAssertFalse(String(decoding: calls[0].body, as: UTF8.self).contains("\"signature\""))
        XCTAssertTrue(String(decoding: calls[1].body, as: UTF8.self).contains("\"signature\""))
    }

    func testVaultDeleteTwoStep() async throws {
        let owner = try SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
        let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        let challenge = Data(repeating: 0x44, count: 32)
        MockURLProtocol.handler = { request, body in
            guard request.httpMethod == "DELETE", request.url!.path.hasSuffix("/vaults/\(vaultID)") else {
                return (404, Data("{\"error\":\"not_found\"}".utf8))
            }
            if body.isEmpty {
                return (401, try WireJSON.encoder.encode(ChallengeErrorBody(error: "delete_challenge_required",
                                                                            challenge: challenge, expires_at: 1790000000000)))
            }
            let req = try WireJSON.decoder.decode(DeleteVaultRequest.self, from: body)
            let tb = try buildVaultDeleteTranscript(vaultID: vaultID, challenge: challenge)
            try verifyDeviceSignature(transcript: tb, signature: req.signature!,
                                      signAlg: owner.signAlg, publicKey: owner.signPublicKey)
            return (204, Data())
        }
        let api = makeAPI(token: "t")
        let ch = try await api.requestVaultDeleteChallenge(vaultID: vaultID)
        XCTAssertEqual(ch.challenge, challenge)
        let sig = try owner.sign(try buildVaultDeleteTranscript(vaultID: vaultID, challenge: challenge))
        try await api.deleteVault(vaultID: vaultID, challenge: challenge, signature: sig)
    }

    // MARK: pairing (§9.1, §6.16–§6.18)

    func testPairingQRRoundtripAndFingerprint() throws {
        let hpke = try HPKEKeys.generateX25519()
        let sign = try HPKEKeys.generateEd25519()
        let nonce = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
        let offer = PairingOffer(hpkeKEM: KEMName.x25519, hpkePublicKey: hpke.publicKey,
                                 signAlg: SignAlg.ed25519, signPublicKey: sign.publicKey,
                                 nonce: nonce, label: "build agent 1",
                                 origin: URL(string: "https://sync.example")!)
        let parsed = try PairingOffer.parse(offer.payload())
        XCTAssertEqual(parsed, offer)
        // The fingerprint is SHA-256(sign pub)[0..8], grouped uppercase hex.
        let digest = Data(SHA256.hash(data: sign.publicKey))
        let hex = digest.prefix(8).map { String(format: "%02X", $0) }.joined()
        XCTAssertEqual(offer.fingerprint, "\(hex.prefix(4))-\(hex.dropFirst(4).prefix(4))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12))")
        // Bad payloads fail closed.
        XCTAssertThrowsError(try PairingOffer.parse("https://evil.example/pair?v=1"))
        XCTAssertThrowsError(try PairingOffer.parse("keyref://pair?v=2"))
        XCTAssertThrowsError(try PairingOffer.parse("keyref://pair?v=1&k=!!!&s=!!!&n=short&name=x&u=https://x"))
    }

    func testPairingCompleteSignsTranscript() async throws {
        let ownerSigner = try SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
        let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        let nonce = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
        let hpke = try HPKEKeys.generateX25519()
        let sign = try HPKEKeys.generateEd25519()
        MockURLProtocol.handler = { request, body in
            guard request.url!.path.hasSuffix("/pair/complete") else {
                return (404, Data("{\"error\":\"not_found\"}".utf8))
            }
            let req = try WireJSON.decoder.decode(PairCompleteRequest.self, from: body)
            // Rebuild the §3.4 transcript server-side and verify.
            let t = PairTranscript(vaultID: vaultID, ownerSignPublicKey: ownerSigner.signPublicKey,
                                   nonce: req.nonce, deviceID: req.device.deviceID,
                                   hpkeKEM: req.device.hpkeKEM, hpkePublicKey: req.device.hpkePublicKey,
                                   signAlg: req.device.signAlg, signPublicKey: req.device.signPublicKey,
                                   label: req.device.label,
                                   grants: req.grants.map { $0.transcript(vaultID: vaultID) })
            try verifyOwnerSignature(transcript: try t.buildBytes(), signature: req.signature,
                                     ownerSignPublicKey: ownerSigner.signPublicKey)
            return (204, Data())
        }
        let device = DeviceInput(deviceID: "11112222333344441111222233334444", kind: DeviceKind.cli,
                                 hpkeKEM: KEMName.x25519, hpkePublicKey: hpke.publicKey,
                                 signAlg: SignAlg.ed25519, signPublicKey: sign.publicKey,
                                 label: "build-agent-1", renewalSignPublicKey: Data())
        // Empty grant set at pairing time (design §15).
        try await PairingClient(api: makeAPI(token: "t")).complete(
            vaultID: vaultID, nonce: nonce, device: device, grants: [], ownerSigner: ownerSigner)
        XCTAssertEqual(MockURLProtocol.recorded().count, 1)
    }

    func testVerifyCompleteStatusRejectsBadSignature() throws {
        let ownerSigner = try SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
        let hpke = try HPKEKeys.generateX25519()
        let sign = try HPKEKeys.generateEd25519()
        let nonce = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
        let offer = PairingOffer(hpkeKEM: KEMName.x25519, hpkePublicKey: hpke.publicKey,
                                 signAlg: SignAlg.ed25519, signPublicKey: sign.publicKey,
                                 nonce: nonce, label: "cli", origin: URL(string: "https://sync.example")!)
        let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        let deviceID = "11112222333344441111222233334444"
        let t = PairTranscript(vaultID: vaultID, ownerSignPublicKey: ownerSigner.signPublicKey,
                               nonce: nonce, deviceID: deviceID,
                               hpkeKEM: offer.hpkeKEM, hpkePublicKey: offer.hpkePublicKey,
                               signAlg: offer.signAlg, signPublicKey: offer.signPublicKey,
                               label: offer.label, grants: [])
        let goodSig = try ownerSigner.sign(try t.buildBytes())
        var badSig = goodSig
        badSig[badSig.startIndex] ^= 0x01
        var status = PairStatusResponse(status: "complete", vaultID: vaultID, deviceID: deviceID,
                                        ownerSignPublicKey: ownerSigner.signPublicKey,
                                        pairingSignature: goodSig, directoryRevision: 1,
                                        directorySigned: Data(), directorySignature: Data(), grants: [])
        try PairingClient(api: makeAPI()).verifyCompleteStatus(status, offer: offer)
        status.pairingSignature = badSig
        XCTAssertThrowsError(try PairingClient(api: makeAPI()).verifyCompleteStatus(status, offer: offer))
    }
}
