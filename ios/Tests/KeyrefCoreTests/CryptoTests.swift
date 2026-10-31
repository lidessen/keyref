// Unit tests for the crypto layer: blob layout, HPKE roundtrips (software
// and Secure Enclave when available), one-time wrap binding and the
// recovery-code codec.
import CryptoKit
import XCTest

@testable import KeyrefCore

final class CryptoTests: XCTestCase {
    private let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    private let ownerDev = "99998888777766665555444433332222"
    private let cliDev = "aaaabbbbccccddddeeeeffff00001111"
    private let itemID = "deadbeefdeadbeefdeadbeefdeadbeef"

    // MARK: blobs

    func testBlobLayout() throws {
        let key = randomKey()
        let aad = try metaAAD(vaultID: vaultID, itemID: itemID)
        let pt = Data("hello keyref".utf8)
        let blob = try BlobCrypto.sealBlob(key: key, aad: aad, plaintext: pt)
        XCTAssertEqual(blob.count, 12 + pt.count + 16)
        XCTAssertEqual(try BlobCrypto.openBlob(key: key, aad: aad, blob: blob), pt)
        // Nonces are random per seal.
        let blob2 = try BlobCrypto.sealBlob(key: key, aad: aad, plaintext: pt)
        XCTAssertNotEqual(blob.prefix(12), blob2.prefix(12))
        // Truncated blobs fail closed.
        XCTAssertThrowsError(try BlobCrypto.openBlob(key: key, aad: aad, blob: blob.prefix(20)))
    }

    // MARK: HPKE software roundtrips

    func testHPKERoundtripBothKEMs() throws {
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID, recipientDeviceID: ownerDev)
        let msg = randomKey()
        for (kem, keys) in [("X25519", try HPKEKeys.generateX25519()),
                            ("P-256", try HPKEKeys.generateP256())] {
            let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: kem, recipientPublicKey: keys.publicKey,
                                                   info: info, plaintext: msg)
            let pt = try KeyrefHPKE.unwrapKey(kemName: kem, privateKey: keys.privateKey,
                                              info: info, enc: enc, ct: ct)
            XCTAssertEqual(pt, msg, kem)
            XCTAssertEqual(enc.count, try KeyrefHPKE.publicKeySize(kemName: kem))
            XCTAssertEqual(try HPKEKeys.publicKey(of: kem, privateKey: keys.privateKey), keys.publicKey)
        }
    }

    func testHPKEOneTimeBinding() throws {
        // The one-time item-key info binds item, approval and the request
        // digest: wrapping for one request must not open for another.
        let x = try HPKEKeys.generateX25519()
        let receiver = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x.privateKey)
        let requestCT = randomKey()
        let otherRequest = randomKey()
        let approvalID = "1029384756afbcde1029384756afbcde"
        let info = try oneTimeItemKeyInfo(vaultID: vaultID, recipientDeviceID: cliDev,
                                          itemID: itemID, approvalID: approvalID,
                                          requestCiphertext: requestCT)
        let key = randomKey()
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: KEMName.x25519, recipientPublicKey: x.publicKey,
                                               info: info, plaintext: key)
        // Same request → opens and returns the wrapped key.
        let ok = try ItemCrypto.unwrapOneTimeItemKey(
            kemName: KEMName.x25519, receiver: .x25519(receiver),
            vaultID: vaultID, deviceID: cliDev, itemID: itemID,
            approvalID: approvalID, requestCiphertext: requestCT, enc: enc, wrappedKey: ct)
        XCTAssertEqual(ok, key)
        // Other request → fails closed.
        XCTAssertThrowsError(try ItemCrypto.unwrapOneTimeItemKey(
            kemName: KEMName.x25519, receiver: .x25519(receiver),
            vaultID: vaultID, deviceID: cliDev, itemID: itemID,
            approvalID: approvalID, requestCiphertext: otherRequest, enc: enc, wrappedKey: ct))
        // Other item → fails closed.
        XCTAssertThrowsError(try ItemCrypto.unwrapOneTimeItemKey(
            kemName: KEMName.x25519, receiver: .x25519(receiver),
            vaultID: vaultID, deviceID: cliDev, itemID: "feedfacefeedfacefeedfacefeedface",
            approvalID: approvalID, requestCiphertext: requestCT, enc: enc, wrappedKey: ct))
    }

    // MARK: Secure Enclave (real hardware on this machine)

    /// Runs body only when the Secure Enclave is usable on this device.
    private func withEnclave(_ body: () throws -> Void) throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }
        try body()
    }

    func testEnclaveHPKEWrapUnwrap() throws {
        try withEnclave {
            // Passcode-only access control: tests must not require biometry.
            let ac = try OwnerKeys.enclaveAccessControl(biometryRequired: false)
            let kem = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
            let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID, recipientDeviceID: ownerDev)
            let vmk = randomKey()
            let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: KEMName.p256,
                                                   recipientPublicKey: kem.publicKey.x963Representation,
                                                   info: info, plaintext: vmk)
            let opened = try KeyrefHPKE.unwrapKey(kemName: KEMName.p256, receiver: .p256Enclave(kem),
                                                  info: info, enc: enc, ct: ct)
            XCTAssertEqual(opened, vmk)
            // The enclave public key is a plain 65-byte SEC1 point that a
            // Go sender (circl) can seal to — checked cross-language.
            XCTAssertEqual(kem.publicKey.x963Representation.count, 65)
            XCTAssertEqual(kem.publicKey.x963Representation.first, 0x04)
        }
    }

    func testEnclaveReconstructionFromDataRepresentation() throws {
        try withEnclave {
            let ac = try OwnerKeys.enclaveAccessControl(biometryRequired: false)
            let sign = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac)
            let rebuilt = try EnclaveP256Signer(dataRepresentation: sign.dataRepresentation)
            XCTAssertEqual(rebuilt.signPublicKey, sign.publicKey.x963Representation)
            let bytes = try buildSessionTranscript(deviceID: ownerDev, challenge: Data(repeating: 9, count: 32))
            let sig = try rebuilt.sign(bytes)
            try verifyOwnerSignature(transcript: bytes, signature: sig, ownerSignPublicKey: rebuilt.signPublicKey)
        }
    }

    func testOwnerKeysEnclaveProbeMatchesHardware() throws {
        let keys = try OwnerKeys.generate(preferEnclave: true, biometryRequired: false)
        XCTAssertEqual(keys.isEnclaveBacked, SecureEnclave.isAvailable,
                       "the backing must follow the hardware probe, never silently swap")
        XCTAssertEqual(keys.kemKEMName, KEMName.p256)
        XCTAssertEqual(keys.kemPublicKey.count, 65)
        XCTAssertEqual(keys.signPublicKey.count, 65)
    }

    func testOwnerKeysSoftwareFallback() throws {
        let keys = try OwnerKeys.generate(preferEnclave: false)
        XCTAssertFalse(keys.isEnclaveBacked)
        // Full VMK wrap/unwrap roundtrip through the software owner.
        let vmk = randomKey()
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: keys.kemKEMName,
                                               recipientPublicKey: keys.kemPublicKey,
                                               info: try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID,
                                                                  recipientDeviceID: ownerDev),
                                               plaintext: vmk)
        let opened = try keys.unwrap(info: try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID,
                                                        recipientDeviceID: ownerDev),
                                     enc: enc, ct: ct)
        XCTAssertEqual(opened, vmk)
    }

    // MARK: audit envelope

    func testAuditEnvelopeRoundtrip() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let event = AuditEventPayload(time: 1790000000000, deviceID: cliDev, refs: ["openai-prod"],
                                      injection: ["env"], argv: ["curl", "{{keyref:openai-prod}}"],
                                      allowArgv: false, policyResult: "allow",
                                      childExit: 0, redactions: 1)
        let envelope = try AuditEnvelope.seal(event: event, vaultID: vaultID,
                                              reportingDeviceID: cliDev,
                                              ownerDeviceID: ownerDev,
                                              ownerHPKEPublicKey: owner.kemPublicKey)
        XCTAssertEqual(envelope[envelope.startIndex], 1)  // wrap_count
        let opened = try AuditEnvelope.open(envelope: envelope, vaultID: vaultID,
                                            reportingDeviceID: cliDev,
                                            owner: owner, ownerDeviceID: ownerDev)
        XCTAssertEqual(opened, event)
        // Wrong reporting device breaks the AES AAD.
        XCTAssertThrowsError(try AuditEnvelope.open(envelope: envelope, vaultID: vaultID,
                                                    reportingDeviceID: ownerDev,
                                                    owner: owner, ownerDeviceID: ownerDev))
    }

    // MARK: item crypto

    func testSealOpenItemRoundtrip() throws {
        let vmk = randomKey()
        let signer = try SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
        let meta = ItemMeta(ref: "openai-prod", name: "OpenAI production", description: "test",
                            type: "api_key", masked: "sk-****abcd", injectable: true,
                            policy: ItemPolicy())
        let secret = SecretPlaintext(value: "sk-example", username: "me")
        let sealed = try ItemCrypto.sealItem(vaultID: vaultID, itemID: itemID, revision: 1,
                                             writerDeviceID: ownerDev, vmk: vmk,
                                             signer: signer, meta: meta, secret: secret)
        let row = ItemData(vaultID: vaultID, itemID: itemID, revision: 1, tombstone: false,
                           metaCiphertext: sealed.transcript.metaCiphertext,
                           secretCiphertext: sealed.transcript.secretCiphertext,
                           vaultWrappedMetaKey: sealed.transcript.vaultWrappedMetaKey,
                           vaultWrappedItemKey: sealed.transcript.vaultWrappedItemKey,
                           writerDeviceID: ownerDev, signature: sealed.signature, updatedAt: 1)
        try ItemCrypto.verifyItemSignature(row, vaultID: vaultID, ownerSignPublicKey: signer.signPublicKey)
        // VMK unwraps the vault-wrapped keys.
        let metaKey = try ItemCrypto.unwrapMetaKey(vmk: vmk, blob: sealed.transcript.vaultWrappedMetaKey,
                                                   vaultID: vaultID, itemID: itemID)
        let itemKey = try ItemCrypto.unwrapItemKey(vmk: vmk, blob: sealed.transcript.vaultWrappedItemKey,
                                                   vaultID: vaultID, itemID: itemID)
        XCTAssertEqual(metaKey, sealed.metaKey)
        XCTAssertEqual(itemKey, sealed.itemKey)
        let openedMeta = try ItemCrypto.openMeta(key: metaKey, blob: row.metaCiphertext,
                                                 vaultID: vaultID, itemID: itemID)
        XCTAssertEqual(openedMeta, meta)
        let openedSecret = try ItemCrypto.openSecret(key: itemKey, blob: row.secretCiphertext,
                                                     vaultID: vaultID, itemID: itemID)
        XCTAssertEqual(openedSecret, secret)
        // AAD does not bind the revision: same key opens the same blob
        // regardless of the revision field (design §9.1).
        let t2 = try ItemTranscript(vaultID: vaultID, itemID: itemID, revision: 2,
                                    metaCiphertext: sealed.transcript.metaCiphertext,
                                    secretCiphertext: sealed.transcript.secretCiphertext,
                                    vaultWrappedMetaKey: sealed.transcript.vaultWrappedMetaKey,
                                    vaultWrappedItemKey: sealed.transcript.vaultWrappedItemKey,
                                    writerDeviceID: ownerDev).buildBytes()
        let sig2 = try signer.sign(t2)
        try verifyOwnerSignature(transcript: t2, signature: sig2, ownerSignPublicKey: signer.signPublicKey)
    }
}

// MARK: proof of work (protocol §10.1)

final class PoWTests: XCTestCase {
    /// The solved nonce must hash to ≥21 leading zero bits under the
    /// §10.1 layout, and the solution must be verified byte-for-byte by
    /// an independent reimplementation of the server check.
    func testSolveMeetsDifficulty() throws {
        let vaultID = "5f0cdeadbeefdeadbeefdeadbeef42aa"
        let challenge = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let nonce = try PoW.solve(challenge: challenge, vaultID: vaultID)
        XCTAssertEqual(nonce.count, 8)
        var vaultRaw = try KeyrefEncoding.hexDecode(vaultID)
        XCTAssertEqual(vaultRaw.count, 16)
        var hasher = SHA256()
        hasher.update(data: challenge)
        hasher.update(data: vaultRaw)
        hasher.update(data: nonce)
        let digest = hasher.finalize()
        var bits = 0
        for byte in digest {
            if byte == 0 { bits += 8; continue }
            var b = byte
            while b & 0x80 == 0 { bits += 1; b <<= 1 }
            break
        }
        XCTAssertGreaterThanOrEqual(bits, 21)
    }

    func testSolveRejectsShortChallenge() {
        XCTAssertThrowsError(try PoW.solve(challenge: Data(repeating: 0, count: 31),
                                           vaultID: String(repeating: "0", count: 32)))
    }
}

// MARK: wire tolerance (cross-language regression)

final class GrantWireDecodingTests: XCTestCase {
    /// The Go server used to omit `deleted` for live rows (json
    /// `omitempty`); a required non-optional Bool made the whole iOS sync
    /// batch fail with invalidJSON. Missing must mean "not deleted".
    func testGrantWithoutDeletedFieldDecodesAsLive() throws {
        let json = #"""
        {"device_id":"aaaabbbbccccddddeeeeffff00001111",
         "item_id":"deadbeefdeadbeefdeadbeefdeadbeef",
         "kind":"use",
         "hpke_enc":"","wrapped_key":"","expires_at":0,
         "revision":1,"signature":""}
        """#
        let g = try WireJSON.decoder.decode(GrantData.self, from: Data(json.utf8))
        XCTAssertFalse(g.deleted)
        XCTAssertEqual(g.revision, 1)
    }
}
