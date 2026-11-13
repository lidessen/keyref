// Approval flow tests (design §8.3, protocol §6.19–§6.21, D4/D7; v2 A/B):
// the owner opens the CLI's HPKE'd request, re-verifies the Ed25519
// signature over the approval-request transcript (§3.11) against the
// directory entry, and wraps the item key one-time to the request's
// ephemeral X25519 key with the §3.7 info binding. The decision itself is
// signed over the approval-decision transcript (§3.12) — the CLI verifies
// that signature before it unwraps. The CLI-side unwrap comes from the
// existing ItemCrypto.unwrapOneTimeItemKey — the round-trip pins both
// sides of the wire to the same info template.
import CryptoKit
import XCTest

@testable import KeyrefCore

final class ApprovalFlowTests: XCTestCase {
    let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    let ownerDeviceID = "aaaabbbbccccddddeeeeffff00001111"
    let cliDeviceID = "11112222333344445555666677778888"
    let itemID = "99990000aaaabbbbccccddddeeeeffff"
    let approvalID = "abcdef01abcdef01abcdef01abcdef01"
    let expiresAt: Int64 = 1790000120000

    private struct CLI {
        var signer: Ed25519Signer
        var ephemeral: Curve25519.KeyAgreement.PrivateKey
        init() throws {
            signer = try Ed25519Signer()
            ephemeral = Curve25519.KeyAgreement.PrivateKey()
        }
    }

    /// Builds a §6.19 request exactly the way the CLI would: HPKE to the
    /// owner (purpose approval-request), Ed25519 signature over the
    /// approval-request transcript (§3.11, v2 A) — which covers the
    /// subject, the expiry, the one-time public key and the digest of the
    /// ciphertext.
    private func makePending(cli: CLI, owner: OwnerKeys, argv: [String] = ["curl", "--reply", "Password:=wifi-home", "https://api.openai.com"]) throws -> (PendingApproval, ApprovalRequestPlaintext) {
        let plaintext = ApprovalRequestPlaintext(
            v: 1, cliDeviceID: cliDeviceID, itemID: itemID,
            argv: argv, refs: ["wifi-home"], injection: "env",
            hosts: ["api.openai.com"], ephemeralKEM: KEMName.x25519,
            ephemeralPublicKey: cli.ephemeral.publicKey.rawRepresentation,
            createdAt: 1790000000000)
        let info = try hpkeInfo(purpose: KeyrefPurpose.approvalRequest,
                                vaultID: vaultID, recipientDeviceID: ownerDeviceID)
        let body = try WireJSON.encoder.encode(plaintext)
        // owner 是 P-256（Secure Enclave 曲线，design §9.2）。
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                               recipientPublicKey: owner.kemPublicKey,
                                               info: info, plaintext: body)
        let ciphertext = enc + ct
        let signature = try cli.signer.sign(try requestTranscript(cli: cli,
                                                                  ciphertext: ciphertext))
        let pending = PendingApproval(approvalID: approvalID, cliDeviceID: cliDeviceID,
                                      itemID: itemID,
                                      cliEphemeralPublicKey: cli.ephemeral.publicKey.rawRepresentation,
                                      requestCiphertext: ciphertext,
                                      requestSignature: signature,
                                      createdAt: 1790000000000,
                                      expiresAt: expiresAt)
        return (pending, plaintext)
    }

    /// The §3.11 transcript the CLI signs and the owner rebuilds.
    private func requestTranscript(cli: CLI, ciphertext: Data,
                                   subjectKind: String = ApprovalSubjectKind.item,
                                   subjectID: String? = nil) throws -> Data {
        try buildApprovalRequestTranscript(ApprovalRequestTranscript(
            vaultID: vaultID,
            cliDeviceID: cliDeviceID,
            subjectKind: subjectKind,
            subjectID: subjectID ?? itemID,
            expiresAt: UInt64(expiresAt),
            cliEphemeralPublicKey: cli.ephemeral.publicKey.rawRepresentation,
            requestCiphertext: ciphertext))
    }

    private func directoryEntry(cli: CLI) -> KeyrefDirectoryDevice {
        KeyrefDirectoryDevice(deviceID: cliDeviceID, kind: DeviceKind.cli,
                              status: DeviceStatus.active, hpkeKEM: KEMName.x25519,
                              hpkePublicKey: Data(repeating: 7, count: 32),
                              signAlg: SignAlg.ed25519,
                              signPublicKey: cli.signer.signPublicKey,
                              renewalSignPublicKey: Data(), grantsDigest: Data())
    }

    func testOpenVerifyApproveRoundTrip() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let cli = try CLI()
        let (pending, plaintext) = try makePending(cli: cli, owner: owner)

        let opened = try ApprovalFlows.openRequest(pending, owner: owner,
                                                   vaultID: vaultID,
                                                   ownerDeviceID: ownerDeviceID)
        XCTAssertEqual(opened, plaintext)
        // §6.20: verify the CLI signature (over the §3.11 transcript)
        // before showing the request.
        try ApprovalFlows.verifyRequestSignature(pending, vaultID: vaultID,
                                                  device: directoryEntry(cli: cli))
        try ApprovalFlows.validatePlaintext(opened, pending: pending)

        let itemKey = randomKey()
        let decision = try ApprovalFlows.approveDecision(vaultID: vaultID, pending: pending,
                                                         plaintext: opened,
                                                         itemKey: itemKey,
                                                         decisionDeviceID: ownerDeviceID,
                                                         signer: owner.signer)
        XCTAssertEqual(decision.decision, "approved")
        guard let enc = decision.oneTimeEnc, let wrapped = decision.oneTimeWrappedKey else {
            return XCTFail("approved decision must carry the one-time wrap")
        }
        XCTAssertEqual(enc.count, KeyrefSizes.x25519Key)

        // CLI side: the same one-time unwrap used in production (§7.1, §8.3).
        let unwrapped = try ItemCrypto.unwrapOneTimeItemKey(
            kemName: KEMName.x25519, receiver: .x25519(cli.ephemeral),
            vaultID: vaultID, deviceID: cliDeviceID, itemID: itemID,
            approvalID: approvalID, requestCiphertext: pending.requestCiphertext,
            enc: enc, wrappedKey: wrapped)
        XCTAssertEqual(unwrapped, itemKey)
    }

    func testDecisionSignatureVerifiesUnderTheOwnerKey() throws {
        // §3.12 (v2 B): the CLI verifies the decision under the owner's
        // public key from the signed directory before it unwraps.
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let cli = try CLI()
        let (pending, plaintext) = try makePending(cli: cli, owner: owner)
        let itemKey = randomKey()
        let decision = try ApprovalFlows.approveDecision(vaultID: vaultID, pending: pending,
                                                         plaintext: plaintext,
                                                         itemKey: itemKey,
                                                         decisionDeviceID: ownerDeviceID,
                                                         signer: owner.signer)
        let enc = try XCTUnwrap(decision.oneTimeEnc)
        let wrapped = try XCTUnwrap(decision.oneTimeWrappedKey)

        let transcript = try buildApprovalDecisionTranscript(ApprovalDecisionTranscript(
            vaultID: vaultID,
            approvalID: approvalID,
            decisionDeviceID: ownerDeviceID,
            decision: "approved",
            requestCiphertext: pending.requestCiphertext,
            oneTimeEnc: enc,
            oneTimeWrappedKey: wrapped))
        try verifyDeviceSignature(transcript: transcript,
                                  signature: decision.decisionSignature,
                                  signAlg: SignAlg.ecdsaP256,
                                  publicKey: owner.signer.signPublicKey)

        // A different wrap (one the server made up) must not verify.
        let forged = try buildApprovalDecisionTranscript(ApprovalDecisionTranscript(
            vaultID: vaultID,
            approvalID: approvalID,
            decisionDeviceID: ownerDeviceID,
            decision: "approved",
            requestCiphertext: pending.requestCiphertext,
            oneTimeEnc: enc,
            oneTimeWrappedKey: wrapped + [0x00]))
        XCTAssertNotEqual(forged, transcript)
        do {
            try verifyDeviceSignature(transcript: forged,
                                      signature: decision.decisionSignature,
                                      signAlg: SignAlg.ecdsaP256,
                                      publicKey: owner.signer.signPublicKey)
            XCTFail("a different wrap must not verify")
        } catch let e as KeyrefWireError {
            XCTAssertEqual(e, .badSignature)
        }
    }

    func testDeniedDecisionIsSignedAndCarriesNoMaterial() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let cli = try CLI()
        let (pending, _) = try makePending(cli: cli, owner: owner)
        let deny = try ApprovalFlows.denyDecision(vaultID: vaultID, pending: pending,
                                                  decisionDeviceID: ownerDeviceID,
                                                  signer: owner.signer)
        XCTAssertEqual(deny.decision, "denied")
        XCTAssertNil(deny.oneTimeEnc)
        XCTAssertNil(deny.oneTimeWrappedKey)

        let transcript = try buildApprovalDecisionTranscript(ApprovalDecisionTranscript(
            vaultID: vaultID,
            approvalID: approvalID,
            decisionDeviceID: ownerDeviceID,
            decision: "denied",
            requestCiphertext: pending.requestCiphertext))
        try verifyDeviceSignature(transcript: transcript,
                                  signature: deny.decisionSignature,
                                  signAlg: SignAlg.ecdsaP256,
                                  publicKey: owner.signer.signPublicKey)
    }

    func testWrongOwnerCannotOpen() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let other = try OwnerKeys.generate(preferEnclave: false)
        let cli = try CLI()
        let (pending, _) = try makePending(cli: cli, owner: owner)
        do {
            _ = try ApprovalFlows.openRequest(pending, owner: other,
                                              vaultID: vaultID,
                                              ownerDeviceID: ownerDeviceID)
            XCTFail("a different owner must not open the request")
        } catch { /* fail closed */ }

        // Wrong recipient device id in the info → also fails closed.
        do {
            _ = try ApprovalFlows.openRequest(pending, owner: owner,
                                              vaultID: vaultID,
                                              ownerDeviceID: "ffffeeeeffffeeeeffffeeeeffffeeee")
            XCTFail("wrong recipient binding must not open")
        } catch { /* fail closed */ }
    }

    func testBadSignatureIsRejected() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let cli = try CLI()
        let (pending, _) = try makePending(cli: cli, owner: owner)
        // 签名对不上目录公钥：显示为无效并可忽略（§8.3）。
        let impostor = try Ed25519Signer()
        let forged = PendingApproval(approvalID: pending.approvalID,
                                     cliDeviceID: pending.cliDeviceID,
                                     itemID: pending.itemID,
                                     cliEphemeralPublicKey: pending.cliEphemeralPublicKey,
                                     requestCiphertext: pending.requestCiphertext,
                                     requestSignature: try impostor.sign(pending.requestCiphertext),
                                     createdAt: pending.createdAt, expiresAt: pending.expiresAt)
        do {
            try ApprovalFlows.verifyRequestSignature(forged, vaultID: vaultID,
                                                      device: directoryEntry(cli: cli))
            XCTFail("forged signature must fail")
        } catch let e as KeyrefWireError {
            XCTAssertEqual(e, .badSignature)
        }
        // Tampered ciphertext also breaks the signature (the transcript
        // hashes the ciphertext).
        var tampered = pending
        tampered.requestCiphertext = pending.requestCiphertext + [0x00]
        do {
            try ApprovalFlows.verifyRequestSignature(tampered, vaultID: vaultID,
                                                      device: directoryEntry(cli: cli))
            XCTFail("tampered ciphertext must fail verification")
        } catch { /* fail closed */ }
    }

    func testRequestSignatureCoversTheEphemeralKeyAndExpiry() throws {
        // §3.11 (v2 A): the signature covers the one-time public key and
        // the expiry — change either and the signature no longer matches,
        // so a decider cannot trust the key on the row.
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let cli = try CLI()
        let (pending, _) = try makePending(cli: cli, owner: owner)

        // A swapped one-time public key must fail verification.
        let otherEphemeral = Curve25519.KeyAgreement.PrivateKey()
        var swapped = pending
        swapped.cliEphemeralPublicKey = otherEphemeral.publicKey.rawRepresentation
        do {
            try ApprovalFlows.verifyRequestSignature(swapped, vaultID: vaultID,
                                                      device: directoryEntry(cli: cli))
            XCTFail("a swapped ephemeral key must fail verification")
        } catch { /* fail closed */ }

        // A changed expiry must fail verification.
        var later = pending
        later.expiresAt = pending.expiresAt + 1000
        do {
            try ApprovalFlows.verifyRequestSignature(later, vaultID: vaultID,
                                                      device: directoryEntry(cli: cli))
            XCTFail("a changed expiry must fail verification")
        } catch { /* fail closed */ }

        // A different vault must fail verification.
        do {
            try ApprovalFlows.verifyRequestSignature(pending,
                                                      vaultID: "ffffffffffffffffffffffffffffffff",
                                                      device: directoryEntry(cli: cli))
            XCTFail("a changed vault must fail verification")
        } catch { /* fail closed */ }
    }

    func testRevokedCLICannotGetItsRequestAccepted() throws {
        // A revoked device in the signed directory → the request is
        // invalid (§3.11, v2 A).
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let cli = try CLI()
        let (pending, _) = try makePending(cli: cli, owner: owner)
        var revoked = directoryEntry(cli: cli)
        revoked.status = DeviceStatus.revoked
        do {
            try ApprovalFlows.verifyRequestSignature(pending, vaultID: vaultID, device: revoked)
            XCTFail("a revoked CLI must not pass verification")
        } catch { /* fail closed */ }
    }

    func testOneTimeWrapBindsRequestBytes() throws {
        // §8.3 step 3 / D4: 换一个请求或条目都解不出可用的密钥。
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let cli = try CLI()
        let (pending, plaintext) = try makePending(cli: cli, owner: owner)
        let itemKey = randomKey()
        let decision = try ApprovalFlows.approveDecision(vaultID: vaultID, pending: pending,
                                                         plaintext: plaintext,
                                                         itemKey: itemKey,
                                                         decisionDeviceID: ownerDeviceID,
                                                         signer: owner.signer)
        guard let enc = decision.oneTimeEnc, let wrapped = decision.oneTimeWrappedKey else {
            return XCTFail("wrap missing")
        }
        // Same wrap, different approval id → the CLI's info binding fails.
        let otherApproval = "ffffffffffffffffffffffffffffffff"
        do {
            _ = try ItemCrypto.unwrapOneTimeItemKey(
                kemName: KEMName.x25519, receiver: .x25519(cli.ephemeral),
                vaultID: vaultID, deviceID: cliDeviceID, itemID: itemID,
                approvalID: otherApproval, requestCiphertext: pending.requestCiphertext,
                enc: enc, wrappedKey: wrapped)
            XCTFail("wrap must be bound to the approval id")
        } catch { /* fail closed */ }
        // Different item id → also fails.
        do {
            _ = try ItemCrypto.unwrapOneTimeItemKey(
                kemName: KEMName.x25519, receiver: .x25519(cli.ephemeral),
                vaultID: vaultID, deviceID: cliDeviceID,
                itemID: "88887777666655554444333322221111",
                approvalID: approvalID, requestCiphertext: pending.requestCiphertext,
                enc: enc, wrappedKey: wrapped)
            XCTFail("wrap must be bound to the item id")
        } catch { /* fail closed */ }
        // Different request bytes (another request for the same item) → fails.
        let (otherPending, _) = try makePending(cli: cli, owner: owner)
        do {
            _ = try ItemCrypto.unwrapOneTimeItemKey(
                kemName: KEMName.x25519, receiver: .x25519(cli.ephemeral),
                vaultID: vaultID, deviceID: cliDeviceID, itemID: itemID,
                approvalID: approvalID, requestCiphertext: otherPending.requestCiphertext,
                enc: enc, wrappedKey: wrapped)
            XCTFail("wrap must be bound to the request bytes")
        } catch { /* fail closed */ }
    }

    func testValidatePlaintextRejectsMismatchedIds() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let cli = try CLI()
        let (pending, plaintext) = try makePending(cli: cli, owner: owner)
        try ApprovalFlows.validatePlaintext(plaintext, pending: pending)

        var mismatched = plaintext
        mismatched.itemID = "88887777666655554444333322221111"
        do {
            try ApprovalFlows.validatePlaintext(mismatched, pending: pending)
            XCTFail("mismatched item id must be rejected")
        } catch { /* fail closed */ }

        var badKEM = plaintext
        badKEM.ephemeralKEM = KEMName.p256
        do {
            try ApprovalFlows.validatePlaintext(badKEM, pending: pending)
            XCTFail("non-X25519 ephemeral must be rejected")
        } catch { /* fail closed */ }

        // The row's one-time key differs from the one inside the request
        // → rejected (§3.11, v2 A).
        var swapped = pending
        swapped.cliEphemeralPublicKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        do {
            try ApprovalFlows.validatePlaintext(plaintext, pending: swapped)
            XCTFail("a swapped ephemeral key must be rejected")
        } catch { /* fail closed */ }
    }
}
