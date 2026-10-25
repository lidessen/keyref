// Unit tests for transcript builders, verification and entity ids
// (docs/protocol.md §3, §8.2). The byte-level contract is anchored by the
// cross-language vectors; these tests cover the Swift-side structure,
// validation rules and roundtrips.
import CryptoKit
import XCTest

@testable import KeyrefCore

final class TranscriptTests: XCTestCase {
    private let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    private let deviceID = "99998888777766665555444433332222"

    private func ownerSigner() throws -> SoftwareP256Signer {
        SoftwareP256Signer(privateKey: P256.Signing.PrivateKey())
    }

    // MARK: structural roundtrips

    func testItemTranscriptRoundtripAndSign() throws {
        let signer = try ownerSigner()
        let t = ItemTranscript(vaultID: vaultID, itemID: deviceID, revision: 3,
                               metaCiphertext: Data([1, 2, 3]), secretCiphertext: Data([4]),
                               vaultWrappedMetaKey: Data(repeating: 9, count: 48),
                               vaultWrappedItemKey: Data(),  // binary fields may contain/omit anything
                               writerDeviceID: deviceID)
        let bytes = try t.buildBytes()
        // Prefix and separators.
        XCTAssertEqual(bytes.prefix(7), Data("KEYREF1".utf8))
        XCTAssertEqual(bytes[bytes.startIndex + 7], 0x00)
        // Signature verifies over exactly these bytes.
        let sig = try signer.sign(bytes)
        try verifyOwnerSignature(transcript: bytes, signature: sig,
                                 ownerSignPublicKey: signer.signPublicKey)
        // Wrong bytes fail.
        var tampered = bytes
        tampered[tampered.startIndex + 10] ^= 0x01
        XCTAssertThrowsError(try verifyOwnerSignature(transcript: tampered, signature: sig,
                                                      ownerSignPublicKey: signer.signPublicKey))
    }

    func testTombstoneTranscriptHasEmptyCiphertexts() throws {
        let t = ItemTranscript.tombstone(vaultID: vaultID, itemID: deviceID,
                                         revision: 5, writerDeviceID: deviceID)
        let bytes = try t.buildBytes()
        XCTAssertTrue(t.metaCiphertext.isEmpty && t.secretCiphertext.isEmpty)
        XCTAssertTrue(t.vaultWrappedMetaKey.isEmpty && t.vaultWrappedItemKey.isEmpty)
        // Signing works on the deletion form too.
        let signer = try ownerSigner()
        try verifyOwnerSignature(transcript: bytes, signature: try signer.sign(bytes),
                                 ownerSignPublicKey: signer.signPublicKey)
    }

    func testGrantTranscriptDeletionForm() throws {
        let full = GrantTranscript(vaultID: vaultID, deviceID: deviceID, itemID: deviceID,
                                   kind: GrantKind.use, revision: 1, expiresAt: 12345,
                                   hpkeEnc: Data(repeating: 7, count: 32), wrappedKey: Data(repeating: 8, count: 48))
        XCTAssertThrowsError(try GrantTranscript(vaultID: vaultID, deviceID: deviceID, itemID: deviceID,
                                                 kind: GrantKind.use, revision: 1, expiresAt: 0,
                                                 hpkeEnc: Data(repeating: 7, count: 32), wrappedKey: Data()).buildBytes(),
                             "half-empty crypto fields are rejected")
        let del = GrantTranscript.deletion(vaultID: vaultID, deviceID: deviceID, itemID: deviceID,
                                           kind: GrantKind.use, revision: 2)
        let bytes = try del.buildBytes()
        XCTAssertTrue(bytes.starts(with: Data("KEYREF1\u{0}grant\u{0}".utf8)))
    }

    // MARK: validation rules

    func testValidationRules() throws {
        // Non-hex / short ids.
        XCTAssertThrowsError(try ItemTranscript(vaultID: "xyz", itemID: deviceID, revision: 1,
                                                metaCiphertext: Data(), secretCiphertext: Data(),
                                                vaultWrappedMetaKey: Data(), vaultWrappedItemKey: Data(),
                                                writerDeviceID: deviceID).buildBytes())
        // Revision 0 rejected.
        XCTAssertThrowsError(try ItemTranscript(vaultID: vaultID, itemID: deviceID, revision: 0,
                                                metaCiphertext: Data(), secretCiphertext: Data(),
                                                vaultWrappedMetaKey: Data(), vaultWrappedItemKey: Data(),
                                                writerDeviceID: deviceID).buildBytes())
        // Bad grant kind.
        XCTAssertThrowsError(try GrantTranscript(vaultID: vaultID, deviceID: deviceID, itemID: deviceID,
                                                 kind: "admin", revision: 1, expiresAt: 0,
                                                 hpkeEnc: Data(), wrappedKey: Data()).buildBytes())
        // Bad label length (>32 bytes).
        XCTAssertThrowsError(try PairTranscript(vaultID: vaultID, ownerSignPublicKey: Data(repeating: 4, count: 65),
                                                nonce: deviceID, deviceID: deviceID,
                                                hpkeKEM: KEMName.x25519, hpkePublicKey: Data(repeating: 5, count: 32),
                                                signAlg: SignAlg.ed25519, signPublicKey: Data(repeating: 6, count: 32),
                                                label: String(repeating: "x", count: 33),
                                                grants: []).buildBytes())
        // Bad owner key length (the builder checks length + point prefix;
        // curve membership is enforced at verification time).
        XCTAssertThrowsError(try PairTranscript(vaultID: vaultID, ownerSignPublicKey: Data(repeating: 4, count: 64),
                                                nonce: deviceID, deviceID: deviceID,
                                                hpkeKEM: KEMName.x25519, hpkePublicKey: Data(repeating: 5, count: 32),
                                                signAlg: SignAlg.ed25519, signPublicKey: Data(repeating: 6, count: 32),
                                                label: "ok", grants: []).buildBytes())
    }

    func testDirectorySortingAndDuplicateDetection() throws {
        let a = DirectoryDevice(deviceID: "aaaabbbbccccddddeeeeffff00001111", kind: DeviceKind.cli,
                                status: DeviceStatus.active, hpkeKEM: KEMName.x25519,
                                hpkePublicKey: Data(repeating: 1, count: 32),
                                signAlg: SignAlg.ed25519, signPublicKey: Data(repeating: 2, count: 32),
                                grantsDigest: emptyGrantsDigest())
        let b = DirectoryDevice(deviceID: "99998888777766665555444433332222", kind: DeviceKind.ios,
                                status: DeviceStatus.active, hpkeKEM: KEMName.p256,
                                hpkePublicKey: Data(repeating: 3, count: 65),
                                signAlg: SignAlg.ecdsaP256, signPublicKey: Data(repeating: 4, count: 65),
                                renewalSignPublicKey: Data(repeating: 5, count: 32),
                                grantsDigest: emptyGrantsDigest())
        // Input order must not matter (records sort by device_id).
        let one = try DirectoryTranscript(vaultID: vaultID, directoryRevision: 2, devices: [b, a]).buildBytes()
        let two = try DirectoryTranscript(vaultID: vaultID, directoryRevision: 2, devices: [a, b]).buildBytes()
        XCTAssertEqual(one, two)
        // Duplicates rejected.
        XCTAssertThrowsError(try DirectoryTranscript(vaultID: vaultID, directoryRevision: 2,
                                                     devices: [a, a]).buildBytes())
    }

    // MARK: grants digest

    func testGrantsDigestOrdering() throws {
        func grant(_ kind: String, _ itemID: String) -> GrantTranscript {
            GrantTranscript(vaultID: vaultID, deviceID: deviceID, itemID: itemID,
                            kind: kind, revision: 1, expiresAt: 0, hpkeEnc: Data(), wrappedKey: Data())
        }
        let itemA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let itemB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        // Same item: "use" (u=0x75) sorts before "view" (v=0x76).
        XCTAssertEqual(try grantsDigest([grant("view", itemA), grant("use", itemA)]),
                       try grantsDigest([grant("use", itemA), grant("view", itemA)]))
        // Different grant sets digest differently.
        XCTAssertNotEqual(try grantsDigest([grant("use", itemA), grant("use", itemB)]),
                          try grantsDigest([grant("use", itemA), grant("view", itemA)]))
        // Empty set = SHA-256("").
        XCTAssertEqual(try grantsDigest([]), emptyGrantsDigest())
        XCTAssertEqual(emptyGrantsDigest(),
                       Data(SHA256.hash(data: Data())))
    }

    // MARK: entity ids (§8.2)

    func testEntityIDs() throws {
        XCTAssertEqual(try EntityID.item(deviceID), "item:\(deviceID)")
        XCTAssertEqual(try EntityID.grant(deviceID: deviceID, itemID: deviceID, kind: "use"),
                       "grant:\(deviceID):\(deviceID):use")
        XCTAssertEqual(try EntityID.device(deviceID), "device:\(deviceID)")
        XCTAssertEqual(try EntityID.directory(vaultID), "directory:\(vaultID)")
        XCTAssertEqual(try EntityID.approval(vaultID), "approval:\(vaultID)")

        let (entity, comps) = try EntityID.parse("grant:\(deviceID):\(deviceID):view")
        XCTAssertEqual(entity, "grant")
        XCTAssertEqual(comps, [deviceID, deviceID, "view"])
        XCTAssertThrowsError(try EntityID.parse("weird:\(deviceID)"))
        XCTAssertThrowsError(try EntityID.parse("item:nothex"))
        XCTAssertThrowsError(try EntityID.item("UPPERCASE UPPERCA ff00"))
    }

    // MARK: verification helpers

    func testEd25519Verification() throws {
        let signer = try Ed25519Signer()
        let bytes = try buildSessionTranscript(deviceID: deviceID, challenge: Data(repeating: 3, count: 32))
        let sig = try signer.sign(bytes)
        try verifyCLISignature(transcript: bytes, signature: sig, cliSignPublicKey: signer.signPublicKey)
        var wrong = sig
        wrong[wrong.startIndex] ^= 0x01
        XCTAssertThrowsError(try verifyCLISignature(transcript: bytes, signature: wrong,
                                                    cliSignPublicKey: signer.signPublicKey))
        // Wrong key length fails closed with invalidField.
        XCTAssertThrowsError(try verifyCLISignature(transcript: bytes, signature: sig, cliSignPublicKey: Data([1])))
    }

    func testU64BE() throws {
        var d = Data()
        KeyrefEncoding.appendU64BE(0x0102030405060708, to: &d)
        XCTAssertEqual(Array(d), [1, 2, 3, 4, 5, 6, 7, 8])
        XCTAssertEqual(try KeyrefEncoding.readU64BE(d, offset: 0), 0x0102030405060708)
        XCTAssertEqual(try KeyrefEncoding.readU64BE(KeyrefEncoding.u64BEBytes(UInt64.max), offset: 0), UInt64.max)
    }

    func testHexRoundtripAndValidation() throws {
        let d = Data([0x00, 0x0f, 0xff, 0x1f])
        XCTAssertEqual(KeyrefEncoding.hexEncode(d), "000fff1f")
        XCTAssertEqual(try KeyrefEncoding.hexDecode("000fff1f"), d)
        XCTAssertThrowsError(try KeyrefEncoding.hexDecode("abc"))
        XCTAssertThrowsError(try KeyrefEncoding.hexDecode("zz"))
        XCTAssertTrue(KeyrefEncoding.isValidID(deviceID))
        XCTAssertFalse(KeyrefEncoding.isValidID("aaaabbbbccccddddeeeeffff00001111".uppercased()))
        XCTAssertFalse(KeyrefEncoding.isValidID(deviceID + "0"))
    }
}
