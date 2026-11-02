// The §3.9 message envelope (design v0.8 §14.3, protocol D15): the owner
// must open what a source sealed, and every binding in the AES AAD / HPKE
// info must fail closed. These tests are the cross-language gate for the
// envelope format — the Android collector and this reader have no other
// shared fixture.
import XCTest
@testable import KeyrefCore

final class MessageEnvelopeTests: XCTestCase {
    private let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    private let sourceID = "aaaabbbbccccddddeeeeffff00001111"

    private func envelope(owner: OwnerKeys, ownerDeviceID: String,
                          sourceDeviceID: String = "aaaabbbbccccddddeeeeffff00001111",
                          vault: String? = nil,
                          plaintext: MessagePlaintext = MessagePlaintext(
                            sender: "10086", body: "【XX银行】您的验证码 482913，5 分钟内有效。",
                            sim: "备用卡1", receivedAt: 1_760_000_000_000))
    throws -> Data {
        let vaultID = vault ?? self.vaultID
        let messageKey = randomKey()
        defer { var k = messageKey; wipe(&k) }
        let record = try MessageEnvelope.sealKey(vaultID: vaultID,
                                                 recipientDeviceID: ownerDeviceID,
                                                 recipientPublicKey: owner.kemPublicKey,
                                                 messageKey: messageKey)
        var out = Data([1])
        out.append(try MessageEnvelope.encode(record))
        let aad = try messageAAD(vaultID: vaultID, sourceDeviceID: sourceDeviceID)
        out.append(try BlobCrypto.sealBlob(key: messageKey, aad: aad,
                                          plaintext: try WireJSON.encoder.encode(plaintext)))
        return out
    }

    func testOwnerOpensSealedMessage() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let ownerID = "11112222333344445555666677778888"
        let env = try envelope(owner: owner, ownerDeviceID: ownerID)

        let opened = try MessageEnvelope.open(envelope: env, vaultID: vaultID,
                                              sourceDeviceID: sourceID,
                                              ownerDeviceID: ownerID, owner: owner)
        XCTAssertEqual(opened.v, 1)
        XCTAssertEqual(opened.sender, "10086")
        XCTAssertEqual(opened.body, "【XX银行】您的验证码 482913，5 分钟内有效。")
        XCTAssertEqual(opened.sim, "备用卡1")
        XCTAssertEqual(opened.receivedAt, 1_760_000_000_000)
    }

    /// The AES段 binds the reporting (source) device: a different source id
    /// in the row must not open.
    func testWrongSourceDeviceFailsClosed() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let ownerID = "11112222333344445555666677778888"
        let env = try envelope(owner: owner, ownerDeviceID: ownerID)

        XCTAssertThrowsError(try MessageEnvelope.open(
            envelope: env, vaultID: vaultID,
            sourceDeviceID: "bbbbccccddddeeeeffff000011112222",
            ownerDeviceID: ownerID, owner: owner))
    }

    func testWrongVaultFailsClosed() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let ownerID = "11112222333344445555666677778888"
        let env = try envelope(owner: owner, ownerDeviceID: ownerID)

        XCTAssertThrowsError(try MessageEnvelope.open(
            envelope: env, vaultID: "ffffffffffffffffffffffffffffffff",
            sourceDeviceID: sourceID, ownerDeviceID: ownerID, owner: owner))
    }

    /// A device that is not a recipient of this envelope gets nothing —
    /// the design's "joined later" gap, healed by the 24 h TTL (§14.3).
    func testNonRecipientCannotOpen() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let stranger = try OwnerKeys.generate(preferEnclave: false)
        let ownerID = "11112222333344445555666677778888"
        let env = try envelope(owner: owner, ownerDeviceID: ownerID)

        XCTAssertThrowsError(try MessageEnvelope.open(
            envelope: env, vaultID: vaultID, sourceDeviceID: sourceID,
            ownerDeviceID: ownerID, owner: stranger))
    }

    /// Every wrap is 48 bytes (HPKE ct of a 32-byte key) and records carry
    /// the recipient's device id explicitly (D15).
    func testRecordShape() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let ownerID = "11112222333344445555666677778888"
        let env = try envelope(owner: owner, ownerDeviceID: ownerID)

        let (records, body) = try MessageEnvelope.split(env)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].deviceID, ownerID)
        XCTAssertEqual(records[0].wrapped.count, MessageEnvelope.wrappedKeySize)
        XCTAssertEqual(records[0].enc.count, KeyrefSizes.p256Key)
        XCTAssertGreaterThan(body.count, 12 + 16)
    }

    /// The one-time message wrap binds message id, approval id and the
    /// request digest — a decision for another message must not open (§3.7).
    func testOneTimeMessageInfoBindsMessage() throws {
        let requestCiphertext = Data(repeating: 0x5a, count: 112)
        let a = try oneTimeMessageKeyInfo(recipientDeviceID: "11112222333344445555666677778888",
                                          vaultID: vaultID,
                                          messageID: "12121212121212121212121212121212",
                                          approvalID: "34343434343434343434343434343434",
                                          requestCiphertext: requestCiphertext)
        let b = try oneTimeMessageKeyInfo(recipientDeviceID: "11112222333344445555666677778888",
                                          vaultID: vaultID,
                                          messageID: "56565656565656565656565656565656",
                                          approvalID: "34343434343434343434343434343434",
                                          requestCiphertext: requestCiphertext)
        XCTAssertNotEqual(a, b)
        XCTAssertTrue(a.starts(with: Data("keyref v1".utf8)))
        XCTAssertTrue(String(decoding: a, as: UTF8.self).contains("one-time-message-key"))
    }
}
