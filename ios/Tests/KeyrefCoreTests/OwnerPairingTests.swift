// Second-iPhone pairing tests (design §9.4 path 2): the join directory
// carries both owners active at revision + 1 and verifies under the
// admitting owner's key; the VMK wrap round-trips only for the new owner's
// key; the QR payload codecs round-trip.
import CryptoKit
import XCTest

@testable import KeyrefCore

final class OwnerPairingTests: XCTestCase {
    let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

    private func seedDirectory(owner: OwnerKeys, deviceID: String, revision: UInt64 = 1) throws -> Data {
        let device = DirectoryDevice(deviceID: deviceID, kind: DeviceKind.ios,
                                     status: DeviceStatus.active,
                                     hpkeKEM: owner.kemKEMName,
                                     hpkePublicKey: owner.kemPublicKey,
                                     signAlg: owner.signer.signAlg,
                                     signPublicKey: owner.signPublicKey,
                                     grantsDigest: emptyGrantsDigest())
        let transcript = DirectoryTranscript(vaultID: vaultID, directoryRevision: revision,
                                             devices: [device])
        return try transcript.buildBytes()
    }

    func testJoinDirectoryAddsSecondOwnerAtNextRevision() throws {
        let oldOwner = try OwnerKeys.generate(preferEnclave: false)
        let newOwner = try OwnerKeys.generate(preferEnclave: false)
        let oldDeviceID = KeyrefEncoding.newID()
        let signed = try seedDirectory(owner: oldOwner, deviceID: oldDeviceID)

        let offer = JoinOffer(hpkeKEM: newOwner.kemKEMName,
                              hpkePublicKey: newOwner.kemPublicKey,
                              signAlg: newOwner.signer.signAlg,
                              signPublicKey: newOwner.signPublicKey,
                              deviceID: KeyrefEncoding.newID(),
                              label: "新 iPhone",
                              origin: URL(string: "https://sync.keyref.app")!)
        let join = try OwnerPairing.buildJoinDirectory(vaultID: vaultID, offer: offer,
                                                       currentDirectorySigned: signed)
        // directory_revision + 1（§9.4）。
        XCTAssertEqual(join.revision, 2)
        XCTAssertEqual(join.devices.count, 2)
        // 目录里两台 owner（§9.4：两台 owner 都进入签名过的设备目录）。
        let owners = join.devices.filter { $0.kind == DeviceKind.ios && $0.status == DeviceStatus.active }
        XCTAssertEqual(owners.count, 2)
        XCTAssertTrue(owners.contains { $0.deviceID == offer.deviceID })
        XCTAssertTrue(owners.contains { $0.deviceID == oldDeviceID })
        // 新 owner 的记录：P-256、空 grants digest。
        let newRecord = join.devices.first { $0.deviceID == offer.deviceID }!
        XCTAssertEqual(newRecord.hpkeKEM, KEMName.p256)
        XCTAssertEqual(newRecord.grantsDigest, emptyGrantsDigest())

        // 誊本签名由旧 owner 验证通过（§6.15：上一版目录内的 owner 公钥）。
        try verifyOwnerSignature(transcript: join.transcript,
                                 signature: try oldOwner.signer.sign(join.transcript),
                                 ownerSignPublicKey: oldOwner.signPublicKey)
        // 旧记录原样保留（状态、renewal key、digest 都不动）。
        XCTAssertEqual(join.devices.first { $0.deviceID == oldDeviceID }!.status, DeviceStatus.active)
    }

    func testJoinDirectoryRejectsDuplicateDevice() throws {
        let oldOwner = try OwnerKeys.generate(preferEnclave: false)
        let deviceID = KeyrefEncoding.newID()
        let signed = try seedDirectory(owner: oldOwner, deviceID: deviceID)
        let offer = JoinOffer(hpkeKEM: oldOwner.kemKEMName,
                              hpkePublicKey: oldOwner.kemPublicKey,
                              signAlg: oldOwner.signer.signAlg,
                              signPublicKey: oldOwner.signPublicKey,
                              deviceID: deviceID,  // 已在目录里
                              label: "dup",
                              origin: URL(string: "https://sync.keyref.app")!)
        do {
            _ = try OwnerPairing.buildJoinDirectory(vaultID: vaultID, offer: offer,
                                                    currentDirectorySigned: signed)
            XCTFail("duplicate device must be rejected")
        } catch { /* fail closed */ }
    }

    func testVMKWrapRoundTripsOnlyForNewOwner() throws {
        let newOwner = try OwnerKeys.generate(preferEnclave: false)
        let stranger = try OwnerKeys.generate(preferEnclave: false)
        let offer = JoinOffer(hpkeKEM: newOwner.kemKEMName,
                              hpkePublicKey: newOwner.kemPublicKey,
                              signAlg: newOwner.signer.signAlg,
                              signPublicKey: newOwner.signPublicKey,
                              deviceID: KeyrefEncoding.newID(),
                              label: "新 iPhone",
                              origin: URL(string: "https://sync.keyref.app")!)
        let vmk = randomKey()
        let wrap = try OwnerPairing.wrapVMK(vmk: vmk, vaultID: vaultID, offer: offer)
        let handoff = JoinHandoff(vaultID: vaultID, newOwnerDeviceID: offer.deviceID,
                                  directoryRevision: 2,
                                  ownerSignPublicKey: Data([0x04]) + Data(repeating: 9, count: 64),
                                  vmkWrap: wrap)
        // 新手机解出 VMK（AEAD tag = 判真伪）。
        let opened = try OwnerPairing.unwrapHandoffVMK(handoff, owner: newOwner)
        XCTAssertEqual(opened, vmk)
        // 别人的手机解不开。
        do {
            _ = try OwnerPairing.unwrapHandoffVMK(handoff, owner: stranger)
            XCTFail("another owner must not unwrap the handoff")
        } catch { /* fail closed */ }
        // device id 绑定：改了 recipient 也解不开。
        let wrongBinding = JoinHandoff(vaultID: vaultID,
                                       newOwnerDeviceID: KeyrefEncoding.newID(),
                                       directoryRevision: 2,
                                       ownerSignPublicKey: handoff.ownerSignPublicKey,
                                       vmkWrap: wrap)
        do {
            _ = try OwnerPairing.unwrapHandoffVMK(wrongBinding, owner: newOwner)
            XCTFail("wrong recipient binding must fail")
        } catch { /* fail closed */ }
    }

    func testOfferAndHandoffPayloadCodecs() throws {
        let offer = JoinOffer(hpkeKEM: KEMName.p256,
                              hpkePublicKey: Data([0x04]) + Data(repeating: 3, count: 64),
                              signAlg: SignAlg.ecdsaP256,
                              signPublicKey: Data([0x04]) + Data(repeating: 4, count: 64),
                              deviceID: KeyrefEncoding.newID(),
                              label: "新 iPhone 2",
                              origin: URL(string: "https://keys.example.com")!)
        let parsed = try JoinOffer.parse(offer.payload())
        XCTAssertEqual(parsed, offer)
        XCTAssertEqual(parsed.fingerprint, offer.fingerprint)
        XCTAssertEqual(offer.fingerprint.count, 19)

        let handoff = JoinHandoff(vaultID: vaultID,
                                  newOwnerDeviceID: KeyrefEncoding.newID(),
                                  directoryRevision: 3,
                                  ownerSignPublicKey: Data([0x04]) + Data(repeating: 5, count: 64),
                                  vmkWrap: Data(repeating: 6, count: 129))
        XCTAssertEqual(try JoinHandoff.parse(handoff.payload()), handoff)

        // Bad payloads fail closed.
        for bad in ["keyref://pair?v=1", "https://example.com", "keyref://join?v=2",
                    "keyref://join?v=1&k=AAAA&s=AAAA&d=zz&name=x&u=https://a.example"] {
            do {
                _ = try JoinOffer.parse(bad)
                XCTFail("bad offer payload must fail: \(bad)")
            } catch { /* expected */ }
        }
        do {
            _ = try JoinHandoff.parse("keyref://join?v=1")
            XCTFail("handoff parser must reject a join payload")
        } catch { /* expected */ }
    }

    func testDirectoryRevisionReader() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let signed = try seedDirectory(owner: owner, deviceID: KeyrefEncoding.newID(),
                                       revision: 7)
        XCTAssertEqual(try OwnerPairing.directoryRevision(of: signed, vaultID: vaultID), 7)
        do {
            _ = try OwnerPairing.directoryRevision(of: Data("junk".utf8), vaultID: vaultID)
            XCTFail("non-transcript bytes must be rejected")
        } catch { /* fail closed */ }
    }
}
