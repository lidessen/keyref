// OwnerKeys persistence tests (KeyStore-backed) and the vault flows:
// creation (§9.3), local VMK unwrap (§9.5), recovery takeover (§8.5) and
// recovery-material replacement (§8.4).
import CryptoKit
import XCTest

@testable import KeyrefCore

final class VaultFlowsTests: XCTestCase {
    private let ownerDeviceID = "99998888777766665555444433332222"
    private let cliDeviceID = "aaaabbbbccccddddeeeeffff00001111"

    // MARK: persistence

    func testOwnerKeysPersistAndLoadSoftware() throws {
        let store = InMemoryKeyStore()
        let owner = try OwnerKeys.generate(preferEnclave: false)
        try owner.persist(to: store, biometryRequired: false)
        let loaded = try OwnerKeys.load(from: store, enclaveBacked: false)
        XCTAssertNotNil(loaded)
        XCTAssertEqual(loaded!.signPublicKey, owner.signPublicKey)
        XCTAssertEqual(loaded!.kemPublicKey, owner.kemPublicKey)
        XCTAssertFalse(loaded!.isEnclaveBacked)

        // The loaded identity can unwrap what the original sealed.
        let vmk = randomKey()
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: ownerDeviceID,
                                recipientDeviceID: ownerDeviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: KEMName.p256,
                                               recipientPublicKey: owner.kemPublicKey,
                                               info: info, plaintext: vmk)
        XCTAssertEqual(try loaded!.unwrap(info: info, enc: enc, ct: ct), vmk)
    }

    func testOwnerKeysPersistAndLoadEnclave() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }
        let store = InMemoryKeyStore()
        let owner = try OwnerKeys.generate(preferEnclave: true, biometryRequired: false)
        XCTAssertTrue(owner.isEnclaveBacked)
        try owner.persist(to: store, biometryRequired: false)
        let loaded = try OwnerKeys.load(from: store, enclaveBacked: true)
        XCTAssertNotNil(loaded)
        XCTAssertTrue(loaded!.isEnclaveBacked)
        XCTAssertEqual(loaded!.signPublicKey, owner.signPublicKey)
        XCTAssertEqual(loaded!.kemPublicKey, owner.kemPublicKey)
        // Enclave sign + verify through the reloaded identity.
        let bytes = try buildSessionTranscript(deviceID: ownerDeviceID, challenge: Data(repeating: 1, count: 32))
        try verifyOwnerSignature(transcript: bytes, signature: try loaded!.signer.sign(bytes),
                                 ownerSignPublicKey: loaded!.signPublicKey)
    }

    // MARK: vault creation (§9.3)

    func testCreateVault() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let renewal = try Ed25519Signer()
        let created = try VaultFlows.createVault(owner: owner, ownerDeviceID: ownerDeviceID,
                                                 label: "iPhone", renewalSigner: renewal)
        let req = created.request
        XCTAssertTrue(KeyrefEncoding.isValidID(req.vaultID))
        XCTAssertEqual(req.directoryRevision, 1)
        XCTAssertEqual(req.recoveryKDFJSON, RecoveryKeys.defaultKDFJSON)

        // The signed directory contains exactly this owner, active.
        let dir = DirectoryTranscript(vaultID: req.vaultID, directoryRevision: 1, devices: [
            DirectoryDevice(deviceID: ownerDeviceID, kind: DeviceKind.ios, status: DeviceStatus.active,
                            hpkeKEM: owner.kemKEMName, hpkePublicKey: owner.kemPublicKey,
                            signAlg: owner.signer.signAlg, signPublicKey: owner.signPublicKey,
                            renewalSignPublicKey: renewal.signPublicKey,
                            grantsDigest: emptyGrantsDigest()),
        ])
        XCTAssertEqual(try dir.buildBytes(), req.directorySigned)
        try verifyOwnerSignature(transcript: req.directorySigned, signature: req.signature,
                                 ownerSignPublicKey: owner.signPublicKey)

        // The recovery code parses to the same vault and re-derives the VMK.
        let parsed = try RecoveryCode.decode(created.recoveryCode)
        XCTAssertEqual(parsed.vaultID, req.vaultID)
        let keys = try RecoveryKeys.derive(fromSeed: parsed.seed)
        XCTAssertEqual(keys.signer.signPublicKey, req.recoverySignPub)
        XCTAssertEqual(try RecoveryKeys.unwrapVMK(keys: keys, recoveryWrap: req.recoveryWrap,
                                                  vaultID: req.vaultID), created.vmk)

        // The local VMK wrap opens with the owner key (§9.3 step 3).
        // VaultFlows.createVault stores enc‖ct under slot .vmkWrap shape:
        // recreate it via unwrapLocalVMK by re-wrapping.
        let wrapped = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                             recipientPublicKey: owner.kemPublicKey,
                                             info: try hpkeInfo(purpose: KeyrefPurpose.vmk,
                                                                vaultID: req.vaultID,
                                                                recipientDeviceID: ownerDeviceID),
                                             plaintext: created.vmk)
        let local = try VaultFlows.unwrapLocalVMK(owner: owner, wrap: wrapped.enc + wrapped.ct,
                                                  vaultID: req.vaultID, ownerDeviceID: ownerDeviceID)
        XCTAssertEqual(local, created.vmk)
    }

    // MARK: recovery takeover (§8.5)

    func testPlanTakeover() throws {
        // Old owner creates the vault; a CLI device exists and gets grants.
        let oldOwner = try OwnerKeys.generate(preferEnclave: false)
        let created = try VaultFlows.createVault(owner: oldOwner, ownerDeviceID: ownerDeviceID,
                                                 label: "iPhone")
        let vaultID = created.request.vaultID
        let x = try HPKEKeys.generateX25519()
        let cliSigner = try Ed25519Signer()

        // Current signed directory: old owner + CLI, revision 4.
        let viewGrant = GrantTranscript(vaultID: vaultID, deviceID: cliDeviceID, itemID: "deadbeefdeadbeefdeadbeefdeadbeef",
                                        kind: GrantKind.view, revision: 1, expiresAt: 0,
                                        hpkeEnc: Data(repeating: 1, count: 32), wrappedKey: Data(repeating: 2, count: 48))
        let dir = DirectoryTranscript(vaultID: vaultID, directoryRevision: 4, devices: [
            DirectoryDevice(deviceID: cliDeviceID, kind: DeviceKind.cli, status: DeviceStatus.active,
                            hpkeKEM: KEMName.x25519, hpkePublicKey: x.publicKey,
                            signAlg: SignAlg.ed25519, signPublicKey: cliSigner.signPublicKey,
                            grantsDigest: try grantsDigest([viewGrant])),
            DirectoryDevice(deviceID: ownerDeviceID, kind: DeviceKind.ios, status: DeviceStatus.active,
                            hpkeKEM: oldOwner.kemKEMName, hpkePublicKey: oldOwner.kemPublicKey,
                            signAlg: oldOwner.signer.signAlg, signPublicKey: oldOwner.signPublicKey,
                            grantsDigest: emptyGrantsDigest()),
        ])
        let dirBytes = try dir.buildBytes()
        let materials = RecoveryMaterialsResponse(
            vaultID: vaultID, recoveryWrap: created.request.recoveryWrap,
            recoveryKDFJSON: created.request.recoveryKDFJSON,
            recoverySignPub: created.request.recoverySignPub,
            directoryRevision: 4, directorySigned: dirBytes,
            directorySignature: try oldOwner.signer.sign(dirBytes))

        // New owner plans the takeover with the recovery code.
        let newOwner = try OwnerKeys.generate(preferEnclave: false)
        let newDeviceID = "11223344556677881122334455667788"
        let plan = try VaultFlows.planTakeover(recoveryCode: created.recoveryCode,
                                               recoveryMaterials: materials,
                                               newOwner: newOwner, newOwnerDeviceID: newDeviceID,
                                               label: "new-phone")
        XCTAssertEqual(plan.vaultID, vaultID)
        XCTAssertEqual(plan.vmk, created.vmk)  // the AEAD tag proved the code
        XCTAssertEqual(plan.request.directoryRevision, 5)

        // The takeover directory: every old device revoked, new owner active.
        let records = try parseDirectoryForTakeover(plan.directoryTranscript, vaultID: vaultID)
        XCTAssertEqual(records.count, 3)
        for r in records where r.deviceID != newDeviceID {
            XCTAssertEqual(r.status, DeviceStatus.revoked, r.deviceID)
        }
        let newRecord = records.first { $0.deviceID == newDeviceID }
        XCTAssertEqual(newRecord?.status, DeviceStatus.active)
        XCTAssertEqual(newRecord?.signPublicKey, newOwner.signPublicKey)
        XCTAssertEqual(newRecord?.grantsDigest, emptyGrantsDigest())
        // Revoked devices keep their material; the CLI keeps its (now
        // stale) grants digest.
        let cliRecord = records.first { $0.deviceID == cliDeviceID }
        XCTAssertEqual(cliRecord?.hpkePublicKey, x.publicKey)
        XCTAssertEqual(cliRecord?.grantsDigest, try grantsDigest([viewGrant]))

        // Both signatures verify: recovery authority + new owner.
        try verifyRecoverySignature(transcript: plan.directoryTranscript,
                                    signature: plan.request.recoverySignature,
                                    recoverySignPub: created.request.recoverySignPub)
        try verifyOwnerSignature(transcript: plan.directoryTranscript,
                                 signature: plan.request.ownerSignature,
                                 ownerSignPublicKey: newOwner.signPublicKey)

        // A wrong recovery code cannot decrypt the VMK (fails before any
        // directory work).
        var broken = created.recoveryCode
        let symbols = Array(broken)
        broken = String(symbols.dropLast()) + (symbols.last == "A" ? "B" : "A")
        XCTAssertThrowsError(try VaultFlows.planTakeover(recoveryCode: broken,
                                                         recoveryMaterials: materials,
                                                         newOwner: newOwner,
                                                         newOwnerDeviceID: newDeviceID,
                                                         label: "new-phone"))
    }

    // MARK: replace recovery material (§8.4)

    func testReplaceRecoveryMaterial() throws {
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let created = try VaultFlows.createVault(owner: owner, ownerDeviceID: ownerDeviceID,
                                                 label: "iPhone")
        let (req, newCode, newSeed) = try VaultFlows.replaceRecoveryMaterial(
            vaultID: created.request.vaultID, vmk: created.vmk, owner: owner)
        XCTAssertNotEqual(newSeed, created.recoverySeed)
        // New wrap opens with the new code to the same VMK.
        let keys = try RecoveryKeys.derive(fromSeed: newSeed)
        XCTAssertEqual(try RecoveryKeys.unwrapVMK(keys: keys, recoveryWrap: req.recoveryWrap,
                                                  vaultID: created.request.vaultID), created.vmk)
        XCTAssertEqual(keys.signer.signPublicKey, req.recoverySignPub)
        // Signature covers the §3.6 vault-recovery transcript.
        let tb = try buildVaultRecoveryTranscript(vaultID: created.request.vaultID,
                                                  recoveryWrap: req.recoveryWrap,
                                                  recoveryKDFJSON: req.recoveryKDFJSON,
                                                  recoverySignPub: req.recoverySignPub)
        try verifyOwnerSignature(transcript: tb, signature: req.signature,
                                 ownerSignPublicKey: owner.signPublicKey)
        // The new code parses to the same vault.
        let parsed = try RecoveryCode.decode(newCode)
        XCTAssertEqual(parsed.vaultID, created.request.vaultID)
    }
}
