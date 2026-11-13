// LiveBackend integration tests over MockURLProtocol: the paths the
// MemoryBackend fakes cannot cover — chiefly that pairing PUBLISHES a
// signed directory containing the new CLI device (design §9.1: device
// public keys are trusted exclusively from the signed directory).
import XCTest

@testable import KeyrefCore
@testable import KeyrefUI

final class PairingDirectoryTests: XCTestCase {
    private let vaultID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

    /// completePairing must, after pair/complete succeeds, re-sign the
    /// directory with the CLI appended (revision+1) and PUT /v1/directory.
    /// Without this the paired CLI is invisible to loadDevices, grant
    /// editing, revocation and approval validation.
    @MainActor
    func testCompletePairingPublishesSignedDirectory() async throws {
        UITestMockURLProtocol.reset()
        let owner = try OwnerKeys.generate(preferEnclave: false)
        let ownDeviceID = KeyrefEncoding.newID()
        let cliOffer = try PairingOffer.make(
            hpkeKEM: KEMName.x25519, hpkePublicKey: Data(repeating: 0x11, count: 32),
            signAlg: SignAlg.ed25519, signPublicKey: Data(repeating: 0x22, count: 32),
            nonce: KeyrefEncoding.newID(), label: "build-bot",
            origin: URL(string: "https://sync.example")!,
            confirmSecret: Data(repeating: 0x33, count: KeyrefSizes.pairConfirmKey))

        // The vault's signed directory as the backend would have bootstrapped it.
        let dirDevice = DirectoryDevice(
            deviceID: ownDeviceID, kind: DeviceKind.ios, status: DeviceStatus.active,
            hpkeKEM: owner.kemKEMName, hpkePublicKey: owner.kemPublicKey,
            signAlg: owner.signer.signAlg, signPublicKey: owner.signPublicKey,
            renewalSignPublicKey: Data(), grantsDigest: emptyGrantsDigest())
        let dirBytes = try DirectoryTranscript(
            vaultID: vaultID, directoryRevision: 1, devices: [dirDevice]).buildBytes()
        let dirSig = try owner.signer.sign(dirBytes)

        UITestMockURLProtocol.handler = { request, _ in
            let p = request.url?.path ?? ""
            if p.hasSuffix("/v1/pair/complete") {
                return (204, Data())
            }
            if p.hasSuffix("/v1/directory") {
                return (200, Data(#"{"directory_revision":2}"#.utf8))
            }
            if p.hasSuffix("/v1/sync") {
                return (200, Data(#"{"cursor":0,"has_more":false,"changes":[]}"#.utf8))
            }
            if p.hasSuffix("/v1/grants/self") {
                return (200, Data("{}".utf8))
            }
            return (404, Data("{}".utf8))
        }

        let keyStore = InMemoryKeyStore()
        let stateStore = UIStateStore()
        let backend = LiveBackend(
            keyStore: keyStore, stateStore: stateStore,
            origin: URL(string: "https://sync.example")!,
            urlSession: UITestMockURLProtocol.makeSession())

        // Seed the backend into the unlocked-with-vault state the pairing
        // flow requires (the same state uploadCreatedVault leaves behind).
        try stateStore.setVaultID(vaultID)
        try stateStore.setOwnDeviceID(ownDeviceID)
        try stateStore.setPinnedOwnerKey(owner.signPublicKey)
        try stateStore.storeDirectory(DirectoryData.make(
            directoryRevision: 1, signed: dirBytes, signature: dirSig))
        // VMK unwrap needs the local wrap; grant wrapping needs the VMK.
        let vmk = Data(repeating: 0x33, count: 32)
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID,
                                recipientDeviceID: ownDeviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                               recipientPublicKey: owner.kemPublicKey,
                                               info: info, plaintext: vmk)
        try keyStore.store(.vaultID, Data(vaultID.utf8))
        try keyStore.store(.ownDeviceID, Data(ownDeviceID.utf8))
        try keyStore.store(.vmkWrap, enc + ct)
        try owner.persist(to: keyStore, biometryRequired: false)
        // Adopt the in-memory state without the biometrics roundtrip.
        backend.adoptForTesting(vaultID: vaultID, owner: owner, vmk: vmk,
                                ownDeviceID: ownDeviceID)

        try await backend.completePairing(offer: cliOffer, deviceLabel: "build-bot",
                                          selections: [])

        // Find the PUT /v1/directory call and verify its contents.
        let calls = UITestMockURLProtocol.recorded().filter { $0.request.url?.path.hasSuffix("/v1/directory") == true }
        XCTAssertEqual(calls.count, 1, "completePairing must publish exactly one directory")
        guard let call = calls.first else { return }
        let body = try JSONDecoder().decode(PutDirectoryRequest.self, from: call.body)
        XCTAssertEqual(body.directoryRevision, 2, "directory revision must advance by one")
        let devices = try VaultFlows.parseVerifiedDevices(body.directorySigned, vaultID: vaultID)
        XCTAssertEqual(devices.count, 2, "directory must contain owner + new CLI")
        XCTAssertTrue(devices.contains { $0.deviceID != ownDeviceID && $0.kind == DeviceKind.cli },
                      "the CLI device must be in the signed directory")
        XCTAssertTrue(devices.contains { $0.deviceID == ownDeviceID && $0.status == DeviceStatus.active })
        // The signature must verify under the owner key (server-side rule).
        try verifyOwnerSignature(transcript: body.directorySigned, signature: body.signature,
                                 ownerSignPublicKey: owner.signPublicKey)
    }
}
