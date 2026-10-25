// Vault creation (design §9.3), recovery takeover (§8.5) and recovery
// material replacement (§8.4) — the owner flows that anchor the device
// directory. All signing goes through the OwnerKeys identity.
import CryptoKit
import Foundation

public enum VaultFlows {
    // MARK: creation (§9.3)

    public struct CreatedVault: Sendable {
        public var request: CreateVaultRequest
        /// Shown exactly once (design §15).
        public var recoveryCode: String
        public var recoverySeed: Data
        public var vmk: Data
        /// The §3.3 directory bytes that were signed and submitted.
        public var directoryTranscript: Data
    }

    /// Creates a new vault: generates the VMK, wraps it to this owner's
    /// P-256 key (stored locally, design §9.3 step 3), derives the
    /// recovery code and builds the signed revision-1 directory with only
    /// this owner device active.
    public static func createVault(owner: OwnerKeys, ownerDeviceID: String,
                                   label: String, renewalSigner: TranscriptSigner? = nil,
                                   pow: PoWSolution? = nil) throws -> CreatedVault {
        try checkID("owner_device_id", ownerDeviceID)
        guard Data(label.utf8).count <= labelMaxBytes else {
            throw KeyrefWireError.invalidField("label must be at most \(labelMaxBytes) bytes")
        }
        let vmk = randomKey()
        let (vaultID, seed, code) = RecoveryCode.generatePayload()
        let keys = try RecoveryKeys.derive(fromSeed: seed)

        // recovery_wrap = AES-256-GCM(recovery-kek, VMK) with the §3.7 AAD.
        let wrap = try BlobCrypto.sealBlob(key: keys.kek, aad: recoveryAAD(vaultID: vaultID), plaintext: vmk)
        let recSignPub = keys.signer.signPublicKey

        // Device directory revision 1: this owner only, active.
        let device = DirectoryDevice(
            deviceID: ownerDeviceID, kind: DeviceKind.ios, status: DeviceStatus.active,
            hpkeKEM: owner.kemKEMName, hpkePublicKey: owner.kemPublicKey,
            signAlg: owner.signer.signAlg, signPublicKey: owner.signPublicKey,
            renewalSignPublicKey: renewalSigner?.signPublicKey ?? Data(),
            grantsDigest: emptyGrantsDigest())
        let dir = DirectoryTranscript(vaultID: vaultID, directoryRevision: 1, devices: [device])
        let dirBytes = try dir.buildBytes()
        let signature = try owner.signer.sign(dirBytes)

        // Wrap the VMK to the owner's own HPKE key for local storage
        // (enc ‖ ct; §3.7 purpose vmk).
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: owner.kemKEMName,
                                         recipientPublicKey: owner.kemPublicKey,
                                         info: hpkeInfo(purpose: KeyrefPurpose.vmk,
                                                        vaultID: vaultID,
                                                        recipientDeviceID: ownerDeviceID),
                                         plaintext: vmk)

        let request = CreateVaultRequest(
            vaultID: vaultID,
            device: DeviceInput(
                deviceID: ownerDeviceID, kind: DeviceKind.ios,
                hpkeKEM: owner.kemKEMName, hpkePublicKey: owner.kemPublicKey,
                signAlg: owner.signer.signAlg, signPublicKey: owner.signPublicKey,
                label: label,
                renewalSignPublicKey: renewalSigner?.signPublicKey ?? Data()),
            recoveryWrap: wrap,
            recoveryKDFJSON: RecoveryKeys.defaultKDFJSON,
            recoverySignPub: recSignPub,
            directoryRevision: 1,
            directorySigned: dirBytes,
            signature: signature,
            pow: pow)
        return CreatedVault(request: request, recoveryCode: code,
                            recoverySeed: seed, vmk: vmk,
                            directoryTranscript: dirBytes)
    }

    // MARK: local VMK wrap (§9.3 step 3, §9.5)

    /// Unwraps the locally stored VMK wrap with this owner's HPKE key
    /// (the Face ID path: the enclave performs the ECDH, §9.5).
    public static func unwrapLocalVMK(owner: OwnerKeys, wrap: Data, vaultID: String,
                                      ownerDeviceID: String) throws -> Data {
        // Stored layout: enc(65) ‖ ct‖tag.
        let encLen = 65
        guard wrap.count > encLen else { throw KeyrefCryptoError.invalidBlob }
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID,
                                recipientDeviceID: ownerDeviceID)
        return try owner.unwrap(info: info, enc: wrap.prefix(encLen), ct: wrap.dropFirst(encLen))
    }

    // MARK: recovery takeover (§8.5)

    public struct TakeoverPlan: Sendable {
        public var vaultID: String
        public var vmk: Data
        public var request: RecoveryDirectoryRequest
        /// The signed takeover directory (all old devices revoked, the new
        /// owner active).
        public var directoryTranscript: Data
    }

    /// Builds the recovery takeover (§8.5): parses the recovery code,
    /// derives the keys, decrypts the VMK (AEAD tag = code verdict) and
    /// jointly signs — recovery authority + new owner — a new directory
    /// with every old device revoked and the new owner active.
    /// `previousDevices` come from the current signed directory fetched in
    /// §6.2; each keeps its key material while flipping to revoked.
    public static func planTakeover(recoveryCode: String,
                                    recoveryMaterials: RecoveryMaterialsResponse,
                                    newOwner: OwnerKeys, newOwnerDeviceID: String,
                                    label: String) throws -> TakeoverPlan {
        let parsed = try RecoveryCode.decode(recoveryCode)
        guard parsed.vaultID == recoveryMaterials.vaultID else {
            throw KeyrefWireError.invalidField("recovery code vault_id does not match the fetched materials")
        }
        let keys = try RecoveryKeys.derive(fromSeed: parsed.seed)
        // The AEAD tag is the "recovery code correct" verdict (§7.3).
        let vmk = try RecoveryKeys.unwrapVMK(keys: keys,
                                             recoveryWrap: recoveryMaterials.recoveryWrap,
                                             vaultID: parsed.vaultID)

        // Old devices: revoke them all; keep their grants digest as stored
        // (their grants are dropped server-side).
        var devices: [DirectoryDevice] = []
        if let previous = try? parseDirectoryForTakeover(recoveryMaterials.directorySigned,
                                                         vaultID: parsed.vaultID) {
            devices = previous.map {
                DirectoryDevice(deviceID: $0.deviceID, kind: $0.kind,
                                status: DeviceStatus.revoked,
                                hpkeKEM: $0.hpkeKEM, hpkePublicKey: $0.hpkePublicKey,
                                signAlg: $0.signAlg, signPublicKey: $0.signPublicKey,
                                renewalSignPublicKey: $0.renewalSignPublicKey,
                                grantsDigest: $0.grantsDigest)
            }
        }
        devices.append(DirectoryDevice(
            deviceID: newOwnerDeviceID, kind: DeviceKind.ios, status: DeviceStatus.active,
            hpkeKEM: newOwner.kemKEMName, hpkePublicKey: newOwner.kemPublicKey,
            signAlg: newOwner.signer.signAlg, signPublicKey: newOwner.signPublicKey,
            grantsDigest: emptyGrantsDigest()))

        let dir = DirectoryTranscript(vaultID: parsed.vaultID,
                                      directoryRevision: recoveryMaterials.directoryRevision + 1,
                                      devices: devices)
        let dirBytes = try dir.buildBytes()
        let recSig = try keys.signer.sign(dirBytes)
        let ownerSig = try newOwner.signer.sign(dirBytes)
        let request = RecoveryDirectoryRequest(
            vaultID: parsed.vaultID,
            directoryRevision: recoveryMaterials.directoryRevision + 1,
            directorySigned: dirBytes,
            recoverySignature: recSig,
            ownerSignature: ownerSig)
        return TakeoverPlan(vaultID: parsed.vaultID, vmk: vmk,
                            request: request, directoryTranscript: dirBytes)
    }

    // MARK: replace recovery material (§8.4, §6.4)

    /// Builds the PUT /v1/vault/recovery request for a fresh recovery
    /// code (VMK rewrap layer only; item ciphertexts stay untouched —
    /// AAD does not bind the revision, §8.4).
    public static func replaceRecoveryMaterial(vaultID: String, vmk: Data,
                                               owner: OwnerKeys) throws -> (request: PutVaultRecoveryRequest, code: String, seed: Data) {
        var freshSeed = Data(count: RecoveryCode.seedLength)
        _ = freshSeed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, RecoveryCode.seedLength, $0.baseAddress!) }
        let keys = try RecoveryKeys.derive(fromSeed: freshSeed)
        let wrap = try BlobCrypto.sealBlob(key: keys.kek, aad: recoveryAAD(vaultID: vaultID), plaintext: vmk)
        let tb = try buildVaultRecoveryTranscript(vaultID: vaultID, recoveryWrap: wrap,
                                                  recoveryKDFJSON: RecoveryKeys.defaultKDFJSON,
                                                  recoverySignPub: keys.signer.signPublicKey)
        let signature = try owner.signer.sign(tb)
        return (PutVaultRecoveryRequest(recoveryWrap: wrap,
                                        recoveryKDFJSON: RecoveryKeys.defaultKDFJSON,
                                        recoverySignPub: keys.signer.signPublicKey,
                                        signature: signature),
                RecoveryCode.encode(payload: try KeyrefEncoding.hexDecode(vaultID) + freshSeed),
                freshSeed)
    }

    private static func checkID(_ name: String, _ v: String) throws {
        guard KeyrefEncoding.isValidID(v) else {
            throw KeyrefWireError.invalidField("\(name) must be 32 lowercase hex characters")
        }
    }
}

// MARK: - takeover directory parsing
//
// Like the sync engine's revocation lookup, this reads an already
// server-delivered directory transcript (its signature is verified by the
// caller against recovery_sign_pub / the pinned owner key chain). It
// reconstructs the device records structurally: every field is
// NUL-terminated except the record-final 32-byte grants digest, and the
// two variable-length public keys have known lengths once their alg
// strings are read.

struct ParsedDirectoryDevice: Equatable, Sendable {
    var deviceID: String
    var kind: String
    var status: String
    var hpkeKEM: String
    var hpkePublicKey: Data
    var signAlg: String
    var signPublicKey: Data
    var renewalSignPublicKey: Data
    var grantsDigest: Data
}

func parseDirectoryForTakeover(_ transcript: Data, vaultID: String) throws -> [ParsedDirectoryDevice] {
    let sep = KeyrefEncoding.fieldSeparator
    let prefix = Data("KEYREF1".utf8) + [sep] + Data("directory".utf8) + [sep]
    guard transcript.starts(with: prefix) else {
        throw KeyrefWireError.invalidField("not a directory transcript")
    }
    var body = transcript.dropFirst(prefix.count)
    let head = Data(vaultID.utf8) + [sep]
    guard body.starts(with: head) else {
        throw KeyrefWireError.invalidField("directory vault_id mismatch")
    }
    body = body.dropFirst(head.count)
    guard body.count >= 9 else {
        throw KeyrefWireError.invalidField("directory too short")
    }
    let revision = try KeyrefEncoding.readU64BE(body, offset: 0)
    guard revision >= 1 else {
        throw KeyrefWireError.invalidField("directory_revision must be >= 1")
    }
    body = body.dropFirst(9)  // u64be + separator

    var out: [ParsedDirectoryDevice] = []
    while !body.isEmpty {
        func takeString() throws -> String {
            guard let idx = body.firstIndex(of: sep), idx > body.startIndex || true else {
                throw KeyrefWireError.invalidField("unterminated directory field")
            }
            // An empty field (e.g. renewal key) is a lone separator.
            let s = String(decoding: body[body.startIndex..<idx], as: UTF8.self)
            body = body.dropFirst(body.distance(from: body.startIndex, to: idx) + 1)
            return s
        }
        func takeFixed(_ n: Int) throws -> Data {
            guard body.count >= n + 1, body[body.startIndex + n] == sep else {
                throw KeyrefWireError.invalidField("short directory binary field")
            }
            let d = Data(body.prefix(n))
            body = body.dropFirst(n + 1)
            return d
        }
        let deviceID = try takeString()
        let kind = try takeString()
        let status = try takeString()
        let kem = try takeString()
        guard kem == KEMName.x25519 || kem == KEMName.p256 else {
            throw KeyrefWireError.invalidField("bad hpke_kem in directory")
        }
        let hpkePub = try takeFixed(kem == KEMName.x25519 ? KeyrefSizes.x25519Key : KeyrefSizes.p256Key)
        let alg = try takeString()
        guard alg == SignAlg.ed25519 || alg == SignAlg.ecdsaP256 else {
            throw KeyrefWireError.invalidField("bad sign_alg in directory")
        }
        let signPub = try takeFixed(alg == SignAlg.ed25519 ? KeyrefSizes.ed25519Key : KeyrefSizes.p256Key)
        // renewal_sign_public_key: empty or 32 bytes, NUL-terminated.
        var renewal = Data()
        if body.first != sep {
            guard body.count >= KeyrefSizes.ed25519Key + 1,
                  body[body.startIndex + KeyrefSizes.ed25519Key] == sep else {
                throw KeyrefWireError.invalidField("bad renewal key in directory")
            }
            renewal = Data(body.prefix(KeyrefSizes.ed25519Key))
            body = body.dropFirst(KeyrefSizes.ed25519Key + 1)
        } else {
            body = body.dropFirst(1)
        }
        guard body.count >= KeyrefSizes.digest else {
            throw KeyrefWireError.invalidField("directory record truncated")
        }
        let digest = Data(body.prefix(KeyrefSizes.digest))
        body = body.dropFirst(KeyrefSizes.digest)
        out.append(ParsedDirectoryDevice(deviceID: deviceID, kind: kind, status: status,
                                         hpkeKEM: kem, hpkePublicKey: hpkePub,
                                         signAlg: alg, signPublicKey: signPub,
                                         renewalSignPublicKey: renewal,
                                         grantsDigest: digest))
        // Records are joined by a single NUL (§3.3); consume it before the
        // next record. A missing separator where more bytes remain is a
        // malformed transcript.
        if !body.isEmpty {
            guard body.first == sep else {
                throw KeyrefWireError.invalidField("directory record separator missing")
            }
            body = body.dropFirst(1)
        }
    }
    return out
}
