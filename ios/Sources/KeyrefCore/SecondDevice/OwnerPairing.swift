// NEW FILE (Phase 2, design §9.4 path 2): adding a second iPhone to a live
// vault. The new phone shows a join offer (its fresh owner P-256 HPKE and
// ECDSA signing public keys); the old phone — after Face ID — signs a new
// directory revision with both owners active (PUT /v1/directory; the server
// upserts device rows from the directory records, server/api/directory.go)
// and hands the VMK to the new phone as an HPKE wrap (purpose `vmk`,
// recipient = the new owner device id). The wrap travels phone-to-phone over
// the visual channel; its AEAD tag is the authenticity verdict — only an
// owner holding the VMK could have produced a wrap this phone's key opens.
import CryptoKit
import Foundation

// MARK: - join offer (new phone → old phone QR)

/// What the NEW phone displays for the old phone to scan:
/// `keyref://join?v=1&k=<b64 P-256 hpke>&s=<b64 P-256 ecdsa>&d=<hex device id>&name=<...>&u=<origin>`.
/// The fingerprint display convention matches the CLI pair code (§9.1).
public struct JoinOffer: Equatable, Sendable {
    public var hpkeKEM: String
    public var hpkePublicKey: Data
    public var signAlg: String
    public var signPublicKey: Data
    /// The new owner's device id (32 lowercase hex) — the old phone needs it
    /// to place the directory record; the pair-session endpoints are CLI-only
    /// (server/api/pair.go pins X25519+Ed25519), so this flow carries the id
    /// in the offer instead of registering a nonce.
    public var deviceID: String
    public var label: String
    public var origin: URL

    public init(hpkeKEM: String, hpkePublicKey: Data, signAlg: String,
                signPublicKey: Data, deviceID: String, label: String, origin: URL) {
        self.hpkeKEM = hpkeKEM
        self.hpkePublicKey = hpkePublicKey
        self.signAlg = signAlg
        self.signPublicKey = signPublicKey
        self.deviceID = deviceID
        self.label = label
        self.origin = origin
    }

    public enum ParseError: Error, Equatable {
        case notKeyrefJoin
        case unsupportedVersion
        case badField(String)
        case missingField(String)
    }

    public static func parse(_ payload: String) throws -> JoinOffer {
        guard let url = URL(string: payload.trimmingCharacters(in: .whitespacesAndNewlines)),
              url.scheme == "keyref", url.host == "join",
              let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw ParseError.notKeyrefJoin
        }
        let q = comps.queryItems ?? []
        func value(_ key: String) throws -> String {
            guard let v = q.first(where: { $0.name == key })?.value, !v.isEmpty else {
                throw ParseError.missingField(key)
            }
            return v
        }
        guard try value("v") == "1" else { throw ParseError.unsupportedVersion }
        func b64(_ key: String) throws -> Data {
            guard let d = Data(base64Encoded: try value(key)) else {
                throw ParseError.badField(key)
            }
            return d
        }
        let kem = try b64("k")
        let sign = try b64("s")
        // Owner keys are always P-256 (design §9.2: Secure Enclave only).
        guard kem.count == KeyrefSizes.p256Key, kem.first == 0x04 else {
            throw ParseError.badField("k")
        }
        guard sign.count == KeyrefSizes.p256Key, sign.first == 0x04 else {
            throw ParseError.badField("s")
        }
        let deviceID = try value("d")
        guard KeyrefEncoding.isValidID(deviceID) else { throw ParseError.badField("d") }
        let origin = try value("u")
        guard let u = URL(string: origin), let scheme = u.scheme?.lowercased(),
              scheme == "https" || scheme == "http" else {
            throw ParseError.badField("u")
        }
        return JoinOffer(hpkeKEM: KEMName.p256, hpkePublicKey: kem,
                         signAlg: SignAlg.ecdsaP256, signPublicKey: sign,
                         deviceID: deviceID, label: try value("name"), origin: u)
    }

    /// Builds the QR payload (percent-encoding follows §9.1 conventions).
    public func payload() -> String {
        func enc(_ s: String) -> String {
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: "-._~")
            return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
        }
        return "keyref://join?v=1"
            + "&k=" + enc(KeyrefEncoding.base64Encode(hpkePublicKey))
            + "&s=" + enc(KeyrefEncoding.base64Encode(signPublicKey))
            + "&d=" + deviceID
            + "&name=" + enc(label)
            + "&u=" + enc(origin.absoluteString)
    }

    /// SHA-256(sign public key) first 8 bytes as `A1B2-C3D4-E5F6-7890` (§9.1).
    public var fingerprint: String {
        JoinOffer.fingerprint(of: signPublicKey)
    }

    public static func fingerprint(of signPublicKey: Data) -> String {
        let digest = Data(SHA256.hash(data: signPublicKey))
        let hex = digest.prefix(8).map { String(format: "%02X", $0) }.joined()
        var groups: [String] = []
        var i = hex.startIndex
        while i < hex.endIndex {
            let end = hex.index(i, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex
            groups.append(String(hex[i..<end]))
            i = end
        }
        return groups.joined(separator: "-")
    }
}

// MARK: - handoff (old phone → new phone QR)

/// What the OLD phone displays after the directory landed: the vault id, the
/// new owner's device id it admitted, the directory revision it signed, the
/// admitting owner's signing public key (the new phone pins it — the §6.18
/// analog), and the HPKE-wrapped VMK.
public struct JoinHandoff: Equatable, Sendable {
    public var vaultID: String
    public var newOwnerDeviceID: String
    public var directoryRevision: UInt64
    public var ownerSignPublicKey: Data
    /// HPKE wrap of the VMK: enc(65B P-256) ‖ ct‖tag, purpose `vmk`,
    /// recipient = newOwnerDeviceID.
    public var vmkWrap: Data

    public init(vaultID: String, newOwnerDeviceID: String, directoryRevision: UInt64,
                ownerSignPublicKey: Data, vmkWrap: Data) {
        self.vaultID = vaultID
        self.newOwnerDeviceID = newOwnerDeviceID
        self.directoryRevision = directoryRevision
        self.ownerSignPublicKey = ownerSignPublicKey
        self.vmkWrap = vmkWrap
    }

    public enum ParseError: Error, Equatable {
        case notKeyrefHandoff
        case unsupportedVersion
        case badField(String)
        case missingField(String)
    }

    public static func parse(_ payload: String) throws -> JoinHandoff {
        guard let url = URL(string: payload.trimmingCharacters(in: .whitespacesAndNewlines)),
              url.scheme == "keyref", url.host == "handoff",
              let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw ParseError.notKeyrefHandoff
        }
        let q = comps.queryItems ?? []
        func value(_ key: String) throws -> String {
            guard let v = q.first(where: { $0.name == key })?.value, !v.isEmpty else {
                throw ParseError.missingField(key)
            }
            return v
        }
        guard try value("v") == "1" else { throw ParseError.unsupportedVersion }
        let vaultID = try value("vault")
        guard KeyrefEncoding.isValidID(vaultID) else { throw ParseError.badField("vault") }
        let deviceID = try value("device")
        guard KeyrefEncoding.isValidID(deviceID) else { throw ParseError.badField("device") }
        guard let rev = UInt64(try value("rev")), rev >= 1 else {
            throw ParseError.badField("rev")
        }
        guard let owner = Data(base64Encoded: try value("owner")),
              owner.count == KeyrefSizes.p256Key, owner.first == 0x04 else {
            throw ParseError.badField("owner")
        }
        guard let wrap = Data(base64Encoded: try value("w")), wrap.count > KeyrefSizes.p256Key else {
            throw ParseError.badField("w")
        }
        return JoinHandoff(vaultID: vaultID, newOwnerDeviceID: deviceID,
                           directoryRevision: rev, ownerSignPublicKey: owner,
                           vmkWrap: wrap)
    }

    public func payload() -> String {
        func enc(_ s: String) -> String {
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: "-._~")
            return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
        }
        return "keyref://handoff?v=1"
            + "&vault=" + vaultID
            + "&device=" + newOwnerDeviceID
            + "&rev=" + String(directoryRevision)
            + "&owner=" + enc(KeyrefEncoding.base64Encode(ownerSignPublicKey))
            + "&w=" + enc(KeyrefEncoding.base64Encode(vmkWrap))
    }
}

// MARK: - the two phone sides

public enum OwnerPairing {
    // MARK: old phone

    /// Builds the new §3.3 directory transcript with BOTH owners active:
    /// every existing device keeps its record untouched, the new owner is
    /// appended (empty grants digest), and the revision advances by exactly
    /// one (§9.4: 服务器写入两台 owner 的签名目录，directory_revision + 1).
    /// Callers sign the returned bytes and PUT /v1/directory (§6.15).
    public static func buildJoinDirectory(vaultID: String, offer: JoinOffer,
                                          currentDirectorySigned: Data) throws
        -> (devices: [DirectoryDevice], revision: UInt64, transcript: Data) {
        try requireID("vault_id", vaultID)
        try requireID("new_device_id", offer.deviceID)
        let previous = try VaultFlows.parseVerifiedDevices(currentDirectorySigned, vaultID: vaultID)
        guard !previous.contains(where: { $0.deviceID == offer.deviceID }) else {
            throw KeyrefWireError.invalidField("device is already in the directory")
        }
        var devices: [DirectoryDevice] = previous.map {
            DirectoryDevice(deviceID: $0.deviceID, kind: $0.kind, status: $0.status,
                            hpkeKEM: $0.hpkeKEM, hpkePublicKey: $0.hpkePublicKey,
                            signAlg: $0.signAlg, signPublicKey: $0.signPublicKey,
                            renewalSignPublicKey: $0.renewalSignPublicKey,
                            grantsDigest: $0.grantsDigest,
                            receiverRole: $0.receiverRole)
        }
        devices.append(DirectoryDevice(
            deviceID: offer.deviceID, kind: DeviceKind.ios, status: DeviceStatus.active,
            hpkeKEM: offer.hpkeKEM, hpkePublicKey: offer.hpkePublicKey,
            signAlg: offer.signAlg, signPublicKey: offer.signPublicKey,
            renewalSignPublicKey: Data(), grantsDigest: emptyGrantsDigest()))
        let revision = try directoryRevision(of: currentDirectorySigned, vaultID: vaultID) + 1
        let transcript = DirectoryTranscript(vaultID: vaultID, directoryRevision: revision,
                                             devices: devices)
        return (devices, revision, try transcript.buildBytes())
    }

    /// Wraps the VMK for the new owner (purpose `vmk`, recipient = the new
    /// owner's device id). Returns enc ‖ ct for the handoff payload.
    public static func wrapVMK(vmk: Data, vaultID: String, offer: JoinOffer) throws -> Data {
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: vaultID,
                                recipientDeviceID: offer.deviceID)
        let (enc, ct) = try KeyrefHPKE.wrapKey(kemName: offer.hpkeKEM,
                                               recipientPublicKey: offer.hpkePublicKey,
                                               info: info, plaintext: vmk)
        return enc + ct
    }

    // MARK: new phone

    /// Opens the handoff's VMK wrap with the new phone's own HPKE key. The
    /// AEAD tag is the verdict: only a VMK holder could have wrapped for
    /// this exact key and device (§9.4).
    public static func unwrapHandoffVMK(_ handoff: JoinHandoff, owner: OwnerKeys) throws -> Data {
        let info = try hpkeInfo(purpose: KeyrefPurpose.vmk, vaultID: handoff.vaultID,
                                recipientDeviceID: handoff.newOwnerDeviceID)
        guard handoff.vmkWrap.count > KeyrefSizes.p256Key else {
            throw KeyrefCryptoError.invalidBlob
        }
        return try owner.unwrap(info: info,
                                enc: handoff.vmkWrap.prefix(KeyrefSizes.p256Key),
                                ct: handoff.vmkWrap.dropFirst(KeyrefSizes.p256Key))
    }

    // MARK: transcript revision reader

    /// Reads `directory_revision` from a §3.3 transcript that the caller has
    /// already verified (KEYREF1 US "directory" US vault_id US u64be).
    public static func directoryRevision(of transcript: Data, vaultID: String) throws -> UInt64 {
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
        return revision
    }

    private static func requireID(_ name: String, _ v: String) throws {
        guard KeyrefEncoding.isValidID(v) else {
            throw KeyrefWireError.invalidField("\(name) must be 32 lowercase hex characters")
        }
    }
}
