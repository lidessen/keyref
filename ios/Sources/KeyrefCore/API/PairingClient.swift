// Pairing client (docs/protocol.md §6.16–§6.18, §9) and session client
// (§6.7): the iOS role scans the CLI's QR payload and completes the pair;
// register/poll are implemented for completeness so the same client can
// drive either side in tests. Session renewal re-runs the two-step
// challenge flow (design §8.2).
import CryptoKit
import Foundation

// MARK: - QR payload (§9.1)

public struct PairingOffer: Equatable, Sendable {
    public var hpkeKEM: String
    public var hpkePublicKey: Data
    public var signAlg: String
    public var signPublicKey: Data
    /// 16-byte nonce as 32 lowercase hex characters.
    public var nonce: String
    /// UTF-8 label, at most 32 bytes.
    public var label: String
    /// Server origin (https).
    public var origin: URL

    enum ParseError: Error, Equatable {
        case notKeyrefPair
        case unsupportedVersion
        case missingField(String)
        case badField(String)
    }

    /// Parses `keyref://pair?v=1&k=<b64>&s=<b64>&n=<hex32>&name=<...>&u=<origin>`.
    /// Values are percent-encoded per RFC 3986; `k`/`s` are standard
    /// Base64 after decoding (§9.1: percent-decode first, then base64).
    public static func parse(_ payload: String) throws -> PairingOffer {
        guard let url = URL(string: payload.trimmingCharacters(in: .whitespacesAndNewlines)),
              url.scheme == "keyref", url.host == "pair" else {
            throw ParseError.notKeyrefPair
        }
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw ParseError.notKeyrefPair
        }
        let q = comps.queryItems ?? []
        func value(_ key: String) throws -> String {
            guard let v = q.first(where: { $0.name == key })?.value, !v.isEmpty else {
                throw ParseError.missingField(key)
            }
            return v
        }
        // URLComponents already percent-decodes query values.
        guard try value("v") == "1" else { throw ParseError.unsupportedVersion }
        func b64(_ key: String) throws -> Data {
            guard let d = Data(base64Encoded: try value(key)) else {
                throw ParseError.badField(key)
            }
            return d
        }
        let nonce = try value("n")
        guard KeyrefEncoding.isValidID(nonce) else { throw ParseError.badField("n") }
        let origin = try value("u")
        guard let u = URL(string: origin), let scheme = u.scheme?.lowercased(),
              scheme == "https" || scheme == "http" else {
            throw ParseError.badField("u")
        }
        let kem = try b64("k")
        let sign = try b64("s")
        let hpkeKEM = kem.count == KeyrefSizes.x25519Key ? KEMName.x25519 : KEMName.p256
        let signAlg = sign.count == KeyrefSizes.ed25519Key ? SignAlg.ed25519 : SignAlg.ecdsaP256
        return PairingOffer(hpkeKEM: hpkeKEM, hpkePublicKey: kem,
                            signAlg: signAlg, signPublicKey: sign,
                            nonce: nonce, label: try value("name"), origin: u)
    }

    /// Builds the QR payload (used by CLI simulations and tests).
    public func payload() -> String {
        func enc(_ s: String) -> String {
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: "-._~")
            return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
        }
        return "keyref://pair?v=1"
            + "&k=" + enc(KeyrefEncoding.base64Encode(hpkePublicKey))
            + "&s=" + enc(KeyrefEncoding.base64Encode(signPublicKey))
            + "&n=" + nonce
            + "&name=" + enc(label)
            + "&u=" + enc(origin.absoluteString)
    }

    /// Human-verifiable fingerprint: first 8 bytes of SHA-256(sign public
    /// key), shown as uppercase 4-hex-digit groups (§9.1).
    public var fingerprint: String {
        let digest = Data(SHA256.hash(data: signPublicKey))
        let bytes = digest.prefix(8)
        let hex = bytes.map { String(format: "%02X", $0) }.joined()
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

// MARK: - pairing client

/// Drives the pairing endpoints. The iOS owner constructs the pair
/// transcript (§3.4), signs it with the owner key and calls `complete`;
/// `register`/`pollStatus` exist so the full CLI dance can be simulated
/// (register → poll status → complete).
public struct PairingClient: Sendable {
    public let api: APIClient

    public init(api: APIClient) {
        self.api = api
    }

    /// POST /v1/pair/register (CLI side, §6.16).
    public func register(nonce: Data, proposedName: String, signer: TranscriptSigner,
                         hpkeKEM: String, hpkePublicKey: Data) async throws -> PairRegisterResponse {
        let tb = try buildPairRegisterTranscript(nonce: nonce, proposedName: proposedName)
        let sig = try signer.sign(tb)
        return try await api.pairRegister(PairRegisterRequest(
            nonce: KeyrefEncoding.hexEncode(nonce),
            hpkeKEM: hpkeKEM, hpkePublicKey: hpkePublicKey,
            signAlg: signer.signAlg, signPublicKey: signer.signPublicKey,
            proposedName: proposedName, signature: sig))
    }

    /// GET /v1/pair/status?nonce= (CLI side polls, §6.18).
    public func pollStatus(nonce: String) async throws -> PairStatusResponse {
        try await api.pairStatus(nonce: nonce)
    }

    /// Verifies the owner signature in a complete pair status (§6.18)
    /// against the offer this device registered, and pins the owner key.
    public func verifyCompleteStatus(_ status: PairStatusResponse, offer: PairingOffer) throws {
        guard status.status == "complete",
              let ownerPub = status.ownerSignPublicKey,
              let sig = status.pairingSignature,
              let vaultID = status.vaultID,
              let deviceID = status.deviceID else {
            throw KeyrefWireError.badSignature
        }
        let t = PairTranscript(
            vaultID: vaultID, ownerSignPublicKey: ownerPub,
            nonce: offer.nonce, deviceID: deviceID,
            hpkeKEM: offer.hpkeKEM, hpkePublicKey: offer.hpkePublicKey,
            signAlg: offer.signAlg, signPublicKey: offer.signPublicKey,
            label: offer.label,
            grants: (status.grants ?? []).map { $0.transcript(vaultID: vaultID) })
        try verifyOwnerSignature(transcript: try t.buildBytes(), signature: sig,
                                 ownerSignPublicKey: ownerPub)
    }

    /// POST /v1/pair/complete (owner side, §6.17): builds and signs the
    /// §3.4 pair transcript over the admitted device and its initial
    /// grants. The grant set is empty until the human selects items
    /// (design §15).
    public func complete(vaultID: String, nonce: String, device: DeviceInput,
                         grants: [GrantData], ownerSigner: TranscriptSigner) async throws {
        let t = PairTranscript(
            vaultID: vaultID, ownerSignPublicKey: ownerSigner.signPublicKey,
            nonce: nonce, deviceID: device.deviceID,
            hpkeKEM: device.hpkeKEM, hpkePublicKey: device.hpkePublicKey,
            signAlg: device.signAlg, signPublicKey: device.signPublicKey,
            label: device.label,
            grants: grants.map { $0.transcript(vaultID: vaultID) })
        let sig = try ownerSigner.sign(try t.buildBytes())
        try await api.pairComplete(PairCompleteRequest(
            nonce: nonce, device: device, grants: grants, signature: sig))
    }
}

// MARK: - session client (§6.7)

public struct SessionClient: Sendable {
    public let api: APIClient

    public init(api: APIClient) {
        self.api = api
    }

    /// Runs the two-step challenge flow with this device's signing key and
    /// returns the bearer session (12 h validity, §8.2).
    public func start(deviceID: String, signer: TranscriptSigner) async throws -> SessionResponse {
        let challenge = try await api.requestSessionChallenge(deviceID: deviceID)
        let tb = try buildSessionTranscript(deviceID: deviceID, challenge: challenge.challenge)
        let sig = try signer.sign(tb)
        return try await api.completeSession(deviceID: deviceID,
                                             challenge: challenge.challenge, signature: sig)
    }

    /// Renewal is the same two-step path (design §8.2: re-sign challenge).
    public func renew(deviceID: String, signer: TranscriptSigner) async throws -> SessionResponse {
        try await start(deviceID: deviceID, signer: signer)
    }
}
