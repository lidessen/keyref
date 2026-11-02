// NEW FILE (added for the KeyrefUI layer, not a modification of existing
// files): public read-only access to the devices recorded in an
// already-signature-verified directory transcript. The sync engine and
// VaultFlows only need status lookups internally (§8.4); the UI additionally
// needs each device's label, public keys and fingerprint material to render
// the device list, drive revoke-with-rotation (§8.4) and re-wrap item keys
// to the remaining devices. Parsing mirrors `parseDirectoryForTakeover`
// (VaultFlows.swift) and is equally restricted in trust: callers must have
// verified `directory_signature` over these bytes first.
import CryptoKit
import Foundation

/// Public snapshot of one device row inside a directory transcript.
public struct KeyrefDirectoryDevice: Equatable, Sendable {
    public var deviceID: String
    public var kind: String
    public var status: String
    public var hpkeKEM: String
    public var hpkePublicKey: Data
    public var signAlg: String
    public var signPublicKey: Data
    public var renewalSignPublicKey: Data
    public var grantsDigest: Data
    /// SMS-inbox role (design v0.8 §14.4): 0 none, 1 primary, 2 inbox.
    public var receiverRole: UInt8

    public init(deviceID: String, kind: String, status: String,
                hpkeKEM: String, hpkePublicKey: Data,
                signAlg: String, signPublicKey: Data,
                renewalSignPublicKey: Data, grantsDigest: Data,
                receiverRole: UInt8 = ReceiverRole.none) {
        self.deviceID = deviceID
        self.kind = kind
        self.status = status
        self.hpkeKEM = hpkeKEM
        self.hpkePublicKey = hpkePublicKey
        self.signAlg = signAlg
        self.signPublicKey = signPublicKey
        self.renewalSignPublicKey = renewalSignPublicKey
        self.grantsDigest = grantsDigest
        self.receiverRole = receiverRole
    }

    /// SHA-256(sign public key) first 8 bytes as `A1B2-C3D4-E5F6-7890` (§9.1).
    public var fingerprint: String {
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

public extension VaultFlows {
    /// Parses the device records of a directory transcript. The transcript
    /// must already be signature-verified (protocol §1.5/D3: transcripts are
    /// write-only; this reader trusts the caller's verification).
    static func parseVerifiedDevices(_ transcript: Data, vaultID: String) throws -> [KeyrefDirectoryDevice] {
        try parseDirectoryForTakeover(transcript, vaultID: vaultID).map {
            KeyrefDirectoryDevice(deviceID: $0.deviceID, kind: $0.kind, status: $0.status,
                                  hpkeKEM: $0.hpkeKEM, hpkePublicKey: $0.hpkePublicKey,
                                  signAlg: $0.signAlg, signPublicKey: $0.signPublicKey,
                                  renewalSignPublicKey: $0.renewalSignPublicKey,
                                  grantsDigest: $0.grantsDigest,
                                  receiverRole: $0.receiverRole)
        }
    }
}
