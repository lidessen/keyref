// Signature construction and verification (docs/protocol.md §1.4).
//
// Owner devices sign with ECDSA P-256 (SHA-256 first, ASN.1 DER) — inside
// the Secure Enclave in production, software keys as the documented
// fallback (design §9.2). CLI devices and the recovery signing authority
// sign with Ed25519 (raw 64-byte signatures). Verification accepts both
// algorithms keyed by the sign_alg identifier.
import CryptoKit
import Foundation
import Security

// MARK: - signing identities

/// Something able to sign transcript bytes.
public protocol TranscriptSigner: Sendable {
    /// sign_alg identifier ("ed25519" | "ecdsa-p256").
    var signAlg: String { get }
    /// Encoded public key (Ed25519 raw 32B; ECDSA P-256 SEC1 uncompressed 65B).
    var signPublicKey: Data { get }
    /// Signs transcript; ECDSA P-256 returns ASN.1 DER.
    func sign(_ transcript: Data) throws -> Data
}

/// Ed25519 signer for CLI-device simulations, the renewal key (§8.4) and
/// the recovery signing authority (§8.5).
public struct Ed25519Signer: TranscriptSigner {
    public let signAlg: String
    public let signPublicKey: Data
    private let privateKey: Curve25519.Signing.PrivateKey

    public init(privateKey: Curve25519.Signing.PrivateKey) {
        self.privateKey = privateKey
        self.signAlg = SignAlg.ed25519
        self.signPublicKey = privateKey.publicKey.rawRepresentation
    }

    /// From a 32-byte seed (e.g. the recovery-sign derivation, §3.8).
    public init(seed: Data) throws {
        try self.init(privateKey: Curve25519.Signing.PrivateKey(rawRepresentation: seed))
    }

    public init() throws {
        try self.init(privateKey: Curve25519.Signing.PrivateKey())
    }

    public func sign(_ transcript: Data) throws -> Data {
        try privateKey.signature(for: transcript)
    }
}

/// Software ECDSA P-256 signer (tests, and the documented fallback path).
public struct SoftwareP256Signer: TranscriptSigner {
    public let signAlg: String
    public let signPublicKey: Data
    let privateKey: P256.Signing.PrivateKey

    public init(privateKey: P256.Signing.PrivateKey) {
        self.privateKey = privateKey
        self.signAlg = SignAlg.ecdsaP256
        self.signPublicKey = privateKey.publicKey.x963Representation
    }

    /// From a 32-byte raw private scalar (vector fixtures).
    public init(rawScalar: Data) throws {
        try self.init(privateKey: P256.Signing.PrivateKey(rawRepresentation: rawScalar))
    }

    public func sign(_ transcript: Data) throws -> Data {
        try privateKey.signature(for: transcript).derRepresentation
    }
}

/// Secure Enclave ECDSA P-256 signer (design §9.2). The private key never
/// leaves the enclave; only the persistent dataRepresentation is stored.
public struct EnclaveP256Signer: TranscriptSigner {
    public let signAlg: String
    public let signPublicKey: Data
    public let dataRepresentation: Data
    private let privateKey: SecureEnclave.P256.Signing.PrivateKey

    public init(privateKey: SecureEnclave.P256.Signing.PrivateKey) {
        self.privateKey = privateKey
        self.signAlg = SignAlg.ecdsaP256
        self.signPublicKey = privateKey.publicKey.x963Representation
        self.dataRepresentation = privateKey.dataRepresentation
    }

    /// Rebuilds the enclave key from its persistent representation (the
    /// access-control policy is baked into the dataRepresentation).
    public init(dataRepresentation: Data) throws {
        try self.init(privateKey: SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation))
    }

    public func sign(_ transcript: Data) throws -> Data {
        try privateKey.signature(for: transcript).derRepresentation
    }
}

// MARK: - verification

/// Verifies a signature over transcript bytes under the given algorithm
/// identifier and encoded public key (protocol §1.4). Throws
/// `KeyrefWireError.badSignature` when verification fails; a returned
/// (non-throwing) call means the signature covers exactly these bytes.
public func verifyDeviceSignature(transcript: Data, signature: Data,
                                  signAlg: String, publicKey: Data) throws {
    switch signAlg {
    case SignAlg.ed25519:
        guard publicKey.count == KeyrefSizes.ed25519Key else {
            throw KeyrefWireError.invalidField("ed25519 public key must be \(KeyrefSizes.ed25519Key) bytes")
        }
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey),
              key.isValidSignature(signature, for: transcript) else {
            throw KeyrefWireError.badSignature
        }
    case SignAlg.ecdsaP256:
        guard publicKey.count == KeyrefSizes.p256Key, publicKey.first == 0x04 else {
            throw KeyrefWireError.invalidField("P-256 public key must be a \(KeyrefSizes.p256Key)-byte uncompressed point")
        }
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              key.isValidSignature(sig, for: transcript) else {
            // A malformed DER signature or a wrong key both fail closed.
            throw KeyrefWireError.badSignature
        }
    default:
        throw KeyrefWireError.invalidField("unknown sign_alg \(signAlg)")
    }
}

/// Verifies an owner (ECDSA P-256) signature over a transcript.
public func verifyOwnerSignature(transcript: Data, signature: Data, ownerSignPublicKey: Data) throws {
    try verifyDeviceSignature(transcript: transcript, signature: signature,
                              signAlg: SignAlg.ecdsaP256, publicKey: ownerSignPublicKey)
}

/// Verifies a CLI-device (Ed25519) signature.
public func verifyCLISignature(transcript: Data, signature: Data, cliSignPublicKey: Data) throws {
    try verifyDeviceSignature(transcript: transcript, signature: signature,
                              signAlg: SignAlg.ed25519, publicKey: cliSignPublicKey)
}

/// Verifies a recovery-authority (Ed25519, derived from the recovery code,
/// §3.8) signature; used only to re-anchor the directory during takeover.
public func verifyRecoverySignature(transcript: Data, signature: Data, recoverySignPub: Data) throws {
    try verifyDeviceSignature(transcript: transcript, signature: signature,
                              signAlg: SignAlg.ed25519, publicKey: recoverySignPub)
}
