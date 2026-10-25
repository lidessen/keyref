// HPKE key wrapping, RFC 9180 base mode (docs/protocol.md §1.4, §1.5).
//
// Dependency decision (probed on this toolchain): the system CryptoKit
// ships HPKE on exactly the package's deployment targets (iOS 17 /
// macOS 14) with DHKEM P-256 (0x10) and X25519 (0x20), HKDF-SHA256 and
// AES-256-GCM — the same fixed suite as the Go reference
// (cloudflare/circl). The swift-crypto SwiftPM package re-exports the
// system CryptoKit on Apple platforms and adds nothing here, so the core
// layer carries no third-party dependency. Crucially, only the system
// framework conforms SecureEnclave.P256.KeyAgreement.PrivateKey to
// HPKEDiffieHellmanPrivateKey, which is the design §9.2 "衔接": VMK and
// approval wraps are opened inside the enclave without the private key
// ever leaving it.
//
// Public-key encodings follow protocol §1.4: X25519 raw 32 bytes;
// P-256 SEC1 uncompressed 65 bytes. HPKE ciphertexts are ct ‖ tag with an
// empty AAD; the KEM encapsulation is carried alongside.
import CryptoKit
import Foundation
import Security

/// A recipient key for HPKE unwrap: software X25519 / P-256 or the
/// Secure Enclave P-256 agreement key.
public enum HPKEReceiverKey: Sendable {
    case x25519(Curve25519.KeyAgreement.PrivateKey)
    case p256(P256.KeyAgreement.PrivateKey)
    case p256Enclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
}

/// Keyref's HPKE facade over CryptoKit's RFC 9180 implementation.
public enum KeyrefHPKE {
    /// Fixed RFC 9180 Base suite: DHKEM + HKDF-SHA256 + AES-256-GCM.
    private static func suite(_ kem: CryptoKit.HPKE.KEM) -> CryptoKit.HPKE.Ciphersuite {
        CryptoKit.HPKE.Ciphersuite(kem: kem, kdf: .HKDF_SHA256, aead: .AES_GCM_256)
    }

    private static func ciphersuite(kemName: String) throws -> CryptoKit.HPKE.Ciphersuite {
        switch kemName {
        case KEMName.x25519: return suite(.Curve25519_HKDF_SHA256)
        case KEMName.p256: return suite(.P256_HKDF_SHA256)
        default: throw KeyrefWireError.invalidField("unknown hpke_kem \(kemName)")
        }
    }

    /// Encoded public key length for a KEM name (§1.4).
    public static func publicKeySize(kemName: String) throws -> Int {
        switch kemName {
        case KEMName.x25519: return KeyrefSizes.x25519Key
        case KEMName.p256: return KeyrefSizes.p256Key
        default: throw KeyrefWireError.invalidField("unknown hpke_kem \(kemName)")
        }
    }

    // MARK: seal (sender)

    /// Seals a key (or any plaintext) to the recipient's encoded public key
    /// with HPKE base mode. Returns the KEM encapsulation (32 bytes X25519 /
    /// 65 bytes P-256 SEC1) and the ciphertext ct ‖ tag. The HPKE AAD is
    /// always empty; all binding lives in info (protocol §1.5, §3.7).
    public static func wrapKey(kemName: String, recipientPublicKey: Data,
                               info: Data, plaintext: Data) throws -> (enc: Data, ct: Data) {
        let cs = try ciphersuite(kemName: kemName)
        do {
            var sender: CryptoKit.HPKE.Sender
            switch kemName {
            case KEMName.x25519:
                let pk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
                sender = try CryptoKit.HPKE.Sender(recipientKey: pk, ciphersuite: cs, info: info)
            case KEMName.p256:
                let pk = try P256.KeyAgreement.PublicKey(x963Representation: recipientPublicKey)
                sender = try CryptoKit.HPKE.Sender(recipientKey: pk, ciphersuite: cs, info: info)
            default:
                throw KeyrefWireError.invalidField("unknown hpke_kem \(kemName)")
            }
            let ct = try sender.seal(plaintext)
            return (sender.encapsulatedKey, ct)
        } catch let e as KeyrefWireError {
            throw e
        } catch {
            throw KeyrefCryptoError.hpkeFailure
        }
    }

    // MARK: open (receiver)

    /// Opens an envelope produced by `wrapKey` with a software key.
    public static func unwrapKey(kemName: String, privateKey: Data,
                                 info: Data, enc: Data, ct: Data) throws -> Data {
        let cs = try ciphersuite(kemName: kemName)
        do {
            var recipient: CryptoKit.HPKE.Recipient
            switch kemName {
            case KEMName.x25519:
                let sk = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
                recipient = try CryptoKit.HPKE.Recipient(privateKey: sk, ciphersuite: cs, info: info, encapsulatedKey: enc)
            case KEMName.p256:
                let sk = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
                recipient = try CryptoKit.HPKE.Recipient(privateKey: sk, ciphersuite: cs, info: info, encapsulatedKey: enc)
            default:
                throw KeyrefWireError.invalidField("unknown hpke_kem \(kemName)")
            }
            return try recipient.open(ct)
        } catch let e as KeyrefWireError {
            throw e
        } catch {
            // Wrong key, wrong info (including the one-time binding of
            // approval wraps) and corrupt ciphertexts all fail closed.
            throw KeyrefCryptoError.hpkeFailure
        }
    }

    /// Opens an envelope with the given receiver key (overload for the
    /// Secure Enclave path, design §9.2).
    public static func unwrapKey(kemName: String, receiver: HPKEReceiverKey,
                                 info: Data, enc: Data, ct: Data) throws -> Data {
        let cs = try ciphersuite(kemName: kemName)
        do {
            var recipient: CryptoKit.HPKE.Recipient
            switch (kemName, receiver) {
            case (KEMName.x25519, .x25519(let sk)):
                recipient = try CryptoKit.HPKE.Recipient(privateKey: sk, ciphersuite: cs, info: info, encapsulatedKey: enc)
            case (KEMName.p256, .p256(let sk)):
                recipient = try CryptoKit.HPKE.Recipient(privateKey: sk, ciphersuite: cs, info: info, encapsulatedKey: enc)
            case (KEMName.p256, .p256Enclave(let sk)):
                recipient = try CryptoKit.HPKE.Recipient(privateKey: sk, ciphersuite: cs, info: info, encapsulatedKey: enc)
            default:
                throw KeyrefWireError.invalidField("hpke_kem does not match the receiver key")
            }
            return try recipient.open(ct)
        } catch let e as KeyrefWireError {
            throw e
        } catch {
            throw KeyrefCryptoError.hpkeFailure
        }
    }
}

// MARK: - encoded key helpers (§1.4)

public enum HPKEKeys {
    /// Generates an X25519 KEM key pair; public key is 32 raw bytes.
    public static func generateX25519() throws -> (publicKey: Data, privateKey: Data) {
        let sk = Curve25519.KeyAgreement.PrivateKey()
        return (sk.publicKey.rawRepresentation, sk.rawRepresentation)
    }

    /// Generates a software P-256 KEM key pair; public key is 65-byte SEC1.
    public static func generateP256() throws -> (publicKey: Data, privateKey: Data) {
        let sk = P256.KeyAgreement.PrivateKey()
        return (sk.publicKey.x963Representation, sk.rawRepresentation)
    }

    /// Recomputes the encoded public key from a private key without
    /// trusting a second stored copy.
    public static func publicKey(of kemName: String, privateKey: Data) throws -> Data {
        switch kemName {
        case KEMName.x25519:
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation
        case KEMName.p256:
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.x963Representation
        default:
            throw KeyrefWireError.invalidField("unknown hpke_kem \(kemName)")
        }
    }

    /// Generates an Ed25519 signing key pair; public key is 32 raw bytes.
    public static func generateEd25519() throws -> (publicKey: Data, seed: Data) {
        let sk = Curve25519.Signing.PrivateKey()
        return (sk.publicKey.rawRepresentation, sk.rawRepresentation)
    }
}
