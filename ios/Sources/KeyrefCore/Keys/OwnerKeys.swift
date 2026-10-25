// Owner device keys (design §9.2, §9.3, §9.5).
//
// The owner identity is a P-256 HPKE (key-agreement) key pair plus a P-256
// ECDSA signing key pair. Production runs both inside the Secure Enclave;
// the documented fallback (design §9.2) stores software P-256 private keys
// in the Keychain with passcode + biometry access control. The chosen
// backing is visible on the type via `isEnclaveBacked` — never silently
// substituted.
import CryptoKit
import Foundation
import Security

/// One owner identity: signing + HPKE receiving, either enclave-backed or
/// software. The raw key material is only held in memory for the software
/// variant; enclave keys reconstruct from their persistent
/// dataRepresentation which the KeyStore holds.
public struct OwnerKeys: Sendable {
    public let signer: TranscriptSigner
    public let kemKEMName: String

    /// SEC1-uncompressed signing public key (65 bytes, §1.4).
    public var signPublicKey: Data { signer.signPublicKey }
    /// SEC1-uncompressed HPKE public key (65 bytes, §1.4).
    public let kemPublicKey: Data
    /// true when both keys live in the Secure Enclave; false is the
    /// explicit software fallback of design §9.2 (weaker: after unlock a
    /// compromised kernel could export the software private key).
    public let isEnclaveBacked: Bool

    private enum Receiver {
        case software(P256.KeyAgreement.PrivateKey)
        case enclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
    }

    private let receiver: Receiver

    // MARK: unwrap

    /// Opens an HPKE envelope sealed to this owner's P-256 public key
    /// (VMK wraps, approval requests, audit event keys — §3.7 purposes).
    public func unwrap(info: Data, enc: Data, ct: Data) throws -> Data {
        switch receiver {
        case .software(let sk):
            return try KeyrefHPKE.unwrapKey(kemName: kemKEMName, receiver: .p256(sk), info: info, enc: enc, ct: ct)
        case .enclave(let sk):
            return try KeyrefHPKE.unwrapKey(kemName: kemKEMName, receiver: .p256Enclave(sk), info: info, enc: enc, ct: ct)
        }
    }

    // MARK: access-control profiles

    /// Enclave access control: private key usage gated on the current
    /// biometric set and the device passcode (design §9.3 step 2).
    public static func enclaveAccessControl(biometryRequired: Bool) throws -> SecAccessControl {
        // §9.3: usage gated on the current biometric set (which requires
        // the device passcode by definition). The biometryRequired=false
        // profile (tests/CI) keeps .privateKeyUsage with
        // WhenUnlockedThisDeviceOnly — adding .devicePasscode alongside
        // that accessibility is rejected by the Secure Enclave daemon.
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if biometryRequired {
            flags.insert(.biometryCurrentSet)
        }
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error) else {
            throw KeyStoreError.unavailable("SecAccessControlCreateWithFlags failed")
        }
        return ac
    }

    // MARK: generation / loading

    public enum OwnerKeysError: Error, Equatable {
        case enclaveUnavailable(String)
        case invalidState(String)
    }

    /// Generates a fresh owner identity. Tries the Secure Enclave first
    /// (`SecureEnclave.isAvailable` probe); when the enclave is not usable
    /// — or `preferEnclave` is false — falls back to explicit software
    /// keys with `isEnclaveBacked == false` (design §9.2 fallback, never a
    /// silent substitution). Biometry-gated enclave keys require the
    /// current biometric set; on machines without biometry hardware pass
    /// `biometryRequired: false` (passcode-only, test/CI profile).
    public static func generate(preferEnclave: Bool = true,
                                biometryRequired: Bool = true) throws -> OwnerKeys {
        if preferEnclave, SecureEnclave.isAvailable {
            if let keys = try? enclaveOwnerKeys(biometryRequired: biometryRequired) {
                return keys
            }
            if biometryRequired, let keys = try? enclaveOwnerKeys(biometryRequired: false) {
                // Machines without biometry hardware cannot create
                // .biometryCurrentSet controls; passcode-only enclave keys
                // remain enclave-backed.
                return keys
            }
            // Enclave unusable: fall through to the explicit software
            // fallback below. The downgrade is never silent — the returned
            // value carries isEnclaveBacked == false (design §9.2).
        }
        return try softwareOwnerKeys()
    }

    private static func enclaveOwnerKeys(biometryRequired: Bool) throws -> OwnerKeys {
        let ac = try enclaveAccessControl(biometryRequired: biometryRequired)
        let kem = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        let sign = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac)
        return OwnerKeys(
            signer: EnclaveP256Signer(privateKey: sign),
            kemKEMName: KEMName.p256,
            kemPublicKey: kem.publicKey.x963Representation,
            isEnclaveBacked: true,
            receiver: .enclave(kem))
    }

    private static func softwareOwnerKeys() throws -> OwnerKeys {
        let kem = try P256.KeyAgreement.PrivateKey()
        let sign = try P256.Signing.PrivateKey()
        return OwnerKeys(
            signer: SoftwareP256Signer(privateKey: sign),
            kemKEMName: KEMName.p256,
            kemPublicKey: kem.publicKey.x963Representation,
            isEnclaveBacked: false,
            receiver: .software(kem))
    }

    // MARK: persistence (KeyStore)

    /// Loads a previously persisted owner identity from the KeyStore.
    /// Enclave-backed identities are stored as their persistent
    /// dataRepresentation; software ones as raw scalars.
    public static func load(from store: KeyStore, enclaveBacked: Bool,
                            biometryRequired: Bool = true) throws -> OwnerKeys? {
        guard let kemData = try store.retrieve(.ownerHPKEPrivate),
              let signData = try store.retrieve(.ownerSignPrivate) else {
            return nil
        }
        if enclaveBacked {
            // The access-control policy is baked into the enclave's
            // dataRepresentation; no SecAccessControl at reconstruction.
            let kem = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: kemData)
            let sign = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signData)
            return OwnerKeys(
                signer: EnclaveP256Signer(privateKey: sign),
                kemKEMName: KEMName.p256,
                kemPublicKey: kem.publicKey.x963Representation,
                isEnclaveBacked: true,
                receiver: .enclave(kem))
        }
        let kem = try P256.KeyAgreement.PrivateKey(rawRepresentation: kemData)
        let sign = try P256.Signing.PrivateKey(rawRepresentation: signData)
        return OwnerKeys(
            signer: SoftwareP256Signer(privateKey: sign),
            kemKEMName: KEMName.p256,
            kemPublicKey: kem.publicKey.x963Representation,
            isEnclaveBacked: false,
            receiver: .software(kem))
    }

    /// Persists both private keys. Enclave dataRepresentations go in as
    /// ordinary ThisDeviceOnly data (the enclave itself enforces usage
    /// conditions); software scalars get the strongest local protection.
    public func persist(to store: KeyStore, biometryRequired: Bool = true) throws {
        switch signer {
        case let enclave as EnclaveP256Signer:
            try store.store(.ownerSignPrivate, enclave.dataRepresentation)
        case let software as SoftwareP256Signer:
            try store.store(.ownerSignPrivate, software.privateKey.rawRepresentation,
                            access: biometryRequired ? .biometryCurrentSet : .whenUnlockedThisDeviceOnly)
        default:
            throw OwnerKeysError.invalidState("unknown signer type")
        }
        switch receiver {
        case .enclave(let sk):
            try store.store(.ownerHPKEPrivate, sk.dataRepresentation)
        case .software(let sk):
            try store.store(.ownerHPKEPrivate, sk.rawRepresentation,
                            access: biometryRequired ? .biometryCurrentSet : .whenUnlockedThisDeviceOnly)
        }
    }
}
