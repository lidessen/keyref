// AES-256-GCM blob layout (docs/protocol.md §1.5): every symmetric
// ciphertext (meta, secret, recovery_wrap, vault_wrapped_*, audit AES
// segment) is nonce(12) ‖ ct ‖ tag with a fresh random nonce. HPKE
// ciphertexts are ct ‖ tag with an empty AAD — all binding lives in info
// (§1.5, handled by HPKE.swift).
import CryptoKit
import Foundation

public enum KeyrefCryptoError: Error, Equatable {
    /// Invalid or unauthenticated blob; never carries key or plaintext.
    case invalidBlob
    case invalidKey
    case hpkeFailure
}

public enum BlobCrypto {
    public static let nonceSize = 12
    public static let tagSize = 16
    public static let keySize = 32
    static let minBlob = nonceSize + tagSize

    /// Encrypts with AES-256-GCM under a fresh random 12-byte nonce and
    /// returns nonce(12) ‖ ct ‖ tag (§1.5).
    public static func sealBlob(key: Data, aad: Data, plaintext: Data) throws -> Data {
        let box = try sealBox(key: key, aad: aad, plaintext: plaintext, nonce: nil)
        guard let combined = box.combined else { throw KeyrefCryptoError.invalidKey }
        return combined
    }

    /// Same as `sealBlob` with a caller-supplied nonce — used by the
    /// deterministic cross-language vectors; production code uses `sealBlob`.
    public static func sealBlob(key: Data, aad: Data, plaintext: Data, nonce: Data) throws -> Data {
        let box = try sealBox(key: key, aad: aad, plaintext: plaintext, nonce: nonce)
        guard let combined = box.combined else { throw KeyrefCryptoError.invalidKey }
        return combined
    }

    /// Decrypts a blob produced by `sealBlob`.
    public static func openBlob(key: Data, aad: Data, blob: Data) throws -> Data {
        guard key.count == keySize else { throw KeyrefCryptoError.invalidKey }
        guard blob.count >= minBlob else { throw KeyrefCryptoError.invalidBlob }
        let nonce = blob.prefix(nonceSize)
        let payload = blob.dropFirst(nonceSize)
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
                                            ciphertext: payload.dropLast(tagSize),
                                            tag: payload.suffix(tagSize))
            return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
        } catch {
            throw KeyrefCryptoError.invalidBlob
        }
    }

    private static func sealBox(key: Data, aad: Data, plaintext: Data, nonce: Data?) throws -> AES.GCM.SealedBox {
        guard key.count == keySize else { throw KeyrefCryptoError.invalidKey }
        let symmetric = SymmetricKey(data: key)
        do {
            if let nonce {
                return try AES.GCM.seal(plaintext, using: symmetric, nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
            }
            return try AES.GCM.seal(plaintext, using: symmetric, authenticating: aad)
        } catch {
            throw KeyrefCryptoError.invalidKey
        }
    }
}
