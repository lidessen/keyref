// Recovery code: Crockford Base32 payload codec and HKDF derivations
// (docs/protocol.md §3.8, design §8.5).
//
// Payload = vault_id (16 raw bytes) ‖ seed (32 bytes CSPRNG). Only the
// seed enters HKDF-SHA256; the two derivations are domain separated and
// mutually independent: recovery-kek decrypts recovery_wrap, recovery-sign
// is the Ed25519 seed of the takeover signing authority.
//
// Display encoding (pinned by tools/vectordump; the protocol fixes the
// payload and alphabet family but not the concrete layout): 5-bit groups
// MSB-first over the big-endian payload, 77 symbols (ceil(384/5); the
// last symbol carries 4 significant bits, zero-padded), shown in 5-symbol
// groups joined by '-'. Decoding accepts lowercase, strips '-' and
// spaces, and folds the confusable symbols I/L→1 and O→0 (the Crockford
// alphabet excludes I, L, O and U).
import CryptoKit
import Foundation

public enum RecoveryCode {
    public static let payloadLength = 48  // 16 vault_id + 32 seed
    public static let vaultIDLength = 16
    public static let seedLength = 32
    public static let symbolCount = 77    // ceil(48*8 / 5)

    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    private static let groupSize = 5

    // MARK: encode

    /// Encodes the 48-byte payload as grouped Crockford Base32.
    public static func encode(payload: Data) -> String {
        precondition(payload.count == payloadLength, "recovery payload must be \(payloadLength) bytes")
        var acc = 0
        var bits = 0
        var symbols: [Character] = []
        symbols.reserveCapacity(symbolCount)
        for byte in payload {
            acc = (acc << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                symbols.append(alphabet[(acc >> bits) & 0x1f])
            }
        }
        if bits > 0 {
            symbols.append(alphabet[(acc << (5 - bits)) & 0x1f])
        }
        var groups: [String] = []
        var i = 0
        while i < symbols.count {
            let end = min(i + groupSize, symbols.count)
            groups.append(String(symbols[i..<end]))
            i = end
        }
        return groups.joined(separator: "-")
    }

    /// Generates a fresh payload: 16 random bytes for the vault id and 32
    /// random bytes for the seed (§9.3 steps 1 and 4).
    public static func generatePayload() -> (vaultID: String, seed: Data, code: String) {
        var vault = Data(count: vaultIDLength)
        var seed = Data(count: seedLength)
        _ = vault.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, vaultIDLength, $0.baseAddress!) }
        _ = seed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, seedLength, $0.baseAddress!) }
        let vaultID = KeyrefEncoding.hexEncode(vault)
        let code = encode(payload: vault + seed)
        return (vaultID, seed, code)
    }

    // MARK: decode

    public enum RecoveryCodeError: Error, Equatable {
        case malformed
        case wrongLength
    }

    /// Parses a displayed recovery code back into vault_id and seed.
    /// Accepts lowercase input, '-' and ' ' separators, and folds
    /// I/L→1, O→0. Any other character (including U, which the alphabet
    /// deliberately excludes) is rejected.
    public static func decode(_ code: String) throws -> (vaultID: String, seed: Data) {
        var symbols: [Int] = []
        symbols.reserveCapacity(symbolCount)
        for ch in code.uppercased() {
            if ch == "-" || ch == " " { continue }
            switch ch {
            case "I", "L": symbols.append(1)
            case "O": symbols.append(0)
            default:
                guard let idx = alphabet.firstIndex(of: ch) else {
                    throw RecoveryCodeError.malformed
                }
                symbols.append(idx)
            }
        }
        guard symbols.count == symbolCount else {
            throw RecoveryCodeError.wrongLength
        }
        var out = Data(capacity: payloadLength)
        var acc = 0
        var bits = 0
        for s in symbols {
            acc = (acc << 5) | s
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((acc >> bits) & 0xff))
            }
        }
        // 77 symbols = 385 bits; the 385th (padding) bit must be zero.
        guard (acc & 1) == 0, out.count == payloadLength else {
            throw RecoveryCodeError.malformed
        }
        let vaultID = KeyrefEncoding.hexEncode(out.prefix(vaultIDLength))
        guard KeyrefEncoding.isValidID(vaultID) else {
            throw RecoveryCodeError.malformed
        }
        return (vaultID, out.suffix(seedLength))
    }
}

public enum RecoveryKeys {
    /// The fixed HKDF info labels (protocol §3.8).
    static let infoKEK = "recovery-kek"
    static let infoSign = "recovery-sign"

    /// The fixed recovery_kdf_json uploaded at vault creation (§3.8).
    public static let defaultKDFJSON =
        "{\"v\":1,\"kdf\":\"hkdf-sha256\",\"salt\":\"\",\"kek_info\":\"recovery-kek\",\"sign_info\":\"recovery-sign\"}"

    public struct Keys: Sendable {
        /// AES-256 key for recovery_wrap.
        public let kek: Data
        /// Ed25519 signer whose public key is recovery_sign_pub.
        public let signSeed: Data

        public var signer: Ed25519Signer {
            // Cannot fail: the seed is exactly 32 bytes.
            (try? Ed25519Signer(seed: signSeed))!
        }
    }

    /// Derives the recovery keys from the 32-byte seed:
    ///
    ///     prk         = HKDF-Extract(SHA-256, ikm = seed, salt = nil (zeros))
    ///     kek         = HKDF-Expand(prk, "recovery-kek", 32)
    ///     sign seed   = HKDF-Expand(prk, "recovery-sign", 32)
    ///
    /// CryptoKit's `deriveKey(salt: nil)` performs Extract with an all-zero
    /// salt, matching Go's hkdf.Extract(..., salt = nil); byte equality is
    /// anchored by the cross-language vectors.
    public static func derive(fromSeed seed: Data) throws -> Keys {
        guard seed.count == RecoveryCode.seedLength else {
            throw KeyrefWireError.invalidField("recovery seed must be \(RecoveryCode.seedLength) bytes")
        }
        let ikm = SymmetricKey(data: seed)
        let kek = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: Data(),
                                         info: Data(infoKEK.utf8), outputByteCount: 32)
        let signSeed = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: Data(),
                                              info: Data(infoSign.utf8), outputByteCount: 32)
        return Keys(kek: kek.withUnsafeBytes { Data($0) },
                    signSeed: signSeed.withUnsafeBytes { Data($0) })
    }

    /// Unwraps the VMK from recovery_wrap using the derived KEK; the AEAD
    /// tag is the "is this recovery code correct" verdict (§7.3).
    public static func unwrapVMK(keys: Keys, recoveryWrap: Data, vaultID: String) throws -> Data {
        let aad = try recoveryAAD(vaultID: vaultID)
        return try BlobCrypto.openBlob(key: keys.kek, aad: aad, blob: recoveryWrap)
    }
}
