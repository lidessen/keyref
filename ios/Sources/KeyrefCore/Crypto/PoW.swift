// Proof of work for hosted vault creation (docs/protocol.md §10.1,
// design §10.5 item 9). Only consulted when the hosted server answers
// 401 pow_required — self-hosted servers never issue challenges. Solve
// runs off the caller's thread: ~2^21 SHA-256 iterations expected.
import CryptoKit
import Foundation

public enum PoW {
    /// Required leading zero bits of SHA-256(challenge ‖ vault_id_raw ‖
    /// u64be(nonce)) — ~2^21 hashes expected (§10.1).
    static let leadingZeroBits = 21

    /// Solves the challenge for one vault id. Returns the 8-byte u64be
    /// nonce. Runs on the current thread (expect tens of milliseconds to
    /// a few seconds on a phone); callers should hop to a background task.
    public static func solve(challenge: Data, vaultID: String) throws -> Data {
        guard challenge.count == 32 else {
            throw KeyrefWireError.invalidField("pow challenge must be 32 bytes")
        }
        let vaultRaw = try KeyrefEncoding.hexDecode(vaultID)
        guard vaultRaw.count == 16 else {
            throw KeyrefWireError.invalidField("vault_id must be 32 hex characters")
        }
        var key = Data(capacity: challenge.count + vaultRaw.count + 8)
        key.append(challenge)
        key.append(vaultRaw)

        var nonce: UInt64 = 0
        var buf = [UInt8](repeating: 0, count: 8)
        while true {
            for i in 0..<8 { buf[7 - i] = UInt8((nonce >> (8 * UInt64(i))) & 0xFF) }
            var hasher = SHA256()
            hasher.update(data: key)
            hasher.update(data: buf.withUnsafeBufferPointer { Data($0) })
            let digest = hasher.finalize()
            if Self.leadingZeros(of: digest) >= leadingZeroBits {
                return Data(buf)
            }
            guard nonce < UInt64.max else {
                throw KeyrefCryptoError.invalidBlob // exhausted — cannot happen in practice
            }
            nonce &+= 1
        }
    }

    static func leadingZeros(of digest: SHA256.Digest) -> Int {
        var bits = 0
        for byte in digest {
            if byte == 0 { bits += 8; continue }
            var b = byte
            while b & 0x80 == 0 { bits += 1; b <<= 1 }
            break
        }
        return bits
    }
}
