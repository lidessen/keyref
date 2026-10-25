// Encoding helpers shared by the wire layer: lowercase hex, standard
// Base64 (RFC 4648 with padding), big-endian uint64 and the protocol's
// field separators (docs/protocol.md §1.1).
import Foundation

public enum KeyrefEncoding {
    /// ASCII unit separator used inside HPKE info strings and AADs.
    public static let unitSeparator: UInt8 = 0x1f
    /// NUL separator used inside signed transcripts.
    public static let fieldSeparator: UInt8 = 0x00

    // MARK: hex

    public static func hexEncode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    public static func hexDecode(_ string: String) throws -> Data {
        let chars = Array(string.utf8)
        guard chars.count % 2 == 0 else {
            throw KeyrefWireError.invalidField("hex string has odd length")
        }
        var out = Data(capacity: chars.count / 2)
        func nibble(_ c: UInt8) throws -> UInt8 {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x61...0x66: return c - 0x61 + 10
            default: throw KeyrefWireError.invalidField("hex string contains a non-lowercase-hex byte")
            }
        }
        var i = 0
        while i < chars.count {
            let hi = try nibble(chars[i])
            let lo = try nibble(chars[i + 1])
            out.append((hi << 4) | lo)
            i += 2
        }
        return out
    }

    // MARK: base64 (standard, padded — JSON binary fields, protocol §1.1)

    public static func base64Encode(_ data: Data) -> String {
        data.base64EncodedString()
    }

    public static func base64Decode(_ string: String) throws -> Data {
        guard let d = Data(base64Encoded: string) else {
            throw KeyrefWireError.invalidField("field is not valid standard base64")
        }
        return d
    }

    // MARK: integers

    /// Appends `value` as 8-byte big-endian (u64be, protocol §1.1).
    public static func appendU64BE(_ value: UInt64, to data: inout Data) {
        withUnsafeBytes(of: value.bigEndian) { data.append(contentsOf: $0) }
    }

    public static func u64BEBytes(_ value: UInt64) -> Data {
        var d = Data(capacity: 8)
        appendU64BE(value, to: &d)
        return d
    }

    public static func readU64BE(_ data: Data, offset: Int) throws -> UInt64 {
        guard offset >= 0, data.count >= offset + 8 else {
            throw KeyrefWireError.invalidField("buffer too short for u64be")
        }
        var v: UInt64 = 0
        for i in 0..<8 {
            v = (v << 8) | UInt64(data[data.startIndex + offset + i])
        }
        return v
    }

    // MARK: identifiers

    /// 16-byte identifiers are encoded as 32 lowercase hex characters
    /// (docs/protocol.md §1.1).
    public static func isValidID(_ s: String) -> Bool {
        guard s.count == 32 else { return false }
        for c in s.utf8 {
            switch c {
            case 0x30...0x39, 0x61...0x66: continue
            default: return false
            }
        }
        return true
    }

    /// 16 random bytes encoded as 32 lowercase hex characters.
    public static func newID() -> String {
        var raw = Data(count: 16)
        _ = raw.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        return hexEncode(raw)
    }
}
