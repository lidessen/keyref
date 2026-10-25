// Recovery-code codec tests (docs/protocol.md §3.8; the byte-level
// agreement with the Go generator is anchored by VectorTests).
import XCTest

@testable import KeyrefCore

final class RecoveryCodeTests: XCTestCase {
    func testRoundtrip() throws {
        let (vaultID, seed, code) = RecoveryCode.generatePayload()
        XCTAssertTrue(KeyrefEncoding.isValidID(vaultID))
        XCTAssertEqual(seed.count, 32)
        let parsed = try RecoveryCode.decode(code)
        XCTAssertEqual(parsed.vaultID, vaultID)
        XCTAssertEqual(parsed.seed, seed)
    }

    func testDeterministicEncoding() throws {
        let vault = try KeyrefEncoding.hexDecode("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        let seed = Data(repeating: 0xab, count: 32)
        let code = RecoveryCode.encode(payload: vault + seed)
        // 48 bytes → 77 symbols in 5-symbol groups (last group 2 symbols).
        XCTAssertEqual(code.filter { $0 != "-" }.count, RecoveryCode.symbolCount)
        let parsed = try RecoveryCode.decode(code)
        XCTAssertEqual(parsed.vaultID, "0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        XCTAssertEqual(parsed.seed, seed)
    }

    func testAlphabetExcludesILOU() throws {
        let payload = Data(repeating: 0xff, count: 48)
        let code = RecoveryCode.encode(payload: payload)
        for ch in code where ch != "-" {
            XCTAssertFalse("ILOU".contains(ch), "Crockford alphabet excludes I, L, O, U")
        }
    }

    func testDecodeFoldingAndSeparators() throws {
        let (vaultID, seed, code) = RecoveryCode.generatePayload()
        // Lowercase.
        XCTAssertEqual(try RecoveryCode.decode(code.lowercased()).seed, seed)
        // Spaces instead of dashes.
        XCTAssertEqual(try RecoveryCode.decode(code.replacingOccurrences(of: "-", with: " ")).seed, seed)
        // Confusable symbols fold: replace 1→I/L and 0→O in the string form.
        let withOnes = code.replacingOccurrences(of: "1", with: "I")
        XCTAssertEqual(try RecoveryCode.decode(withOnes).seed, seed)
        let withZeros = code.replacingOccurrences(of: "0", with: "O")
        XCTAssertEqual(try RecoveryCode.decode(withZeros).vaultID, vaultID)
        // U is not in the alphabet and must not fold to anything.
        let withU = code.replacingOccurrences(of: "V", with: "U")
        if withU != code {
            XCTAssertThrowsError(try RecoveryCode.decode(withU))
        }
        _ = vaultID
    }

    func testDecodeRejectsGarbage() throws {
        XCTAssertThrowsError(try RecoveryCode.decode(""))
        XCTAssertThrowsError(try RecoveryCode.decode("AAAA"))  // too short
        XCTAssertThrowsError(try RecoveryCode.decode(String(repeating: "A", count: 78)))  // too long
        XCTAssertThrowsError(try RecoveryCode.decode(String(repeating: "2", count: 38) + "-" + String(repeating: "!", count: 39)))
    }

    func testDecodeRejectsBadPaddingBit() throws {
        // 77 symbols carry 385 bits; the last (padding) bit must be zero.
        let (vaultID, _, code) = RecoveryCode.generatePayload()
        _ = vaultID
        var symbols = Array(code.filter { $0 != "-" })
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        // Flip the last symbol to one with the low bit set (odd value).
        for candidate in alphabet.reversed() where alphabet.firstIndex(of: candidate)! % 2 == 1 {
            symbols[76] = candidate
            break
        }
        let bad = symbols.map(String.init).joined(separator: "-")
        XCTAssertThrowsError(try RecoveryCode.decode(bad))
    }

    func testHKDFDerivations() throws {
        let seed = Data(repeating: 0x42, count: 32)
        let keys = try RecoveryKeys.derive(fromSeed: seed)
        XCTAssertEqual(keys.kek.count, 32)
        XCTAssertEqual(keys.signSeed.count, 32)
        // Domain separation: the two derivations differ.
        XCTAssertNotEqual(keys.kek, keys.signSeed)
        // Deterministic.
        let again = try RecoveryKeys.derive(fromSeed: seed)
        XCTAssertEqual(again.kek, keys.kek)
        XCTAssertEqual(again.signSeed, keys.signSeed)
        // The sign seed is a valid Ed25519 seed and yields a stable public key.
        XCTAssertEqual(keys.signer.signPublicKey.count, 32)
        XCTAssertThrowsError(try RecoveryKeys.derive(fromSeed: Data(repeating: 0, count: 31)))
    }
}
