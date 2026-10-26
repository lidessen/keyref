// Masked-value tests (design §6.1): the prefix table, the longest-match
// rule and the minimum-length floor — the masked string is the deliberate
// leak shown to every view-granted agent, so its shape is contractual.
import XCTest

@testable import KeyrefCore

final class ItemMaskingTests: XCTestCase {

    // MARK: §6.1 prefix table + length floor

    func testAPIKeyWithPrefixKeepsPrefixAndLastFour() {
        // sk- + 8 more chars = 11 total → prefix + **** + last4.
        XCTAssertEqual(ItemMasking.mask("sk-12345678", type: "api_key"),
                       "sk-****5678")
        XCTAssertEqual(ItemMasking.mask("sk-proj-abcdefgh", type: "token"),
                       "sk-proj-****efgh")
        XCTAssertEqual(ItemMasking.mask("github_pat_abcd12345678", type: "api_key"),
                       "github_pat_****5678")
        XCTAssertEqual(ItemMasking.mask("AKIA12345678", type: "api_key"),
                       "AKIA****5678")
    }

    func testLongestPrefixWins() {
        // "sk-proj-x..." matches both "sk-" and "sk-proj-"; the longer one
        // applies (and its higher floor must be used, not sk-'s).
        XCTAssertEqual(ItemMasking.longestPrefix(of: "sk-proj-abcdefgh"), "sk-proj-")
        // 11 chars: passes the sk- floor (3+8) but not sk-proj-'s (8+8=16).
        XCTAssertEqual(ItemMasking.mask("sk-proj-abc", type: "api_key"), "***")
        // 16 chars: passes sk-proj-'s floor.
        XCTAssertEqual(ItemMasking.mask("sk-proj-abcdefgh", type: "api_key"),
                       "sk-proj-****efgh")
    }

    func testTooShortValuesAreFullyMasked() {
        // 5-char api_key: old behavior leaked "ab1****ab12c" (7 of 5 chars
        // shown); §6.1 floor requires prefix + 8 → ***.
        XCTAssertEqual(ItemMasking.mask("ab12c", type: "api_key"), "***")
        XCTAssertEqual(ItemMasking.mask("ghp_123", type: "token"), "***")
        XCTAssertEqual(ItemMasking.mask("github_pat_x", type: "token"), "***")
    }

    func testExactlyAtFloorIsKept() {
        // len == prefix.count + 8 → keep (至少比前缀多 8 个字符).
        XCTAssertEqual(ItemMasking.mask("ghp_12345678", type: "api_key"),
                       "ghp_****5678")
    }

    func testNoPrefixMatchUsesEmptyPrefixFloor() {
        // generic 8+ chars: **** + last four; shorter: ***.
        XCTAssertEqual(ItemMasking.mask("abcd1234", type: "generic"), "****1234")
        XCTAssertEqual(ItemMasking.mask("abc12", type: "generic"), "***")
    }

    // MARK: always-masked types

    func testPasswordAndNoteAlwaysMasked() {
        for t in ["password", "note"] {
            XCTAssertEqual(ItemMasking.mask("sk-12345678", type: t), "***")
            XCTAssertEqual(ItemMasking.mask("short", type: t), "***")
        }
    }

    func testEmptyValueMasked() {
        XCTAssertEqual(ItemMasking.mask("", type: "api_key"), "***")
        XCTAssertEqual(ItemMasking.mask("", type: "password"), "***")
    }
}
