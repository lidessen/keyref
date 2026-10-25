// Unit tests for the KeyrefUI stores and view models (docs/ios-ui.md):
// pure logic with injected mocks — no Keychain, no network. Runs both on
// macOS (`swift test`) and the iOS simulator (xcodebuild test).
import XCTest
@testable import KeyrefUI
import KeyrefCore

@MainActor
final class RecoveryAndValidationTests: XCTestCase {

    // MARK: group backfill (§2.2 校验抄写)

    func testBackfillAcceptsCorrectSequentialInput() {
        let groups = ["ABCDE", "FGHJK", "MNPQR"]
        let model = RecoveryBackfillModel(targetGroups: groups)
        for (i, g) in groups.enumerated() {
            model.update(group: i, raw: g)
        }
        XCTAssertTrue(model.allMatched)
        XCTAssertTrue(model.completed)
        XCTAssertNil(model.firstMismatchIndex)
    }

    func testBackfillMarksMismatchedGroupRed() {
        let model = RecoveryBackfillModel(targetGroups: ["ABCDE", "FGHJK", "MNPQR"])
        model.update(group: 0, raw: "ABCDE")
        model.update(group: 1, raw: "FGHXK")  // one symbol wrong
        XCTAssertFalse(model.allMatched)
        XCTAssertEqual(model.firstMismatchIndex, 1)
        XCTAssertEqual(model.results[0], true)
        XCTAssertEqual(model.results[1], false)
        XCTAssertEqual(model.errorMessage, "有一组和屏幕上的不一致，请对照你抄写的那份修改。")
    }

    func testBackfillNormalizesCrockfordConfusables() {
        // 0/O、1/I/L 视为同字符（§2.2）。
        let model = RecoveryBackfillModel(targetGroups: ["0AB1L", "O2I34"])
        model.update(group: 0, raw: "OAB1I")
        model.update(group: 1, raw: "02134")
        XCTAssertTrue(model.allMatched)
    }

    func testBackfillSplitsPastedBlob() {
        let model = RecoveryBackfillModel(targetGroups: ["ABCDE", "FGHJK"])
        model.update(group: 0, raw: "ABCDE FGHJK")
        XCTAssertTrue(model.allMatched)
        XCTAssertEqual(model.inputs, ["ABCDE", "FGHJK"])
    }

    func testBackfillPastedWithHyphensAndLowercase() {
        let model = RecoveryBackfillModel(targetGroups: ["ABCDE", "FGHJK"])
        model.update(group: 0, raw: "abcde-fghjk")
        XCTAssertTrue(model.allMatched)
    }

    func testBackfillPasteWithMismatchFocusesFirstIncomplete() {
        let model = RecoveryBackfillModel(targetGroups: ["ABCDE", "FGHJK", "MNPQR"])
        model.update(group: 0, raw: "ABCDE-X")
        // The pasted blob is shorter than the whole code; the focus jumps to
        // the first incomplete group.
        XCTAssertEqual(model.focusIndex, 1)
        XCTAssertEqual(model.inputs[0], "ABCDE")
        XCTAssertEqual(model.inputs[1], "X")
        XCTAssertFalse(model.allMatched)
    }

    // MARK: ref validation (§6.1 syntax)

    func testRefValidation() {
        XCTAssertTrue(RefValidation.isValid("openai-prod"))
        XCTAssertTrue(RefValidation.isValid("a"))
        XCTAssertTrue(RefValidation.isValid("a1"))
        XCTAssertFalse(RefValidation.isValid("OpenAI"))
        XCTAssertFalse(RefValidation.isValid("-abc"))
        XCTAssertFalse(RefValidation.isValid("abc-"))
        XCTAssertFalse(RefValidation.isValid(""))
        let long = String(repeating: "a", count: 65)
        XCTAssertFalse(RefValidation.isValid(long))
    }

    // MARK: §7.3 deny list

    func testDenyListHitsInterpreters() {
        XCTAssertTrue(DefaultDeny.isDenied("python3"))
        XCTAssertTrue(DefaultDeny.isDenied("/usr/bin/env"))  // basename check
        XCTAssertTrue(DefaultDeny.isDenied("BASH"))
        XCTAssertFalse(DefaultDeny.isDenied("curl"))
        XCTAssertFalse(DefaultDeny.isDenied("my-python-tool"))
    }

    // MARK: §7.4 leak matchers

    func testLeakDetectionRaw() {
        let secret = "sk-super-secret-value-1234"
        XCTAssertTrue(SecretLeak.leaks(secret: secret, in: "my name has sk-super-secret-value-1234 inside"))
        XCTAssertFalse(SecretLeak.leaks(secret: secret, in: "clean name"))
    }

    func testLeakDetectionBase64AndHex() {
        let secret = "hunter2hunter2"
        let b64 = Data(secret.utf8).base64EncodedString()
        XCTAssertTrue(SecretLeak.leaks(secret: secret, in: "prefix \(b64)"))
        let hex = secret.utf8.map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(SecretLeak.leaks(secret: secret, in: "hex: \(hex)"))
        XCTAssertTrue(SecretLeak.leaks(secret: secret, in: "HEX: \(hex.uppercased())"))
    }

    func testLeakDetectionPercentEncoding() {
        let secret = "pa$$ word!"
        let encoded = "pa%24%24%20word%21"
        XCTAssertTrue(SecretLeak.leaks(secret: secret, in: "encoded \(encoded)"))
    }

    func testLeakKindLabels() {
        let secret = "sk-abcdefgh123456"
        XCTAssertEqual(SecretLeak.leakKind(secret: secret, in: "value \(secret)"), "原文")
        let b64 = Data(secret.utf8).base64EncodedString()
        XCTAssertEqual(SecretLeak.leakKind(secret: secret, in: b64), "Base64")
    }

    // MARK: S14 expiry marks (§2.5)

    func testExpiryMarks() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        XCTAssertEqual(ExpiryMark.mark(expiresAt: now.addingTimeInterval(3 * 86_400), now: now),
                       .inSevenDays)
        XCTAssertEqual(ExpiryMark.mark(expiresAt: now.addingTimeInterval(10 * 86_400), now: now),
                       .none)
        XCTAssertEqual(ExpiryMark.mark(expiresAt: now.addingTimeInterval(3600), now: now),
                       .tomorrow)
        XCTAssertEqual(ExpiryMark.mark(expiresAt: now.addingTimeInterval(-60), now: now),
                       .tomorrow)
        XCTAssertEqual(ExpiryMark.inSevenDays.text, "7 天后到期")
        XCTAssertEqual(ExpiryMark.tomorrow.text, "明天到期")
    }
}
