// Simulator UI end-to-end: the real app, launched with a DEBUG-only
// local-server origin, creates a vault and pairs a CLI through the actual
// SwiftUI flow against a real keyref-server started by
// scripts/dev/ui-test.sh.
//
// The recovery code is read through RecoveryCodeDisplay's accessibility
// value (the lazy horizontal stack only materializes visible groups).
// The test process acts as the CLI: it registers a pairing session over
// the real API with CryptoKit keys, then drives the app's scanner paste
// path and verifies the pair status/grants afterwards.
import CryptoKit
import UIKit
import XCTest

final class KeyrefFlowUITests: XCTestCase {
    private static let origin = "http://127.0.0.1:18080"

    // MARK: - flows

    @MainActor
    func testCreateVaultAgainstLocalServer() throws {
        let app = launchApp(extraArguments: [])
        createVault(in: app)

        // Home: the four-tab shell is visible and unlocked.
        XCTAssertTrue(app.tabBars.buttons["条目"].waitForExistence(timeout: 20),
                      "main shell did not appear after entering the vault")
        XCTAssertTrue(app.tabBars.buttons["设备"].exists)
        XCTAssertTrue(app.tabBars.buttons["审计"].exists)
        XCTAssertTrue(app.tabBars.buttons["设置"].exists)
    }

    @MainActor
    func testPairCLIThroughTheUI() async throws {
        let createdApp = launchApp(extraArguments: ["-keyref-auto-auth"])
        createVault(in: createdApp)
        addItem(in: createdApp)

        // The test process plays the CLI: register a real pairing session.
        let cli = CLIIdentity()
        try await Self.registerCLI(cli, name: "build-bot")
        let payload = cli.payload(name: "build-bot", origin: Self.origin)

        // The iOS 27 floating glass tab bar does not accept XCUITest taps
        // in the simulator, so cold-restart onto the device tab via the
        // DEBUG hook. This also exercises restart → unlock → sync.
        createdApp.terminate()
        let app = launchApp(includeReset: false, initialTab: 1,
                            extraArguments: ["-keyref-auto-auth"])
        let unlock = app.buttons["使用 Face ID 解锁"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 20),
                      "lock screen missing after restart")
        unlock.tap()
        XCTAssertTrue(app.staticTexts["还没有 agent 设备"].waitForExistence(timeout: 20),
                      "device tab did not show the empty state after unlock")

        // Devices → 扫码配对 → simulator paste path → 核对 → 勾选 → 确认.
        // Prefer the empty-state button inside the List: the toolbar icon
        // reports an invalid hit point under XCUITest.
        let pairPredicate = NSPredicate(format: "label BEGINSWITH '扫码配对'")
        let listPair = app.collectionViews.buttons.matching(pairPredicate).firstMatch
        XCTAssertTrue(listPair.waitForExistence(timeout: 15),
                      "device list did not show 扫码配对")
        listPair.tap()

        let pasteField = app.textFields.firstMatch
        XCTAssertTrue(pasteField.waitForExistence(timeout: 15), "simulator paste field missing")
        UIPasteboard.general.string = payload
        pasteField.press(forDuration: 1.2)
        if !tapMenuItem(app, ["粘贴", "Paste"]) {
            pasteField.typeText(payload)
        }
        let parse = app.buttons["解析配对码"]
        XCTAssertTrue(parse.waitForExistence(timeout: 10))
        parse.tap()

        let proceed = app.buttons["继续"]
        XCTAssertTrue(proceed.waitForExistence(timeout: 15), "pair verify page missing")
        proceed.tap()

        // The pairing sheet overlays the item list; the same label exists
        // behind it. Tap the hittable (topmost) one.
        let itemMatches = app.staticTexts.matching(
            NSPredicate(format: "label == 'OpenAI production'"))
        XCTAssertTrue(itemMatches.firstMatch.waitForExistence(timeout: 15),
                      "grant selection list missing the item")
        var itemTapped = false
        for i in 0..<itemMatches.count where itemMatches.element(boundBy: i).isHittable {
            itemMatches.element(boundBy: i).tap()
            itemTapped = true
            break
        }
        XCTAssertTrue(itemTapped, "item row was not hittable in the grant selection")
        let confirm = app.buttons.matching(
            NSPredicate(format: "label BEGINSWITH '用 Face ID 确认'")).firstMatch
        XCTAssertTrue(confirm.waitForExistence(timeout: 10), "confirm button missing")
        confirm.tap()

        XCTAssertTrue(app.staticTexts["配对完成"].waitForExistence(timeout: 30),
                      "pairing did not complete")
        app.buttons["完成"].tap()

        // The paired CLI must appear in the signed-directory-backed list
        // (the list refreshes when the pairing cover dismisses).
        XCTAssertTrue(app.staticTexts["build-bot"].waitForExistence(timeout: 20),
                      "paired CLI missing from the device list (directory not published?)")

        // Runner-side verification of the real wire result.
        let status = try await Self.pollPairStatus(cli.nonceHex)
        XCTAssertEqual(status.status, "complete")
        XCTAssertEqual(status.grants?.count, 2, "expected view + use grants")
        XCTAssertEqual(Set(status.grants?.map(\.kind) ?? []), ["view", "use"])
    }

    // MARK: - app UI helpers

    @MainActor
    private func launchApp(includeReset: Bool = true, initialTab: Int? = nil,
                           extraArguments: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        var args = [
            "-keyref-assume-prerequisites", // simulator has no passcode/Face ID
            "-keyref-skip-push",            // no notification prompt behind the UI test
            "-keyref-force-no-camera",      // deterministic simulator pairing paste path
            "-keyref-origin", Self.origin,
        ]
        if includeReset { args.append("-keyref-reset") }
        if let initialTab { args += ["-keyref-initial-tab", String(initialTab)] }
        app.launchArguments = args + extraArguments
        app.launch()
        addUIInterruptionMonitor(withDescription: "system alerts") { alert in
            for label in ["允许", "Allow", "好", "OK", "不允许", "Don't Allow", "Don’t Allow"] {
                if alert.buttons[label].exists {
                    alert.buttons[label].tap()
                    return true
                }
            }
            return false
        }
        return app
    }

    @MainActor
    private func createVault(in app: XCUIApplication) {
        let create = app.buttons["创建保险库"]
        XCTAssertTrue(create.waitForExistence(timeout: 20), "welcome screen did not appear")
        create.tap()

        let proceed = app.buttons["继续"]
        XCTAssertTrue(proceed.waitForExistence(timeout: 10), "prerequisites page did not appear")
        waitEnabled(proceed, timeout: 10)
        proceed.tap()

        XCTAssertTrue(app.staticTexts["抄下恢复码"].waitForExistence(timeout: 30),
                      "recovery code page did not appear (vault generation failed?)")
        let codeElement = app.descendants(matching: .any)
            .matching(NSPredicate(format: "label BEGINSWITH '恢复码，共'"))
            .firstMatch
        XCTAssertTrue(codeElement.waitForExistence(timeout: 10), "recovery code element missing")
        let code = (codeElement.value as? String) ?? ""
        XCTAssertGreaterThanOrEqual(code.split(separator: " ").count, 2,
                                    "unexpected recovery code shape")

        let written = app.buttons["我已抄写，开始校验"]
        XCTAssertTrue(written.waitForExistence(timeout: 10))
        written.tap()

        // Real paste path: the model splits one pasted code across fields.
        let firstField = app.textFields.firstMatch
        XCTAssertTrue(firstField.waitForExistence(timeout: 10), "backfill fields did not appear")
        UIPasteboard.general.string = code
        firstField.press(forDuration: 1.2)
        if !tapMenuItem(app, ["粘贴", "Paste", "Paste and Match Style"]) {
            firstField.typeText(code)
        }

        let finish = app.buttons["完成"]
        XCTAssertTrue(finish.waitForExistence(timeout: 10))
        waitEnabled(finish, timeout: 15)
        finish.tap()

        XCTAssertTrue(app.staticTexts["保险库已创建"].waitForExistence(timeout: 30),
                      "creation did not finish")
        let synced = app.staticTexts["已同步"]
        if !synced.waitForExistence(timeout: 45) {
            let failed = app.buttons["重试上传"].exists
            XCTFail("vault was not uploaded to the local server (uploadFailed=\(failed))")
            return
        }
        let enter = app.buttons["进入保险库"]
        XCTAssertTrue(enter.waitForExistence(timeout: 10))
        enter.tap()
        XCTAssertTrue(app.tabBars.buttons["条目"].waitForExistence(timeout: 20))
    }

    @MainActor
    private func addItem(in app: XCUIApplication) {
        let add = app.buttons["添加条目"].firstMatch
        XCTAssertTrue(add.waitForExistence(timeout: 10), "add-item entry missing")
        add.tap()

        let name = app.textFields["名称"]
        XCTAssertTrue(name.waitForExistence(timeout: 10), "item editor did not appear")
        name.tap(); name.typeText("OpenAI production")
        let ref = app.textFields["ref"]
        ref.tap(); ref.typeText("openai-prod")
        let value = app.secureTextFields["值"]
        XCTAssertTrue(value.waitForExistence(timeout: 10), "secret field missing")
        value.tap(); value.typeText("sk-ui-test-value")
        let save = app.buttons["保存"]
        XCTAssertTrue(save.waitForExistence(timeout: 10))
        waitEnabled(save, timeout: 10)
        save.tap()
        XCTAssertTrue(app.staticTexts["OpenAI production"].waitForExistence(timeout: 15),
                      "item did not appear after saving")
    }

    @MainActor
    private func tapMenuItem(_ app: XCUIApplication, _ labels: [String]) -> Bool {
        let predicate = NSPredicate(format: "label IN %@", labels)
        let item = app.menuItems.matching(predicate).firstMatch
        if item.waitForExistence(timeout: 5) {
            item.tap()
            return true
        }
        return false
    }

    /// Polls `isEnabled` (XCTest has no built-in wait for enablement).
    @MainActor
    private func waitEnabled(_ element: XCUIElement, timeout: TimeInterval,
                             file: StaticString = #filePath, line: UInt = #line) {
        let deadline = Date().addingTimeInterval(timeout)
        while !element.isEnabled && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
        XCTAssertTrue(element.isEnabled, "element stayed disabled: \(element)", file: file, line: line)
    }

    // MARK: - test harness acting as the CLI

    private struct CLIIdentity {
        let hpke = Curve25519.KeyAgreement.PrivateKey()
        let sign = Curve25519.Signing.PrivateKey()
        let nonce = Data((0..<16).map { _ in UInt8.random(in: 0...255) })

        var hpkePub: Data { hpke.publicKey.rawRepresentation }
        var signPub: Data { sign.publicKey.rawRepresentation }
        var nonceHex: String { nonce.map { String(format: "%02x", $0) }.joined() }

        /// `keyref://pair?v=1&k=<b64>&s=<b64>&n=<hex>&name=..&u=<origin>`
        func payload(name: String, origin: String) -> String {
            func enc(_ s: String) -> String {
                var allowed = CharacterSet.alphanumerics
                allowed.insert(charactersIn: "-._~")
                return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
            }
            return "keyref://pair?v=1"
                + "&k=" + enc(hpkePub.base64EncodedString())
                + "&s=" + enc(signPub.base64EncodedString())
                + "&n=" + nonceHex
                + "&name=" + enc(name)
                + "&u=" + enc(origin)
        }
    }

    private struct PairStatus: Decodable {
        struct Grant: Decodable {
            let itemID: String
            let kind: String
            enum CodingKeys: String, CodingKey {
                case itemID = "item_id"
                case kind
            }
        }
        let status: String
        let grants: [Grant]?
    }

    private static func registerCLI(_ cli: CLIIdentity, name: String) async throws {
        // §3.5 pair-register transcript: "KEYREF1" NUL "pair-register" NUL
        // nonce(16 raw) NUL proposed_name.
        var tb = Data("KEYREF1".utf8); tb.append(0)
        tb.append(Data("pair-register".utf8)); tb.append(0)
        tb.append(cli.nonce); tb.append(0)
        tb.append(Data(name.utf8))
        let signature = try cli.sign.signature(for: tb)
        let body: [String: Any] = [
            "nonce": cli.nonceHex,
            "hpke_kem": "X25519",
            "hpke_public_key": cli.hpkePub.base64EncodedString(),
            "sign_alg": "ed25519",
            "sign_public_key": cli.signPub.base64EncodedString(),
            "proposed_name": name,
            "signature": signature.base64EncodedString(),
        ]
        var request = URLRequest(url: URL(string: Self.origin + "/v1/pair/register")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        XCTAssertEqual(status, 201, "pair/register: \(String(decoding: data, as: UTF8.self))")
    }

    private static func pollPairStatus(_ nonceHex: String) async throws -> PairStatus {
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            let url = URL(string: Self.origin + "/v1/pair/status?nonce=" + nonceHex)!
            if let (data, response) = try? await URLSession.shared.data(from: url),
               (response as? HTTPURLResponse)?.statusCode == 200,
               let status = try? JSONDecoder().decode(PairStatus.self, from: data) {
                return status
            }
            try? await Task.sleep(for: .milliseconds(300))
        }
        throw NSError(domain: "keyref.ui", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "pair status never completed"])
    }
}
