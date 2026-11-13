# ios

The owner app for humans. Agents do not run here; this side holds the master key, edits items, pairs the CLI and approves sensitive `exec` calls.

See the "iOS app" and "cryptography" sections of [docs/design.md](../docs/design.md) for the design.

- Swift + SwiftUI. Minimum system **iOS 26** (raised with Liquid Glass in design v0.5; CryptoKit has native RFC 9180 HPKE, and the enclave private key is integrated natively).
- Unlock uses Face ID / Touch ID (`LocalAuthentication`). The agreement key that wraps the VMK lives in the Secure Enclave and its curve must be P-256.
- There is a second Secure Enclave P-256 signing key, used to sign item ciphertext and pairing records.
- Creating, editing, deleting and rotating items only happen on this device (or on a later one). The CLI cannot modify the vault.
- Interface copy is Simplified Chinese. `ref`, algorithm names and API paths stay English.
- Plaintext may be shown, but every "reveal" goes through biometric authentication again. Never write plaintext into system logs, crash reports or analytics SDKs.
- The sync server defaults to the official hosted service. The settings allow any HTTPS origin, for self-hosting. When a scanned pairing QR code points at a different server, show the domain first and ask for confirmation. Do not skip a layer of end-to-end encryption just because the hosted service is operated by us.

Current layout:

```
ios/
├── Package.swift            # KeyrefCore (crypto / protocol / sync / approvals / second-device pairing) + KeyrefUI (all the views)
├── Sources/KeyrefCore/      # UI-free core: encryption, APIClient, SyncEngine, VaultFlows, ApprovalFlows, OwnerPairing
├── Sources/KeyrefUI/        # The SwiftUI layer (the 17 screens of docs/ios-ui.md, iOS 26 Liquid Glass)
├── Tests/                   # KeyrefCoreTests + KeyrefUITests (both run on the simulator and on macOS)
├── Keyref.xcodeproj         # The app shell (target "Keyref", iOS 26+)
└── Keyref/                  # the @main entry point and Info.plist
```

Build: `scripts/dev/xcodebuild.sh -project Keyref.xcodeproj -scheme Keyref -destination 'platform=iOS Simulator,name=iPhone 17' build|test`. The script points `DEVELOPER_DIR` at `/Applications/Xcode.app/Contents/Developer` — running `xcodebuild` directly on a machine whose `xcode-select` points at CommandLineTools fails with "tool 'xcodebuild' requires Xcode"; where `xcode-select` already points at a full Xcode, plain `xcodebuild` works.

### The visual language

The interface shares one design system, in `Sources/KeyrefUI/DesignSystem/`:

- `Theme.swift` — the palette. Cool editorial typography: an almost-white page (light) / almost-black page (dark), text almost-black / almost-white, one hairline colour for layering, and one solid "plaintext slab" (`slab`, the colour opposite the page) — the secret is the only dark block on the page, findable at a glance. Amber is the only accent colour and is used only as a small signal (the key in the brand mark, the current step in the stepper, the small square badge on pending approvals). Every adaptive colour goes through a `UIColor` dynamic provider, and light and dark are the same logic in two modes (the macOS branch is fixed to light — the package on macOS is only compiled and tested).
- `DesignSystem.swift` — the shared parts: page background, brand mark, hairline blocks, bare type, type in a circle, section labels, status text, result hero images, two button styles and list shading.

The rule: **everything we draw is flat** — no gradients, no glows, no shadows, no cards, no tinted icon tiles; layering comes only from hairlines and whitespace. The primary button is `KeyrefPrimaryButtonStyle` (a solid block in the foreground colour with page-coloured text), the secondary is `KeyrefSecondaryButtonStyle` (the same shape, outlined); every other control (Toggle / Picker / SecureField / searchable / navigation bar / Tab bar / bottom accessory) is stock SwiftUI, and the accent follows `.tint(KeyrefTheme.tint)` — it tracks the foreground colour instead of dyeing controls.

Where the system supplies the material (navigation bar, Tab bar, bottom accessory), do not imitate it by hand; the custom controls that genuinely float above content (the collapse/copy buttons on the plaintext slab, the sync capsule, the flashlight on the scanner page) use `glassEffect` rather than hand-drawn translucency — see docs/ios-ui.md §3.8. Recovery codes and raw argv are not floating layers; they are solid plaintext slabs.

`ref`, fingerprints, masks and recovery codes are always monospace; timestamps use the compact form `2026-11-01 04:37` (a long Chinese date does not fit in a label–value row and gets truncated to 「2026年11月1日 04:…」).

### Simulator UI end-to-end (optional)

```sh
scripts/dev/ui-test.sh
```

It starts a real `keyref-server` (`KEYREF_ENFORCE_QUOTAS=1`, so creating a vault also exercises PoW), then drives the real app on the iPhone 17 simulator: create a vault (including the recovery-code confirmation) → add an item → cold-start unlock → pair the CLI through the simulator's paste entry point (the test process acts as the CLI and checks pair/status and the grant). It needs a local `go`; it only runs on macOS.

- The unit and flow tests still run under the default scheme (`KeyrefCoreTests` + `KeyrefUITests`); the UI automation lives in its own `KeyrefUIAutomation` scheme so it does not slow the default gate.
- DEBUG builds use `Info-Debug.plist` to allow plain-HTTP loopback for `127.0.0.1` (`NSAllowsLocalNetworking`); Release keeps using `Info.plist` and does not relax ATS. The UI test launch arguments (`-keyref-reset`, `-keyref-origin`, `-keyref-assume-prerequisites`, `-keyref-skip-push`, `-keyref-auto-auth`, `-keyref-initial-tab`) are all compiled under `#if DEBUG` and ignored in Release builds.
- The simulator has no camera, so pairing goes through the paste entry point of `NoCameraView`; the floating glass Tab bar of iOS 26/27 does not accept taps under XCUITest, so the tests cold-start into the target tab with `-keyref-initial-tab`.

The interface spec is [docs/ios-ui.md](../docs/ios-ui.md). Implemented: four tabs, create/recover/takeover/pair/revoke/audit/settings, the approval inbox (foreground polling + Face ID approval), fine-grained editing of allowCommands/allowedHosts, and online pairing with a second iPhone. Push (APNs) and the Plus purchase need Apple developer credentials and are wired up separately.
