// swift-tools-version:6.2
import PackageDescription

// KeyrefCore is the UI-free core of the keyref iOS app: cryptography
// (docs/design.md §9), the wire-protocol client (docs/protocol.md) and the
// sync engine (design §10.6). HPKE comes from the system CryptoKit, so the
// package has no external dependencies. Deployment target is iOS 26 /
// macOS 26 (design §12.1, ios-ui §3.8: Liquid Glass), applied package-wide —
// KeyrefCore itself needs none of it but shares the floor.
let package = Package(
    name: "KeyrefCore",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
    ],
    products: [
        .library(name: "KeyrefCore", targets: ["KeyrefCore"]),
        .library(name: "KeyrefUI", targets: ["KeyrefUI"]),
    ],
    targets: [
        .target(
            name: "KeyrefCore",
            path: "Sources/KeyrefCore"
        ),
        // All SwiftUI views and view models (docs/ios-ui.md). Built on top of
        // KeyrefCore only; compiles on macOS too so `swift test` stays green.
        .target(
            name: "KeyrefUI",
            dependencies: ["KeyrefCore"],
            path: "Sources/KeyrefUI"
        ),
        .testTarget(
            name: "KeyrefCoreTests",
            dependencies: ["KeyrefCore"],
            path: "Tests/KeyrefCoreTests",
            resources: [
                .copy("Fixtures"),
            ]
        ),
        // Unit tests for the UI stores/view models (mocked dependencies, no
        // Keychain or network). Runs on both macOS (`swift test`) and the
        // iOS simulator (xcodebuild test).
        .testTarget(
            name: "KeyrefUITests",
            dependencies: ["KeyrefUI"],
            path: "Tests/KeyrefUITests"
        ),
    ]
)
