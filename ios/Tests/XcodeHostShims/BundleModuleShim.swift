// Shim for the Xcode-hosted test targets only (not part of any SwiftPM
// target): SwiftPM generates a `Bundle.module` accessor for package test
// targets; these native unit-test bundles compile the same test sources and
// need an equivalent that points at the .xctest bundle.
import Foundation

extension Bundle {
    static let module: Bundle = {
        Bundle.allBundles.first { $0.bundleURL.pathExtension == "xctest" } ?? .main
    }()
}
