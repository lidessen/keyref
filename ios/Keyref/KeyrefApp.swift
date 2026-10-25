// keyref iOS app entry: builds the live dependency graph (Keychain-backed
// KeyStore, real LocalAuthentication, local-only clipboard) and hands it to
// the KeyrefUI root view. All product behaviour lives in the KeyrefUI target.
import SwiftUI
import KeyrefCore
import KeyrefUI

@main
struct KeyrefApp: App {
    @State private var app: AppModel

    init() {
        let backend = LiveBackend(
            keyStore: KeychainKeyStore(service: "app.keyref.ios"),
            stateStore: UIStateStore(),
            origin: URL(string: "https://sync.keyref.app")!)
        _app = State(initialValue: AppModel(
            backend: backend,
            authenticator: LiveBiometricAuthenticator(),
            haptics: LiveHaptics(),
            clipboard: LiveClipboard(),
            systemOpener: LiveSystemOpener()))
    }

    var body: some Scene {
        WindowGroup {
            RootView(app: app)
                .tint(.orange)
        }
    }
}
