// Compatibility shims so the iOS-first view code also compiles on macOS
// (the package tests run there via `swift test`). These are no-ops or
// nearest-equivalents; behaviour only matters on iOS where the app runs.
import SwiftUI

#if os(macOS)

/// iOS-only enum placeholder.
enum NavigationBarItemShim { case inline, large, automatic }

extension View {
    /// No-op: title display mode is iOS-only chrome.
    func navigationBarTitleDisplayMode(_ mode: NavigationBarItemShim) -> some View {
        self
    }

    /// Sheets stand in for full-screen covers on macOS.
    func fullScreenCover<Content: View>(isPresented: Binding<Bool>,
                                        @ViewBuilder content: @escaping () -> Content) -> some View {
        sheet(isPresented: isPresented, content: content)
    }

    /// No-op.
    func textInputAutocapitalization(_ autocapitalization: AutocapitalizationShim?) -> some View {
        self
    }

    /// No-op.
    func keyboardType(_ type: UIKeyboardTypeShim) -> some View {
        self
    }

}

/// Placeholders so iOS-only enum cases parse on macOS.
enum UIKeyboardTypeShim {
    case URL
}

enum AutocapitalizationShim {
    case never
}

extension ToolbarItemPlacement {
    static var topBarLeading: ToolbarItemPlacement { .automatic }
    static var topBarTrailing: ToolbarItemPlacement { .automatic }
    static var topBarLanding: ToolbarItemPlacement { .automatic }
    static var keyboard: ToolbarItemPlacement { .automatic }
    static var bottomBar: ToolbarItemPlacement { .automatic }
    static var navigationBarLeadingShim: ToolbarItemPlacement { .automatic }
}

#endif

public extension Color {
    /// Semantic background that exists on both platforms.
    static var keyrefBackground: Color {
        #if os(macOS)
        return Color(nsColor: .windowBackgroundColor)
        #else
        return Color(uiColor: .systemBackground)
        #endif
    }
}
