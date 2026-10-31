// DEBUG-only UI-automation hooks. Release builds do not contain this file's
// code path (the flag is compiled out at the call sites).
import Foundation

#if DEBUG
public enum KeyrefUITestHooks {
    /// Simulators have no passcode/biometry enrolled; the creation UI's
    /// prerequisite gate would never open. Set by the app from
    /// `-keyref-assume-prerequisites` in DEBUG builds only.
    nonisolated(unsafe) public static var assumePrerequisitesSatisfied = false
    /// Skip the notification-authorization prompt (which would block UI
    /// automation with a system alert). Only the prompt is skipped; the
    /// approval inbox still works via foreground polling.
    nonisolated(unsafe) public static var skipPushRegistration = false
    /// Show the simulator-only manual-paste pairing view directly. The
    /// simulator reports its (absent) camera inconsistently across Xcode
    /// versions; this makes the paste path deterministic for UI tests.
    nonisolated(unsafe) public static var forceNoCamera = false
}
#endif
