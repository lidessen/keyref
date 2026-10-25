// Face ID behind an injectable protocol (docs/ios-ui.md §3.1): the LA system
// dialog performs the authentication, but the self-drawn lock screen always
// sits underneath it (the dialog can be cancelled; the content layer must
// never show through). No passcode fallback — `.biometryCurrentSet` enclave
// keys do not accept the device passcode (design §9.2); a fake button would
// be a lie.
import Foundation
import LocalAuthentication

/// Availability of the current biometric set, mapped from LAContext.
public enum BiometryAvailability: Equatable, Sendable {
    case available
    case unavailable(reason: String)
}

public enum BiometricError: Error, Equatable {
    /// The user cancelled, or the system dialog was dismissed (§3.1).
    case cancelled
    /// Authentication ran and failed (S3: 包裹完好，重试即可).
    case failed
    /// Biometry is not enrolled / not available at all.
    case notAvailable(String)
    /// Any other LAError.
    case other(String)
}

public protocol BiometricAuthenticator: Sendable {
    /// Whether the current biometric set can be used right now.
    func availability() -> BiometryAvailability
    /// Runs one authentication. The reason is shown by the system dialog.
    func authenticate(reason: String) async -> Result<Void, BiometricError>
}

/// Live LocalAuthentication wrapper.
public struct LiveBiometricAuthenticator: BiometricAuthenticator {
    public init() {}

    public func availability() -> BiometryAvailability {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .unavailable(reason: error?.localizedDescription ?? "Biometry unavailable")
        }
        return .available
    }

    public func authenticate(reason: String) async -> Result<Void, BiometricError> {
        let context = LAContext()
        context.localizedFallbackTitle = ""  // no passcode fallback button (§3.1)
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .failure(.notAvailable(error?.localizedDescription ?? "unavailable"))
        }
        do {
            let ok = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason)
            return ok ? .success(()) : .failure(.failed)
        } catch let e as LAError {
            switch e.code {
            case .userCancel, .systemCancel, .appCancel, .userFallback:
                return .failure(.cancelled)
            case .authenticationFailed:
                return .failure(.failed)
            case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout, .passcodeNotSet:
                return .failure(.notAvailable(e.localizedDescription))
            default:
                return .failure(.other(e.localizedDescription))
            }
        } catch {
            return .failure(.other(error.localizedDescription))
        }
    }
}

/// Deterministic mock for tests and previews.
public final class MockBiometricAuthenticator: BiometricAuthenticator, @unchecked Sendable {
    public var available: BiometryAvailability
    /// Queued results; the last one repeats. `.success` on an empty queue.
    public var queue: [Result<Void, BiometricError>]
    public private(set) var calls: [String] = []

    public init(available: BiometryAvailability = .available,
                queue: [Result<Void, BiometricError>] = []) {
        self.available = available
        self.queue = queue
    }

    public func availability() -> BiometryAvailability { available }

    public func authenticate(reason: String) async -> Result<Void, BiometricError> {
        calls.append(reason)
        if queue.isEmpty { return .success(()) }
        return queue.count == 1 ? queue[0] : queue.removeFirst()
    }
}
