// Second-iPhone pairing state (Phase 2, design §9.4 path 2): the new phone
// shows its join offer, the old phone scans it, confirms with Face ID, signs
// the two-owner directory and displays the VMK handoff back. The screen
// skeleton follows the existing pairing flow (scan → 核对 → 确认 → 完成).
import Foundation
import KeyrefCore

@Observable
@MainActor
public final class SecondDeviceFlowModel {
    public enum Role: Equatable, Sendable {
        case newPhone   // 出示「加入已有保险库」二维码
        case oldPhone   // 扫新手机、Face ID、把 VMK 交接回去
    }

    public enum Step: Equatable, Sendable {
        // 新手机
        case preparingOffer
        case showingOffer(JoinOffer)      // 新手机出示二维码，等旧手机扫
        case waitingHandoff(JoinOffer)    // 旧手机确认后，扫/粘回执
        case adopting
        case doneNew(itemCount: Int)
        // 旧手机
        case scanning
        case verifyOld(JoinOffer)         // 核对页：指纹、名字、origin
        case admitting
        case showingHandoff(String)       // 回执二维码（含 VMK 包裹）
        // 共用
        case failed(message: String)
    }

    public let role: Role
    public let backend: any AppBackend
    public let haptics: any Haptics

    public private(set) var step: Step
    public var torchOn = false
    /// 模拟器降级入口：新手机粘贴旧手机的回执码。
    public var manualHandoffInput = ""
    /// 旧手机核对页的 origin 不一致确认（S11 的 join 变体：不一致直接阻断）。
    public private(set) var originMismatch = false
    /// 新手机完成后的条目数（完成页摘要）。
    public private(set) var adoptedItemCount = 0

    public init(role: Role, backend: any AppBackend, haptics: any Haptics) {
        self.role = role
        self.backend = backend
        self.haptics = haptics
        step = role == .newPhone ? .preparingOffer : .scanning
    }

    // MARK: 新手机

    /// Generates this device's owner identity and the join offer.
    public func prepareOffer() async {
        guard case .preparingOffer = step else { return }
        do {
            let offer = try await backend.prepareJoinOffer(label: "这台 iPhone")
            haptics.fire(.success)
            step = .showingOffer(offer)
        } catch {
            step = .failed(message: "加入没有开始，没有更改任何东西。请重试。")
        }
    }

    /// 新手机出示二维码后进入等待回执页。
    public func beginWaitingForHandoff() {
        guard case .showingOffer(let offer) = step else { return }
        step = .waitingHandoff(offer)
    }

    /// 失败后重试：回到出码页并重新生成 offer。
    public func retryOffer() {
        guard case .failed = step, role == .newPhone else { return }
        step = .preparingOffer
        Task { await prepareOffer() }
    }

    /// 新手机扫描旧手机的回执码（或模拟器粘贴）后接管。
    public func submitHandoff(_ payload: String) async {
        guard case .waitingHandoff = step else { return }
        step = .adopting
        do {
            try await backend.adoptSecondDevice(handoffPayload: payload)
            let items = await backend.loadItems()
            adoptedItemCount = items.count
            haptics.fire(.success)
            step = .doneNew(itemCount: adoptedItemCount)
        } catch {
            haptics.fire(.error)
            step = .failed(message: "交接没有完成。回执码 10 分钟内有效，请让旧手机重新出码，再扫一次。")
        }
    }

    // MARK: 旧手机

    /// Handles a scanned payload: only a `keyref://join` offer counts (S7:
    /// other payloads keep scanning).
    public func handleScanned(_ payload: String) {
        guard case .scanning = step else { return }
        guard let offer = try? JoinOffer.parse(payload) else {
            return
        }
        haptics.fire(.lightImpact)
        originMismatch = offer.origin.host != backend.origin.host
            || offer.origin.port != backend.origin.port
        step = .verifyOld(offer)
    }

    /// Face ID（由调用方先认证）→ 签两台 owner 的目录 + 包裹 VMK → 回执码。
    /// origin 不一致时拒绝继续——owner 级交接不做静默切服务器。
    public func confirmAdmit(offer: JoinOffer, label: String,
                             authenticator: any BiometricAuthenticator) async {
        guard case .verifyOld = step else { return }
        guard !originMismatch else {
            haptics.fire(.warning)
            return
        }
        haptics.fire(.heavyImpact)
        let auth = await authenticator.authenticate(reason: "把保险库加入新的 iPhone")
        guard case .success = auth else {
            haptics.fire(.warning)
            return
        }
        step = .admitting
        do {
            let payload = try await backend.admitSecondDevice(offer: offer, label: label)
            haptics.fire(.success)
            step = .showingHandoff(payload)
        } catch {
            haptics.fire(.error)
            step = .failed(message: "加入没有完成，没有更改任何授权。请重试。")
        }
    }

    public func backToScanning() {
        step = .scanning
        originMismatch = false
    }
}
