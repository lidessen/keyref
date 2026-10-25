// Devices tab state (docs/ios-ui.md §2.7–§2.10): the device overview, the
// scan→verify→select→complete pairing flow, grant add/revoke, and the
// dedicated revoke page with its default-checked rotation option (B6).
import Foundation
import KeyrefCore

@Observable
@MainActor
public final class DevicesStore {
    let backend: any AppBackend
    let haptics: any Haptics

    public private(set) var rows: [DeviceRow] = []
    public private(set) var items: [ItemRow] = []
    public var revokedExpanded = false
    public var toast: String?

    /// 免费档只有 1 台 CLI 配额（§10.5）。
    public var cliQuotaReached: Bool {
        rows.filter { $0.isCLI && !$0.isRevoked }.count >= 1
    }

    public init(backend: any AppBackend, haptics: any Haptics) {
        self.backend = backend
        self.haptics = haptics
    }

    public func refresh() async {
        rows = await backend.loadDevices()
        items = await backend.loadItems()
    }

    public var activeCLI: [DeviceRow] {
        rows.filter { $0.isCLI && !$0.isRevoked }
    }

    public var revoked: [DeviceRow] {
        rows.filter { $0.isRevoked }
    }

    public func device(id: String) -> DeviceRow? {
        rows.first { $0.id == id }
    }

    public func itemName(_ itemID: String) -> String {
        items.first { $0.id == itemID }?.name ?? itemID
    }

    // MARK: grants (§2.9)

    @discardableResult
    public func revokeGrant(deviceID: String, itemID: String, kind: String) async -> Bool {
        do {
            try await backend.revokeGrant(deviceID: deviceID, itemID: itemID, kind: kind)
            await refresh()
            toast = "已收回"
            return true
        } catch {
            haptics.fire(.error)
            toast = "收回没有完成，请重试。"
            return false
        }
    }

    @discardableResult
    public func appendGrants(deviceID: String, selections: [GrantSelection]) async -> Bool {
        do {
            try await backend.appendGrants(deviceID: deviceID, selections)
            await refresh()
            toast = "已授予 \(selections.count) 条"
            return true
        } catch {
            haptics.fire(.error)
            toast = "授予没有完成，请重试。"
            return false
        }
    }

    public func rename(deviceID: String, label: String) async {
        try? await backend.renameDevice(deviceID: deviceID, label: label)
        await refresh()
    }
}

// MARK: - pairing flow (§2.8)

/// scan → 核对页（指纹 + origin，S10/S11）→ 勾选页（默认全不选）→ 完成。
@Observable
@MainActor
public final class PairingFlowModel {
    public enum Step: Equatable, Sendable {
        case scanning
        case verify(PairingOffer)
        case select(PairingOffer)
        case completing
        case done(deviceLabel: String)
        case failed(message: String)
    }

    public let backend: any AppBackend
    public let haptics: any Haptics
    public private(set) var step: Step = .scanning
    /// 勾选页：全部条目默认不勾选（§15）。
    public var selected: Set<String> = []
    public var originMismatchConfirmed = false
    public var deviceLabel = ""
    public var torchOn = false

    public init(backend: any AppBackend, haptics: any Haptics) {
        self.backend = backend
        self.haptics = haptics
    }

    public var currentOrigin: URL { backend.origin }
    public var itemCount: Int { selected.count }

    /// S11: 配对码指向另一台服务器。
    public func originMismatch(_ offer: PairingOffer) -> Bool {
        offer.origin.host != backend.origin.host
            || offer.origin.port != backend.origin.port
    }

    public func handlePayload(_ payload: String, items: [ItemRow]) {
        guard let offer = try? PairingOffer.parse(payload) else {
            return  // not a keyref pair code — keep scanning (S7)
        }
        haptics.fire(.lightImpact)
        deviceLabel = offer.label
        step = .verify(offer)
    }

    /// S11 pre-check (§8.5): 切换前先探测新 origin 上是否存在本 vault。
    public func probeTargetOrigin() async -> Bool {
        guard case .verify(let offer) = step else { return true }
        return await backend.probeVaultExists(onOrigin: offer.origin)
    }

    /// 核对页「继续」→ 勾选页。
    public func proceedToSelection(_ offer: PairingOffer) {
        step = .select(offer)
    }

    /// 「切换并继续」：确认后手机才改自己的服务器 URL（§8.1 步骤 4）。
    public func confirmOriginSwitch(to offer: PairingOffer) async {
        switching = true
        defer { switching = false }
        do {
            try await backend.switchOrigin(to: offer.origin) { _ in }
            step = .select(offer)
        } catch {
            haptics.fire(.error)
            step = .failed(message: "切换服务器没有完成。没有授予任何条目，请重试。")
        }
    }

    /// 切换进行中标志（核对页按钮态）。
    public var switching = false

    public func toggle(_ itemID: String) {
        haptics.fire(.lightImpact)
        if selected.contains(itemID) {
            selected.remove(itemID)
        } else {
            selected.insert(itemID)
        }
    }

    /// Face ID 确认（N 条）→ complete. N=0 时按钮禁用并显示
    /// 「至少勾选一条，或直接取消配对」。
    public func complete(grantSelections: [GrantSelection], items: [ItemRow],
                         authenticator: any BiometricAuthenticator) async {
        guard case .select(let offer) = step else { return }
        let result = await authenticator.authenticate(reason: "确认配对并授予 \(selected.count) 条条目")
        guard case .success = result else {
            haptics.fire(.warning)
            return
        }
        step = .completing
        do {
            try await backend.completePairing(offer: offer,
                                              deviceLabel: deviceLabel,
                                              selections: grantSelections)
            haptics.fire(.success)
            step = .done(deviceLabel: deviceLabel)
        } catch let e as APIError {
            haptics.fire(.error)
            switch e {
            case .pairExpired:
                step = .failed(message: "配对码已过期。在终端重新运行 keyref pair，再扫一次。")
            case .unexpected:
                step = .failed(message: "这个配对码已被使用。")
            default:
                step = .failed(message: "配对没有完成，没有授予任何条目。请重试。")
            }
        } catch {
            haptics.fire(.error)
            step = .failed(message: "配对没有完成，没有授予任何条目。请重试。")
        }
    }

    public func cancel() {
        step = .scanning
        selected = []
        originMismatchConfirmed = false
    }
}

// MARK: - revoke flow (§2.10)

/// 专用页（不是弹窗——要解释 B6、放默认勾选的轮换选项和一个次级「仅停用」）。
@Observable
@MainActor
public final class RevokeFlowModel {
    public enum Phase: Equatable, Sendable {
        case configuring
        case running
        case done
        /// 轮换中途中断（网络断开）：撤销已生效，轮换可重入（§2.10 失败态）。
        case interrupted(remaining: Int)
        case failed(message: String)
    }

    public let backend: any AppBackend
    public let haptics: any Haptics
    public let device: DeviceRow
    public let itemName: (String) -> String

    /// 「同时轮换这 M 条条目的密钥」— 默认勾选（§8.4 默认动作）。
    public var rotateSelected = true
    public private(set) var phase: Phase = .configuring
    public private(set) var remaining = 0

    public var useGrantCount: Int {
        device.grants.filter { $0.kind == "use" }.count
    }

    public var grantCount: Int {
        device.grants.count
    }

    public init(backend: any AppBackend, haptics: any Haptics,
                device: DeviceRow, itemName: @escaping (String) -> String) {
        self.backend = backend
        self.haptics = haptics
        self.device = device
        self.itemName = itemName
        self.remaining = device.grants.filter { $0.kind == "use" }.count
    }

    /// 撤销并轮换 M 条 → Face ID（由调用方先认证）。
    public func run(authenticator: any BiometricAuthenticator) async {
        haptics.fire(.heavyImpact)
        let result = await authenticator.authenticate(reason: "撤销设备 \(device.label)")
        guard case .success = result else {
            haptics.fire(.warning)
            return
        }
        phase = .running
        do {
            _ = try await backend.revokeDevice(deviceID: device.id, rotate: rotateSelected) { [weak self] step in
                guard let self else { return }
                if case .rotation(let remaining) = step {
                    Task { @MainActor in self.remaining = remaining }
                }
            }
            haptics.fire(.success)
            phase = .done
        } catch {
            haptics.fire(.error)
            if rotateSelected, pendingRotationActive(deviceID: device.id) {
                phase = .interrupted(remaining: max(remaining, 1))
            } else {
                phase = .failed(message: "撤销没有完成。那台设备还没有被停用，请重试。")
            }
        }
    }

    public func resume(authenticator: any BiometricAuthenticator) async {
        phase = .running
        do {
            _ = try await backend.resumeRotation(deviceID: device.id) { [weak self] step in
                guard let self else { return }
                if case .rotation(let remaining) = step {
                    Task { @MainActor in self.remaining = remaining }
                }
            }
            haptics.fire(.success)
            phase = .done
        } catch {
            haptics.fire(.error)
            phase = .interrupted(remaining: max(remaining, 1))
        }
    }

    func pendingRotationActive(deviceID: String) -> Bool {
        backend.hasPendingRotation(deviceID: deviceID)
    }
}
