// Second-iPhone pairing views (Phase 2, design §9.4 path 2, docs/ios-ui.md
// §5 的旧手机扫新手机配对页): the new phone displays its join offer, the old
// phone scans → 核对（指纹最显眼、origin 不一致阻断）→ Face ID → displays the
// VMK handoff back. Screen skeleton mirrors the existing pairing flow
// (DeviceViews §2.8) and the recovery progress checklist.
import SwiftUI
import CoreImage.CIFilterBuiltins
import KeyrefCore

// MARK: - flow root

struct SecondDeviceFlowView: View {
    let app: AppModel
    let role: SecondDeviceFlowModel.Role
    @State private var model: SecondDeviceFlowModel?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Group {
            if let model {
                SecondDeviceFlowBody(app: app, model: model) { dismiss() }
            } else {
                ProgressView()
            }
        }
        .onAppear {
            if model == nil {
                model = SecondDeviceFlowModel(role: role, backend: app.backend,
                                              haptics: app.haptics)
                if role == .newPhone {
                    Task { await model?.prepareOffer() }
                }
            }
        }
        .navigationTitle(role == .newPhone ? "加入已有保险库" : "添加另一台 iPhone")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("关闭") { dismiss() }
            }
        }
    }
}

struct SecondDeviceFlowBody: View {
    let app: AppModel
    @Bindable var model: SecondDeviceFlowModel
    let onClose: () -> Void

    var body: some View {
        Group {
            switch model.step {
            case .preparingOffer:
                ProgressView("正在生成这台手机的密钥…")
            case .showingOffer(let offer):
                JoinOfferPage(offer: offer) {
                    model.beginWaitingForHandoff()
                }
            case .waitingHandoff:
                JoinHandoffInputPage(model: model)
            case .adopting:
                ProgressView("正在接管保险库…")
            case .doneNew(let itemCount):
                JoinDoneNewPage(itemCount: itemCount) { onClose() }
            case .scanning:
                JoinScanPage(app: app, model: model)
            case .verifyOld(let offer):
                JoinVerifyPage(app: app, model: model, offer: offer)
            case .admitting:
                ProgressView("正在签署设备目录…")
            case .showingHandoff(let payload):
                JoinHandoffShowPage(payload: payload) { onClose() }
            case .failed(let message):
                JoinFailedPage(message: message) {
                    if model.role == .newPhone {
                        model.retryOffer()
                    } else {
                        model.backToScanning()
                    }
                }
            }
        }
    }
}

// MARK: - 新手机

/// 新手机出示「加入已有保险库」二维码（含隔区 P-256 HPKE 公钥与签名公钥，
/// §9.4）。替代文本按 §3.6：这是配对码，内容是设备公钥，不含任何秘密。
struct JoinOfferPage: View {
    let offer: JoinOffer
    let onContinue: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Text("让旧手机扫这个码")
                .font(.title3.weight(.semibold))
            Text("旧手机会用 Face ID 确认，把这台手机加入它的保险库。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            QRCodeView(payload: offer.payload(), size: 220)
                .accessibilityLabel("这是配对码，内容是设备公钥，不含任何秘密")
            VStack(alignment: .leading, spacing: 6) {
                LabeledContent("设备名", value: offer.label)
                LabeledContent("同步服务器", value: offer.origin.absoluteString)
                    .font(.callout.monospaced())
            }
            .font(.callout)
            .padding(.horizontal, 8)
            Spacer()
            Button {
                onContinue()
            } label: {
                Text("旧手机已扫码，下一步")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glassProminent)
        }
        .padding(24)
    }
}

/// 新手机等待并接收旧手机的 VMK 交接码：相机扫描；模拟器降级为粘贴。
struct JoinHandoffInputPage: View {
    @Bindable var model: SecondDeviceFlowModel

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "arrow.left.arrow.right.circle.fill")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("用这台手机扫旧手机上的交接码")
                .font(.title3.weight(.semibold))
                .multilineTextAlignment(.center)
            Text("旧手机确认后会显示一个交接码。它里面是加密后的主密钥包裹，只有这台手机能解开。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            #if os(iOS) && !targetEnvironment(simulator)
            JoinHandoffScanner(model: model)
            #else
            VStack(alignment: .leading, spacing: 8) {
                Text("模拟器入口：粘贴 keyref://handoff?… 交接码")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                TextField("keyref://handoff?v=1&…", text: $model.manualHandoffInput)
                    .textFieldStyle(.roundedBorder)
                    .font(.footnote.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("接收交接") {
                    Task { await model.submitHandoff(model.manualHandoffInput) }
                }
                .buttonStyle(.glassProminent)
                .disabled(model.manualHandoffInput.isEmpty)
            }
            #endif
        }
        .padding(24)
    }
}

#if os(iOS)
/// 交接码相机层（真机构建；模拟器用粘贴降级，真机行为留待真机验证）。
struct JoinHandoffScanner: View {
    @Bindable var model: SecondDeviceFlowModel
    @State private var scanner: QRScannerCoordinator?

    var body: some View {
        ZStack {
            if let scanner {
                switch scanner.state {
                case .running, .idle:
                    CameraPreview(scanner: scanner)
                        .frame(height: 320)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                case .permissionDenied:
                    VStack(spacing: 8) {
                        Text("相机权限已关闭。")
                            .font(.callout)
                        Text("交接码也可以由旧手机以受信任的方式当面送达——到系统设置里打开相机权限后扫描。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                case .noCamera:
                    Text("此设备没有可用相机。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } else {
                RoundedRectangle(cornerRadius: 16)
                    .fill(Color.secondary.opacity(0.1))
                    .frame(height: 320)
            }
        }
        .onAppear {
            let coordinator = QRScannerCoordinator()
            coordinator.onPayload = { payload in
                Task { await model.submitHandoff(payload) }
            }
            scanner = coordinator
            coordinator.start()
        }
        .onDisappear {
            scanner?.stop()
        }
    }
}
#endif

/// 新手机完成页：接管后能解全部条目（摘要给条目数）。
struct JoinDoneNewPage: View {
    let itemCount: Int
    let onFinish: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 48))
                .foregroundStyle(.green)
            Text("已加入保险库")
                .font(.title2.weight(.semibold))
            Text("这台手机现在是第二台 owner 设备，\(itemCount) 条条目已经同步并可以解开。两台手机都能创建和修改条目。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Text("恢复码没有变化，仍然是唯一的恢复凭证。")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            Button("进入保险库") { onFinish() }
                .buttonStyle(.glassProminent)
        }
        .padding(28)
    }
}

// MARK: - 旧手机

/// 扫新手机的 join 二维码（S7 变体：其他码保持扫描）。
struct JoinScanPage: View {
    let app: AppModel
    @Bindable var model: SecondDeviceFlowModel

    var body: some View {
        #if os(iOS)
        iOSBody
        #else
        VStack(spacing: 16) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("扫描需要在 iOS 设备上运行。")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(28)
        #endif
    }

    #if os(iOS)
    @State private var scanner: QRScannerCoordinator?

    var iOSBody: some View {
        ZStack {
            if let scanner {
                switch scanner.state {
                case .running, .idle:
                    CameraPreview(scanner: scanner)
                        .ignoresSafeArea()
                case .permissionDenied:
                    PermissionDeniedView(app: app)
                case .noCamera:
                    VStack(spacing: 12) {
                        Text("此设备没有可用相机")
                            .font(.title3.weight(.semibold))
                        Text("用新手机屏幕上的二维码对准取景框。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .padding(28)
                }
            } else {
                Color.black.ignoresSafeArea()
            }
            VStack {
                Spacer()
                VStack(spacing: 8) {
                    Text("用旧手机扫新手机的二维码")
                        .font(.headline)
                        .foregroundStyle(.white)
                    Text("确认屏幕前的人与设备之后，这台手机会把保险库的主密钥交接过去。")
                        .font(.callout)
                        .foregroundStyle(.white.opacity(0.9))
                        .multilineTextAlignment(.center)
                }
                .padding(16)
                .background(.black.opacity(0.55), in: RoundedRectangle(cornerRadius: 14))
                .padding(20)
            }
        }
        .ignoresSafeArea()
        .onAppear {
            let coordinator = QRScannerCoordinator()
            coordinator.onPayload = { payload in
                model.handleScanned(payload)
            }
            scanner = coordinator
            coordinator.start()
        }
        .onDisappear {
            scanner?.stop()
        }
    }
    #endif
}

/// 核对页（S10/S11 骨架）：指纹最显眼；origin 不一致直接阻断——owner 级
/// 交接不做静默切服务器（§8.1 步骤 4 的从严变体）。
struct JoinVerifyPage: View {
    let app: AppModel
    @Bindable var model: SecondDeviceFlowModel
    let offer: JoinOffer

    var body: some View {
        Form {
            Section("新设备") {
                LabeledContent("名称", value: offer.label)
                VStack(alignment: .leading, spacing: 6) {
                    Text("指纹")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    FingerprintText(fingerprint: offer.fingerprint)
                    Text("与新手机屏幕上显示的指纹逐组核对")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            Section {
                LabeledContent("新手机的服务器", value: offer.origin.absoluteString)
                    .font(.callout.monospaced())
                LabeledContent("本机当前", value: app.backend.origin.absoluteString)
                    .font(.callout.monospaced())
                if model.originMismatch {
                    WarningCard(
                        title: "新手机连着另一台服务器",
                        body_: "这台 iPhone 同步到 \(offer.origin.host ?? "")，本机同步到 \(app.backend.origin.host ?? "")。两台 owner 必须在同一个服务器上才能共享保险库。请先在其中一台设备的设置里改到相同的 origin，再回来继续。")
                }
            } header: {
                Text("同步服务器")
            } footer: {
                Text("确认后，新手机会进入签名过的设备目录，并拿到主密钥的加密包裹。")
            }
            Section {
                Button {
                    Task {
                        await model.confirmAdmit(offer: offer, label: offer.label,
                                                 authenticator: app.authenticator)
                    }
                } label: {
                    Text(model.originMismatch ? "服务器不一致，无法继续" : "用 Face ID 确认交接")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .disabled(model.originMismatch)
                Button("重新扫描") {
                    model.backToScanning()
                }
            }
        }
        .navigationTitle("核对交接")
        .navigationBarTitleDisplayMode(.inline)
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }
}

/// 旧手机出示 VMK 交接码（§9.4：Face ID 之后把 VMK HPKE 给新手机的 P-256
/// 公钥）。密文只有新手机能解开，但仍然只当面展示。
struct JoinHandoffShowPage: View {
    let payload: String
    let onFinish: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("目录已更新，两台 iPhone 都是 owner")
                .font(.title3.weight(.semibold))
                .multilineTextAlignment(.center)
            Text("把这个交接码给新手机扫。它只对那台手机的密钥有效。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            QRCodeView(payload: payload, size: 220)
                .accessibilityLabel("这是交接码，内容是只有新手机能解开的主密钥加密包裹")
            Text("交接完成后，这个码就作废了。不要截图或转发。")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            Button("完成") { onFinish() }
                .buttonStyle(.glassProminent)
        }
        .padding(24)
    }
}

struct JoinFailedPage: View {
    let message: String
    let onRetry: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "xmark.octagon.fill")
                .font(.system(size: 48))
                .foregroundStyle(.red)
            Text(message)
                .font(.callout)
                .multilineTextAlignment(.center)
            Spacer()
            Button("重试") { onRetry() }
                .buttonStyle(.glassProminent)
        }
        .padding(28)
    }
}

// MARK: - QR rendering

/// Renders a payload as a QR image via CoreImage. The two hand-off codes
/// carry public keys / ciphertext only (the VMK wrap is ciphertext keyed to
/// the new phone); the accessibility labels spell out what each code is.
struct QRCodeView: View {
    let payload: String
    var size: CGFloat = 200

    var body: some View {
        Group {
            if let image = Self.qrImage(payload: payload) {
                #if os(macOS)
                Image(decorative: image, scale: 1.0)
                #else
                Image(uiImage: UIImage(cgImage: image))
                    .interpolation(.none)
                #endif
            } else {
                Image(systemName: "qrcode")
                    .font(.system(size: 44))
                    .foregroundStyle(.secondary)
            }
        }
        .frame(width: size, height: size)
        .accessibilityElement(children: .ignore)
    }

    static func qrImage(payload: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        let context = CIContext()
        return context.createCGImage(scaled, from: scaled.extent)
    }
}
