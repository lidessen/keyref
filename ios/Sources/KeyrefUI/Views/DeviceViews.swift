// Devices tab (docs/ios-ui.md §2.7 device list, §2.8 scan pairing with S7 /
// S10 / S11, §2.9 device detail + grant management, §2.10 dedicated revoke
// page with the default-checked rotation and the B6 copy).
import SwiftUI
import KeyrefCore

// MARK: - 2.7 device list

struct DeviceListView: View {
    let app: AppModel
    @Bindable var devices: DevicesStore
    @State private var showPairing = false
    @State private var showSecondDevice = false

    init(app: AppModel) {
        self.app = app
        _devices = Bindable(wrappedValue: app.devices)
    }

    var localDevice: DeviceRow? {
        devices.rows.first { !$0.isCLI }
    }

    var body: some View {
        NavigationStack {
            List {
                approvalsSection
                if devices.activeCLI.isEmpty && devices.revoked.isEmpty {
                    emptySection
                } else {
                    deviceSections
                }
            }
            .keyrefListSurface()
            .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
            .navigationTitle("设备")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showPairing = true
                    } label: {
                        Image(systemName: "qrcode.viewfinder")
                    }
                    .disabled(devices.cliQuotaReached)
                    .accessibilityLabel(devices.cliQuotaReached
                                        ? "扫码配对——免费档限 1 台 CLI 设备" : "扫码配对")
                }
            }
            .overlay(alignment: .bottom) {
                if devices.cliQuotaReached {
                    Text("免费档限 1 台 CLI 设备")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding(.bottom, 12)
                }
                if let toast = devices.toast {
                    ToastView(text: toast)
                        .task {
                            try? await Task.sleep(for: .seconds(2))
                            devices.toast = nil
                        }
                }
            }
            .fullScreenCover(isPresented: $showPairing) {
                PairingFlowView(app: app)
            }
            // 配对完成回到列表时必须刷新：新 CLI 只有在签名目录落库后
            // 才可见（loadDevices 读目录），不刷新会显示陈旧的空列表。
            .onChange(of: showPairing) { _, shown in
                if !shown {
                    Task { await devices.refresh() }
                }
            }
            .fullScreenCover(isPresented: $showSecondDevice) {
                NavigationStack {
                    SecondDeviceFlowView(app: app, role: .oldPhone)
                }
            }
            .task {
                await devices.refresh()
                // 收件箱计数在设备页可见，进入时顺带拉一次（§14.4：打开时拉取）。
                await app.messages.refresh()
            }
        }
    }

    /// 待审批（Phase 2, §8.3）：设备 Tab 下的固定入口 + 角标。轮询由
    /// ApprovalsStore 只在 App 活跃时进行；这里只是入口。
    var approvalsSection: some View {
        Section {
            NavigationLink {
                MessageInboxView(app: app)
            } label: {
                HStack(spacing: 12) {
                    IconGlyph(systemName: "envelope", size: 20)
                    Text("收件箱")
                        .font(.body.weight(.medium))
                    Spacer()
                    if !app.messages.entries.isEmpty {
                        Text("\(app.messages.entries.count)")
                            .font(.caption.weight(.bold).monospacedDigit())
                            .foregroundStyle(KeyrefTheme.foreground)
                    }
                }
            }
            NavigationLink {
                ApprovalInboxView(app: app)
            } label: {
                HStack(spacing: 12) {
                    IconGlyph(systemName: "checkmark.shield.fill", size: 20)
                    Text("待审批")
                        .font(.body.weight(.medium))
                    Spacer()
                    if app.approvals.badgeCount > 0 {
                        // 角标是一粒琥珀小方点 + 数字：琥珀只在这里点一下。
                        HStack(spacing: 5) {
                            RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                                .fill(KeyrefTheme.accent)
                                .frame(width: 6, height: 6)
                            Text("\(app.approvals.badgeCount)")
                                .font(.caption.weight(.bold).monospacedDigit())
                                .foregroundStyle(KeyrefTheme.foreground)
                        }
                        .accessibilityLabel("\(app.approvals.badgeCount) 条待审批请求")
                    }
                }
            }
        } footer: {
            Text("采集设备上传的验证码在收件箱里，24 小时后自动销毁；agent 发起的 approval 请求在待审批里，2 分钟内有效。")
        }
    }

    var emptySection: some View {
        Section {
            VStack(spacing: 12) {
                KeyrefGlyphCircle(systemName: "laptopcomputer.and.iphone", size: 88)
                Text("还没有 agent 设备")
                    .font(.body.weight(.semibold))
                Text("在 agent 的机器上运行 keyref pair，然后用这台手机扫终端上的二维码。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Button("扫码配对") { showPairing = true }
                    .buttonStyle(KeyrefPrimaryButtonStyle())
                    .padding(.top, 4)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 24)
            .listRowBackground(Color.clear)
        }
    }

    var deviceSections: some View {
        Group {
            if let localDevice {
                Section {
                    NavigationLink {
                        LocalDeviceDetailView(app: app, device: localDevice)
                    } label: {
                        deviceRow(localDevice, subtitle: localDevice.isActive ? "正常" : "包裹已失效")
                    }
                    .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 0, trailing: 12))
                    .listRowBackground(Color.clear)
                    .listRowSeparatorTint(KeyrefTheme.hairline)
                } header: {
                    KeyrefSectionLabel(text: "本机")
                }
            }
            if !devices.activeCLI.isEmpty {
                Section {
                    ForEach(devices.activeCLI) { device in
                        NavigationLink {
                            DeviceDetailView(app: app, device: device)
                        } label: {
                            deviceRow(device, subtitle: device.isPending ? "等待确认" : device.fingerprint)
                        }
                        .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 0, trailing: 12))
                        .listRowBackground(Color.clear)
                        .listRowSeparatorTint(KeyrefTheme.hairline)
                    }
                } header: {
                    HStack {
                        KeyrefSectionLabel(text: "agent 设备")
                        Spacer()
                        Text("\(devices.activeCLI.count)")
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(KeyrefTheme.muted)
                    }
                    .padding(.horizontal, 4)
                }
            }
            // Phase 2（§9.4 path 2）：旧手机在线添加第二台 iPhone。
            Section {
                Button {
                    showSecondDevice = true
                } label: {
                    Label("添加另一台 iPhone", systemImage: "iphone.badge.plus")
                }
            }
            if !devices.revoked.isEmpty {
                Section("已撤销") {
                    DisclosureGroup(isExpanded: $devices.revokedExpanded) {
                        ForEach(devices.revoked) { device in
                            HStack {
                                Text(device.label)
                                    .foregroundStyle(.secondary)
                                Spacer()
                                Image(systemName: "checkmark.seal")
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    } label: {
                        Text("已撤销（\(devices.revoked.count)）")
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    func deviceRow(_ device: DeviceRow, subtitle: String) -> some View {
        HStack(spacing: 12) {
            IconGlyph(systemName: device.isCLI ? "terminal.fill" : "iphone", size: 20)
            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    Text(device.isCLI ? device.label : "这台 iPhone")
                        .font(.subheadline.weight(.semibold))
                    Spacer(minLength: 6)
                    statusBadge(device)
                }
                Text(subtitle)
                    .font(.caption)
                    .monospaced()
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if !device.grants.isEmpty {
                    Text("已授权 \(device.grants.count) 条")
                        .font(.caption2)
                        .foregroundStyle(KeyrefTheme.muted)
                }
            }
            Spacer(minLength: 0)
            if device.isPrimaryReceiver {
                StatusText(text: "主接收端", tint: KeyrefTheme.success, showDot: true)
            }
        }
        .padding(.vertical, 12)
    }

    @ViewBuilder
    func statusBadge(_ device: DeviceRow) -> some View {
        if device.isPending {
            StatusText(text: "等待确认", tint: KeyrefTheme.warning, showDot: true)
        } else if device.isActive {
            StatusText(text: "活跃", tint: KeyrefTheme.success, showDot: true)
        } else {
            StatusText(text: "已撤销", tint: KeyrefTheme.muted)
        }
    }
}

// MARK: - 2.8 pairing flow

struct PairingFlowView: View {
    let app: AppModel
    @State private var model: PairingFlowModel
    @Environment(\.dismiss) private var dismiss

    init(app: AppModel) {
        self.app = app
        _model = State(initialValue: PairingFlowModel(backend: app.backend, haptics: app.haptics))
    }

    var body: some View {
        NavigationStack {
            switch model.step {
            case .scanning:
                ScanPairingView(app: app, model: model)
            case .verify(let offer):
                PairVerifyView(app: app, model: model, offer: offer)
            case .select(let offer):
                GrantSelectionView(app: app, model: model, offer: offer, items: app.items.rows)
            case .completing:
                ProgressView("正在完成配对…")
            case .done(let label):
                PairDoneView(label: label) { dismiss() }
            case .failed(let message):
                PairFailedView(message: message) { model.cancel() }
            }
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("取消") { dismiss() }
            }
        }
    }
}

/// 取景页：全屏相机 + 取景框 + 手电筒；S7 引导与警示常驻。
/// 相机层只在 iOS 构建；其他平台显示占位说明。
struct ScanPairingView: View {
    let app: AppModel
    @Bindable var model: PairingFlowModel

    var body: some View {
        #if os(iOS)
        iOSBody
        #else
        VStack(spacing: 16) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("扫码配对需要在 iOS 设备上运行。")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(28)
        #endif
    }

    #if os(iOS)
    @State private var scanner: QRScannerCoordinator?
    @State private var torchOn = false

    var iOSBody: some View {
        ZStack {
            cameraLayer
            VStack {
                Spacer()
                VStack(spacing: 8) {
                    Text("在 agent 的机器上运行 keyref pair")
                        .font(.headline)
                        .foregroundStyle(.white)
                    Text("把终端上出现的二维码对准取景框。配对码 10 分钟内有效。")
                        .font(.callout)
                        .foregroundStyle(.white.opacity(0.9))
                        .multilineTextAlignment(.center)
                    Label("只扫你面前这台机器屏幕上的码——旁边的屏幕可能属于别人。",
                          systemImage: "exclamationmark.triangle")
                        .font(.footnote)
                        .foregroundStyle(.yellow)
                        .multilineTextAlignment(.leading)
                }
                .padding(16)
                .background(.black.opacity(0.55), in: RoundedRectangle(cornerRadius: 14))
                .padding(20)
            }
            VStack {
                HStack {
                    Spacer()
                    // §3.8：手电筒按钮用系统玻璃胶囊，不再手绘半透明圆底。
                    Button {
                        torchOn.toggle()
                        scanner?.setTorch(on: torchOn)
                    } label: {
                        Image(systemName: torchOn ? "flashlight.on.fill" : "flashlight.off.fill")
                            .font(.title3)
                            .foregroundStyle(torchOn ? .yellow : .primary)
                            .padding(12)
                    }
                    .glassEffect(.regular, in: Circle())
                    .accessibilityLabel(torchOn ? "关闭手电筒" : "打开手电筒")
                    .padding(.trailing, 16)
                }
                Spacer()
            }
        }
        .ignoresSafeArea()
        .onAppear {
            let coordinator = QRScannerCoordinator()
            coordinator.onPayload = { payload in
                model.handlePayload(payload, items: app.items.rows)
            }
            scanner = coordinator
            coordinator.start()
        }
        .onDisappear {
            scanner?.stop()
        }
    }

    @ViewBuilder
    var cameraLayer: some View {
        #if DEBUG && targetEnvironment(simulator)
        if KeyrefUITestHooks.forceNoCamera {
            NoCameraView(app: app, model: model)
        } else {
            scannerLayer
        }
        #else
        scannerLayer
        #endif
    }

    @ViewBuilder
    var scannerLayer: some View {
        if let scanner {
            switch scanner.state {
            case .running, .idle:
                CameraPreview(scanner: scanner)
                    .ignoresSafeArea()
            case .permissionDenied:
                PermissionDeniedView(app: app)
            case .noCamera:
                // NoCameraView (the manual-paste fallback) is
                // simulator-only (§3.2: no manual input on real devices);
                // a real device without a camera falls to the denied view,
                // which deep-links to Settings.
                #if targetEnvironment(simulator)
                NoCameraView(app: app, model: model)
                #else
                PermissionDeniedView(app: app)
                #endif
            }
        } else {
            Color.black.ignoresSafeArea()
        }
    }
    #endif
}

/// 相机权限被拒的降级路径：整页替换 + 系统设置深链（§3.2：不做相册识码、
/// 不做手动输入）。
struct PermissionDeniedView: View {
    let app: AppModel

    var body: some View {
        VStack(spacing: 18) {
            KeyrefGlyphCircle(systemName: "video.slash.fill", tint: KeyrefTheme.muted)
            Text("相机权限已关闭")
                .font(.title3.weight(.semibold))
            Text("配对码只能用相机扫描，keyref 不提供手动输入的替代路径。到系统设置里打开相机权限，回来继续。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("打开设置") {
                app.openSystemSettings()
            }
            .buttonStyle(KeyrefPrimaryButtonStyle())
        }
        .padding(28)
    }
}

/// 模拟器没有相机：优雅降级——提示 + 仅模拟器构建可见的手动粘贴入口。
/// 真机构建里这个路径不存在（编译期裁掉），不违反 §3.2。
#if os(iOS) && targetEnvironment(simulator)
struct NoCameraView: View {
    let app: AppModel
    @Bindable var model: PairingFlowModel
    @State private var manualPayload = ""

    var body: some View {
        VStack(spacing: 18) {
            KeyrefGlyphCircle(systemName: "camera.on.rectangle.fill", tint: KeyrefTheme.muted)
            Text("此设备没有可用相机")
                .font(.title3.weight(.semibold))
            Text("把终端上出现的二维码对准取景框。配对码 10 分钟内有效。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            VStack(alignment: .leading, spacing: 8) {
                Text("模拟器入口：粘贴 keyref://pair?… 配对码")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                TextField("keyref://pair?v=1&…", text: $manualPayload)
                    .textFieldStyle(.roundedBorder)
                    .font(.footnote.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("解析配对码") {
                    model.handlePayload(manualPayload, items: app.items.rows)
                }
                .buttonStyle(KeyrefPrimaryButtonStyle())
                .disabled(manualPayload.isEmpty)
            }
            .padding(.top, 8)
            Button("打开设置") {
                app.openSystemSettings()
            }
            .buttonStyle(KeyrefSecondaryButtonStyle())
        }
        .padding(28)
    }
}
#endif

/// 核对页（S10/S11）：设备名、指纹（最显眼）、origin 行与不一致警示卡。
struct PairVerifyView: View {
    let app: AppModel
    @Bindable var model: PairingFlowModel
    let offer: PairingOffer
    @State private var probing = false
    @State private var targetMissingVault = false

    var mismatch: Bool { model.originMismatch(offer) }

    var mainButtonLabel: String {
        if model.switching { return "切换中…" }
        return targetMissingVault ? "先迁移服务器" : "切换并继续"
    }

    var body: some View {
        Form {
            Section {
                HStack(spacing: 12) {
                    IconGlyph(systemName: "terminal.fill", size: 20)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("名称")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(offer.label)
                            .font(.headline)
                    }
                    Spacer(minLength: 0)
                }
                VStack(alignment: .leading, spacing: 7) {
                    Text("指纹")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    FingerprintText(fingerprint: offer.fingerprint)
                        .foregroundStyle(KeyrefTheme.foreground)
                    Text("与终端上印出的指纹逐组核对")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } header: {
                KeyrefSectionLabel(text: "设备")
            }
            Section("同步服务器") {
                LabeledContent("配对码指向", value: offer.origin.absoluteString)
                    .font(.callout.monospaced())
                LabeledContent("手机当前", value: app.backend.origin.absoluteString)
                    .font(.callout.monospaced())
                if mismatch {
                    WarningCard(
                        title: "配对码指向另一台服务器",
                        body_: "终端连接的是 \(offer.origin.host ?? "")，你的手机当前同步到 \(app.backend.origin.host ?? "")。继续配对会把手机切换到 \(offer.origin.host ?? "")：密文与授权关系将同步到那台服务器。加密强度不变，但你要确认自己信任它的运营者。")
                }
            }
            Section {
                if mismatch {
                    Button {
                        Task {
                            if probing { return }
                            probing = true
                            targetMissingVault = !(await model.probeTargetOrigin())
                            probing = false
                            if !targetMissingVault {
                                await model.confirmOriginSwitch(to: offer)
                            }
                        }
                    } label: {
                        if probing || model.switching {
                            ProgressView()
                        } else {
                            Text(mainButtonLabel)
                        }
                    }
                    .buttonStyle(KeyrefPrimaryButtonStyle())
                    .disabled(probing || model.switching)
                    if targetMissingVault {
                        Text("你的手机已有保险库，而这台服务器上还没有它。直接切过去只会得到一个空库——先迁移服务器。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Button {
                            // 深链 2.15：关闭配对，切到设置 Tab 的服务器页。
                            app.requestServerMigration = true
                        } label: {
                            Text("去迁移服务器")
                        }
                    }
                    Button("取消", role: .cancel) {
                        model.cancel()
                    }
                } else {
                    Button {
                        model.proceedToSelection(offer)
                    } label: {
                        Text("继续")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(KeyrefPrimaryButtonStyle())
                }
            }
        }
        .navigationTitle("核对配对")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .onAppear {
            targetMissingVault = false
        }
    }
}

/// 勾选页：全部条目默认不勾选（§15）；N=0 时主按钮禁用。
struct GrantSelectionView: View {
    let app: AppModel
    @Bindable var model: PairingFlowModel
    let offer: PairingOffer
    let items: [ItemRow]

    var body: some View {
        List {
            Section {
                ForEach(items) { row in
                    Button {
                        model.toggle(row.id)
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: model.selected.contains(row.id)
                                  ? "checkmark.circle.fill" : "circle")
                                .font(.title3)
                                .foregroundStyle(model.selected.contains(row.id)
                                                 ? KeyrefTheme.success : KeyrefTheme.muted)
                            ItemTypeGlyph(type: row.type, size: 34)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(row.name)
                                MaskText(row: row)
                            }
                            Spacer()
                        }
                    }
                    .buttonStyle(.plain)
                }
            } header: {
                Text("选择要授予的条目")
            } footer: {
                Text("勾选的条目将被授予查看与使用权限，默认 30 天有效，每次打开 keyref 解锁时自动顺延即将到期的授权。现在什么都没有授予——勾选并确认之后才算。")
            }
            Section {
                Button {
                    Task {
                        let selections = model.selected.sorted().flatMap { itemID in
                            [GrantSelection(itemID: itemID, kind: "view"),
                             GrantSelection(itemID: itemID, kind: "use")]
                        }
                        await model.complete(grantSelections: selections,
                                             items: items,
                                             authenticator: app.authenticator)
                    }
                } label: {
                    Text(model.itemCount == 0
                         ? "至少勾选一条，或直接取消配对"
                         : "用 Face ID 确认（\(model.itemCount) 条）")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(KeyrefPrimaryButtonStyle())
                .disabled(model.itemCount == 0)
            }
        }
        .navigationTitle("勾选条目")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }
}

struct PairDoneView: View {
    let label: String
    let onFinish: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            ResultHero(systemName: "checkmark.seal.fill",
                       tint: KeyrefTheme.success,
                       title: "配对完成",
                       message: "终端会显示成功，并拿到你勾选的条目。")
            Spacer()
            Button("完成") { onFinish() }
                .buttonStyle(KeyrefPrimaryButtonStyle())
        }
        .padding(28)
    }
}

struct PairFailedView: View {
    let message: String
    let onRetry: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            ResultHero(systemName: "xmark.octagon.fill",
                       tint: KeyrefTheme.danger,
                       title: message)
            Spacer()
            Button("返回扫码") { onRetry() }
                .buttonStyle(KeyrefPrimaryButtonStyle())
        }
        .padding(28)
    }
}

// MARK: - 2.9 device detail (CLI) + grants

struct DeviceDetailView: View {
    let app: AppModel
    let device: DeviceRow
    @State private var showAddGrant = false
    @State private var revokeTarget: GrantSummary?
    @State private var showRevoke = false
    @State private var editingLabel = false
    @State private var labelDraft = ""

    var body: some View {
        List {
            Section {
                HStack(spacing: 14) {
                    IconGlyph(systemName: "terminal.fill", size: 20)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(device.label)
                            .font(.title3.weight(.semibold))
                        Text(device.fingerprint)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer(minLength: 0)
                    statusPillForDetail
                }
                .padding(.vertical, 4)
            }
            Section {
                InfoRow(label: "状态", value: device.isActive ? "活跃" : device.isPending ? "等待确认" : "已撤销")
                InfoRow(label: "指纹", value: device.fingerprint, mono: true)
                InfoRow(label: "添加时间", value: Format.dateTime(device.createdAt), mono: true)
                Button {
                    labelDraft = device.label
                    editingLabel = true
                } label: {
                    HStack {
                        Text("备注")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(device.label)
                            .foregroundStyle(.tint)
                        Image(systemName: "pencil")
                            .font(.caption)
                            .foregroundStyle(.tint)
                    }
                }
            }
            grantsSection
            recentActivitySection
            Section {
                Button(role: .destructive) {
                    showRevoke = true
                } label: {
                    Text("撤销这台设备")
                        .frame(maxWidth: .infinity)
                }
            }
        }
        .navigationTitle(device.label)
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
        .sheet(isPresented: $showAddGrant) {
            GrantAddSheet(app: app, device: device)
        }
        .sheet(isPresented: $showRevoke) {
            NavigationStack {
                RevokeDeviceView(app: app, device: device)
            }
        }
        .alert("修改备注", isPresented: $editingLabel) {
            TextField("名称", text: $labelDraft)
            Button("保存") {
                Task { await app.devices.rename(deviceID: device.id, label: labelDraft) }
            }
            Button("取消", role: .cancel) {}
        }
        // 收回单条（轻档确认，§3.3）。
        .confirmationDialog(revokeDialogTitle, isPresented: Binding(
            get: { revokeTarget != nil },
            set: { if !$0 { revokeTarget = nil } }), titleVisibility: .visible) {
            Button("收回", role: .destructive) {
                guard let target = revokeTarget else { return }
                Task { _ = await app.devices.revokeGrant(deviceID: device.id,
                                                         itemID: target.itemID,
                                                         kind: target.kind) }
                revokeTarget = nil
            }
            Button("取消", role: .cancel) { revokeTarget = nil }
        } message: {
            Text("设备下次同步后失效。已经拷到那台机器上的密钥不受影响——必要时撤销整台设备并轮换（B6）。")
        }
    }

    @ViewBuilder
    private var statusPillForDetail: some View {
        if device.isPending {
            StatusText(text: "等待确认", tint: KeyrefTheme.warning, showDot: true)
        } else if device.isActive {
            StatusText(text: "活跃", tint: KeyrefTheme.success, showDot: true)
        } else {
            StatusText(text: "已撤销", tint: KeyrefTheme.muted)
        }
    }

    var revokeDialogTitle: String {
        guard let target = revokeTarget,
              let item = app.devices.items.first(where: { $0.id == target.itemID }) else {
            return "收回授权？"
        }
        return "收回「\(item.ref)」的\(Format.grantLevelLabel(target.kind))授权？"
    }

    @ViewBuilder
    var grantsSection: some View {
        Section {
            if device.grants.isEmpty {
                Text("这台设备还没有被授予任何条目。")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(device.grants) { grant in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(app.devices.itemName(grant.itemID))
                            Text(grant.kind == "use" ? "使用" : "查看")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("到期 \(Format.dateTime(grant.expiresAt))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        ExpiryChip(mark: .mark(expiresAt: Date(timeIntervalSince1970: Double(grant.expiresAt) / 1000)))
                    }
                    #if os(iOS)
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) {
                            revokeTarget = grant
                        } label: {
                            Label("收回", systemImage: "minus.circle")
                        }
                    }
                    #endif
                }
            }
            Button {
                showAddGrant = true
            } label: {
                Label("追加授权", systemImage: "plus")
            }
        } header: {
            Text("授权清单")
        } footer: {
            Text("到期前会自动续期：每次打开 keyref 解锁时顺延即将到期的授权（§8.4）。")
        }
    }

    /// 最近活动：本机审计流按此设备过滤的前 5 条 + 查看全部。
    @ViewBuilder
    var recentActivitySection: some View {
        Section("最近活动") {
            let recent = app.audit.rows.filter { $0.deviceID == device.id }.prefix(5)
            if recent.isEmpty {
                Text("这台设备还没有审计记录。")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(Array(recent)) { row in
                    AuditRowView(row: row, deviceLabel: device.label)
                }
            }
            NavigationLink {
                AuditListView(app: app, initialDeviceFilter: device.id)
            } label: {
                Text("查看全部")
            }
        }
    }
}

/// 追加授权 sheet：列出尚未授予的条目（默认全不选）→「授予（N 条）」→ Face ID。
struct GrantAddSheet: View {
    let app: AppModel
    let device: DeviceRow
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<String> = []

    var grantable: [ItemRow] {
        let granted = Set(device.grants.map { $0.itemID })
        return app.items.rows.filter { !granted.contains($0.id) }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(grantable) { row in
                        Button {
                            if selected.contains(row.id) {
                                selected.remove(row.id)
                            } else {
                                selected.insert(row.id)
                                app.haptics.fire(.lightImpact)
                            }
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: selected.contains(row.id)
                                      ? "checkmark.circle.fill" : "circle")
                                    .font(.title3)
                                    .foregroundStyle(selected.contains(row.id)
                                                     ? KeyrefTheme.success : KeyrefTheme.muted)
                                ItemTypeGlyph(type: row.type, size: 34)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(row.name)
                                    MaskText(row: row)
                                }
                                Spacer()
                            }
                        }
                        .buttonStyle(.plain)
                    }
                } footer: {
                    Text("默认全不选。授予后默认 30 天有效，每次解锁自动顺延（§8.4）。")
                }
                Section {
                    Button {
                        Task {
                            let selections = selected.sorted().flatMap { itemID in
                                [GrantSelection(itemID: itemID, kind: "view"),
                                 GrantSelection(itemID: itemID, kind: "use")]
                            }
                            let auth = await app.authenticator.authenticate(
                                reason: "授予 \(selected.count) 条条目")
                            guard case .success = auth else { return }
                            _ = await app.devices.appendGrants(deviceID: device.id,
                                                               selections: selections)
                            dismiss()
                        }
                    } label: {
                        Text(selected.isEmpty ? "授予（0 条）" : "授予（\(selected.count) 条）")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(KeyrefPrimaryButtonStyle())
                    .disabled(selected.isEmpty)
                }
            }
            .navigationTitle("追加授权")
            .navigationBarTitleDisplayMode(.inline)
            .keyrefListSurface()
            .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }
}

// MARK: - 2.9 local device detail (simplified)

struct LocalDeviceDetailView: View {
    let app: AppModel
    let device: DeviceRow
    @State private var showExplanation = false

    var body: some View {
        List {
            Section {
                HStack(spacing: 14) {
                    IconGlyph(systemName: "iphone", size: 20)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("这台 iPhone")
                            .font(.title3.weight(.semibold))
                        Text(device.isActive ? "安全隔区包裹正常" : "包裹已失效")
                            .font(.footnote)
                            .foregroundStyle(device.isActive ? KeyrefTheme.success : KeyrefTheme.danger)
                    }
                    Spacer(minLength: 0)
                }
                .padding(.vertical, 4)
            }
            Section {
                InfoRow(label: "状态", value: device.isActive ? "正常" : "包裹已失效")
                InfoRow(label: "指纹", value: device.fingerprint, mono: true)
                InfoRow(label: "创建时间", value: Format.dateTime(device.createdAt), mono: true)
            } header: {
                Text("本机")
            } footer: {
                Text("主密钥只活在这台手机的安全隔区里。")
            }
            Section {
                Button {
                    showExplanation = true
                } label: {
                    LabeledContent("自动锁定", value: app.settings.autoLock.label)
                }
            }
            Section {
                Button {
                    Task {
                        try? await app.backend.setPrimaryReceiver(
                            deviceID: device.isPrimaryReceiver ? nil : device.id)
                        await app.devices.refresh()
                    }
                } label: {
                    HStack {
                        Text(device.isPrimaryReceiver ? "取消主接收端" : "设为主接收端")
                        Spacer()
                        if device.isPrimaryReceiver {
                            StatusText(text: "主接收端", tint: KeyrefTheme.success, showDot: true)
                        }
                    }
                }
                .disabled(!device.isActive)
            } header: {
                Text("短信接收")
            } footer: {
                Text("每个保险库至多一台主接收端。验证码与审批的推送指向它；没有登记推送令牌时退回全部 owner 设备。改动会随设备目录重签下发。")
            }
            if !device.isActive {
                Section {
                    Button("用恢复码在本机重建") {
                        app.showRecoveryFromLock = true
                    }
                }
            }
        }
        .navigationTitle("这台 iPhone")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .sheet(isPresented: $showExplanation) {
            SecurityExplanationView()
        }
    }
}

// MARK: - 2.10 revoke device (dedicated page, B6)

struct RevokeDeviceView: View {
    let app: AppModel
    let device: DeviceRow
    @State private var model: RevokeFlowModel?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Group {
            if let model {
                RevokeFlowBody(app: app, model: model) { dismiss() }
            } else {
                ProgressView()
            }
        }
        .onAppear {
            if model == nil {
                model = RevokeFlowModel(backend: app.backend, haptics: app.haptics,
                                        device: device) { itemID in
                    app.devices.itemName(itemID)
                }
            }
        }
        .navigationTitle("撤销设备")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct RevokeFlowBody: View {
    let app: AppModel
    @Bindable var model: RevokeFlowModel
    let onFinish: () -> Void
    @State private var showOnlyDisableAlert = false

    var body: some View {
        switch model.phase {
        case .configuring:
            configurePage
        case .running:
            progressPage
        case .done:
            donePage
        case .interrupted(let remaining):
            interruptedPage(remaining: remaining)
        case .failed(let message):
            failedPage(message: message)
        }
    }

    /// 第一步（专用页）：摘要 + 默认勾选的轮换选项（B6 文案）+ 次级「仅停用」。
    var configurePage: some View {
        Form {
            Section("摘要") {
                InfoRow(label: "指纹", value: model.device.fingerprint, mono: true)
                InfoRow(label: "授权", value: "\(model.grantCount) 条，其中 \(model.useGrantCount) 条有使用授权")
            }
            Section {
                Toggle(isOn: $model.rotateSelected) {
                    Text("同时轮换这 \(model.useGrantCount) 条条目的密钥")
                }
                Text("撤销只能拦住服务器这条路。那台机器上已经解开的密钥副本，在轮换之前仍然有效——哪怕它被改得不再理会过期时间。轮换会生成新密钥、重新加密这 \(model.useGrantCount) 条条目，并把新密钥发给其余设备。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("轮换")
            }
            Section {
                Button(role: .destructive) {
                    Task { await model.run(authenticator: app.authenticator) }
                } label: {
                    Text("撤销并轮换 \(model.useGrantCount) 条")
                        .frame(maxWidth: .infinity)
                }
                // 次级链接「不轮换，仅停用」→ 二次警报（§8.4：只撤销不轮换
                // 放在二级确认后面）。
                Button {
                    showOnlyDisableAlert = true
                } label: {
                    Text("不轮换，仅停用")
                        .foregroundStyle(.secondary)
                }
                .confirmationDialog("仅停用？", isPresented: $showOnlyDisableAlert,
                                    titleVisibility: .visible) {
                    Button("仅停用", role: .destructive) {
                        model.rotateSelected = false
                        Task { await model.run(authenticator: app.authenticator) }
                    }
                    Button("返回，保持轮换", role: .cancel) {
                        model.rotateSelected = true
                    }
                } message: {
                    Text("仅当确认密钥从未离开那台机器时才安全。适用于设备退役；如果只是怀疑它出了问题，请保持轮换。")
                }
            }
        }
        .navigationTitle("撤销 \(model.device.label)")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }

    /// 第二步：三项清单逐项打勾。
    var progressPage: some View {
        VStack(spacing: 24) {
            StepChecklist(items: [
                .init(label: "重签设备目录", done: true, active: false),
                .init(label: "删除授权", done: true, active: false),
                .init(label: model.rotateSelected
                      ? "重新加密 \(model.useGrantCount) 条"
                      : "不轮换条目密钥",
                      done: false, active: true),
            ])
            ProgressView()
            Spacer()
        }
        .padding(28)
        .navigationTitle("撤销进行中")
        .navigationBarTitleDisplayMode(.inline)
    }

    var donePage: some View {
        VStack(spacing: 0) {
            Spacer()
            ResultHero(systemName: "checkmark.seal.fill",
                       tint: KeyrefTheme.success,
                       title: "已撤销",
                       message: "那台设备下次联网同步时会收到停用指令。")
            Spacer()
            Button("完成") { onFinish() }
                .buttonStyle(KeyrefPrimaryButtonStyle())
        }
        .padding(28)
    }

    /// 失败态：轮换中途中断 → 「撤销已生效，轮换还剩 K 条」+「继续轮换」。
    func interruptedPage(remaining: Int) -> some View {
        VStack(spacing: 0) {
            Spacer()
            ResultHero(systemName: "arrow.triangle.2.circlepath",
                       tint: KeyrefTheme.warning,
                       title: "撤销已生效，轮换还剩 \(remaining) 条",
                       message: "目录签名与授权删除已落库（撤销本身不可回退），轮换作为可恢复任务继续。")
            Spacer()
            Button("继续轮换") {
                Task { await model.resume(authenticator: app.authenticator) }
            }
            .buttonStyle(KeyrefPrimaryButtonStyle())
        }
        .padding(28)
    }

    func failedPage(message: String) -> some View {
        VStack(spacing: 0) {
            Spacer()
            ResultHero(systemName: "xmark.octagon.fill",
                       tint: KeyrefTheme.danger,
                       title: message)
            Spacer()
            Button("返回") { onFinish() }
                .buttonStyle(KeyrefPrimaryButtonStyle())
        }
        .padding(28)
    }
}
