// Settings tab (docs/ios-ui.md §2.14–§2.17): server origin (S10) with its
// change/migration flow, plan & quota (S12/S13), security (auto-lock, Face
// ID, the two recovery-material rotations), recovery entry with the fixed
// declaration line, the danger zone (two-step delete) and about.
import SwiftUI
import KeyrefCore

// MARK: - 2.14 settings root

struct SettingsView: View {
    let app: AppModel
    @Bindable var settings: SettingsStore

    init(app: AppModel) {
        self.app = app
        _settings = Bindable(wrappedValue: app.settings)
    }

    var body: some View {
        NavigationStack {
            Form {
                vaultHeroSection
                serverSection
                quotaSection
                securitySection
                delegationSection
                recoverySection
                dangerSection
                aboutSection
            }
            .navigationTitle("设置")
            .keyrefListSurface()
            .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
            .task {
                await settings.refreshAccount()
                // 状态行要显示服务器上真正生效的委托（design §14.8）。
                await app.delegation.refresh()
            }
            .sheet(isPresented: Binding(
                get: { app.requestServerMigration },
                set: { app.requestServerMigration = $0 })) {
                NavigationStack {
                    ServerOriginView(app: app)
                }
            }
            .overlay(alignment: .top) {
                if let toast = settings.toast {
                    ToastView(text: toast)
                        .task {
                            try? await Task.sleep(for: .seconds(2))
                            settings.toast = nil
                        }
                }
            }
        }
    }

    /// 保险库摘要：一眼看到服务器归属、条目/设备数量和档位。
    var vaultHeroSection: some View {
        Section {
            KeyrefBlock(padding: 16) {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 12) {
                        BrandMark(size: 48)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("keyref 保险库")
                                .font(.headline)
                            Text(app.backend.origin.host ?? "")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        Spacer(minLength: 4)
                        StatusText(text: settings.planLabel,
                                   tint: KeyrefTheme.foreground)
                    }
                    Divider().overlay(KeyrefTheme.hairline)
                    HStack(spacing: 0) {
                        metric("条目", "\(app.items.rows.count)")
                        metricDivider
                        metric("CLI 设备", "\(app.devices.activeCLI.count)")
                        metricDivider
                        metric("部署", settings.hostedShortBadge)
                    }
                }
            }
            .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 10, trailing: 16))
            .listRowBackground(Color.clear)
            .listRowSeparator(.hidden)
        }
    }

    func metric(_ label: String, _ value: String) -> some View {
        VStack(spacing: 3) {
            Text(value)
                .font(.callout.weight(.semibold).monospacedDigit())
                .lineLimit(1)
                .minimumScaleFactor(0.75)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }

    var metricDivider: some View {
        Rectangle()
            .fill(KeyrefTheme.hairline)
            .frame(width: 1, height: 26)
    }

    /// 服务器 origin（S10，一级信息）。
    var serverSection: some View {
        Section {
            NavigationLink {
                ServerOriginView(app: app)
            } label: {
                HStack(spacing: 12) {
                    IconGlyph(systemName: "server.rack", size: 18)
                    VStack(alignment: .leading, spacing: 4) {
                        LabeledContent("同步服务器", value: app.backend.origin.host ?? "")
                        Text(settings.hostedBadge)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        } header: {
            Text("服务器")
        }
    }

    /// 保险库与配额。
    var quotaSection: some View {
        Section {
            NavigationLink {
                QuotaStatusView(app: app)
            } label: {
                HStack(spacing: 12) {
                    IconGlyph(systemName: "chart.bar.fill", size: 18)
                    VStack(alignment: .leading, spacing: 4) {
                        LabeledContent("档位", value: settings.planLabel)
                        if let usage = settings.account?.usage, let limits = settings.account?.limits {
                            Text("条目 \(usage.items)/\(limits.items ?? 0) · 存储 \(Format.bytes(usage.storageBytes))/\(Format.bytes(limits.storageBytes ?? 0)) · 今日请求 \(usage.requestsToday)/\(limits.requestsPerDay ?? 0)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            LabeledContent {
                Text("随内购上线。")
                    .foregroundStyle(.secondary)
            } label: {
                Label("Plus（$6/月）", systemImage: "sparkles")
            }
            .disabled(true)
            NavigationLink {
                CloudBackupView(app: app)
            } label: {
                Label("iCloud 副本（仅本机条目）", systemImage: "icloud")
            }
        } header: {
            Text("保险库与配额")
        }
    }

    /// 安全（§2.14 分区 3）。
    var securitySection: some View {
        Section {
            Picker("自动锁定", selection: $settings.autoLock) {
                ForEach(AutoLockInterval.allCases, id: \.self) { interval in
                    Text(interval.label).tag(interval)
                }
            }
            NavigationLink {
                SecurityExplanationView()
            } label: {
                Label("Face ID 说明", systemImage: "faceid")
            }
            NavigationLink {
                RotationEntryView(app: app, kind: .vmkLayer)
            } label: {
                Label("轮换 VMK 与恢复码", systemImage: "arrow.triangle.2.circlepath")
            }
            NavigationLink {
                RotationEntryView(app: app, kind: .recoveryLeak)
            } label: {
                Label("怀疑恢复码泄露", systemImage: "exclamationmark.shield")
            }
            NavigationLink {
                ItemKeyRotationView(app: app)
            } label: {
                Label("轮换条目密钥", systemImage: "key.fill")
            }
        } header: {
            Text("安全")
        }
    }

    /// 自动审批委托（design v0.8 §14.8）：一行状态，点开编辑页。
    var delegationSection: some View {
        Section {
            NavigationLink {
                DelegationEditView(app: app)
            } label: {
                DelegationStatusRow(app: app)
            }
        } header: {
            Text("自动审批")
        } footer: {
            Text("委托给决策器后，命中策略的短信验证码消费不必每次解锁手机——代价是它持有有效期内全部短信明文。不开委托时行为与从前一样：每条都等人确认。")
        }
    }

    /// 恢复（§2.14 分区 4）：固定说明行是任务的显式声明。
    var recoverySection: some View {
        Section {
            NavigationLink {
                RecoveryFlowView(app: app, mode: .takeover)
            } label: {
                Label("用恢复码接管", systemImage: "arrow.counterclockwise")
            }
        } header: {
            Text("恢复")
        } footer: {
            Text("恢复码不能再次查看。keyref 不保存它，没有任何入口能重新显示。忘了、又没抄下来，数据无法恢复。")
        }
    }

    /// 危险区（§2.16 两步删除）。
    var dangerSection: some View {
        Section {
            NavigationLink {
                DeleteVaultView(app: app)
            } label: {
                Label("删除保险库", systemImage: "trash")
                    .foregroundStyle(KeyrefTheme.danger)
            }
        } header: {
            Text("危险区")
        }
    }

    var aboutSection: some View {
        Section {
            LabeledContent("版本", value: "0.1.0")
            LabeledContent("协议版本", value: "1")
        } header: {
            Text("关于")
        }
    }
}

// MARK: - 2.15 server origin change & migration

struct ServerOriginView: View {
    let app: AppModel
    @Bindable var settings: SettingsStore
    @Environment(\.dismiss) private var dismiss
    @State private var showConfirm = false
    @State private var showManualEntry = false

    init(app: AppModel) {
        self.app = app
        _settings = Bindable(wrappedValue: app.settings)
    }

    var newOriginEmpty: Bool {
        settings.newOriginText.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        Form {
            Section {
                LabeledContent("当前", value: settings.originDisplay)
                    .font(.footnote.monospaced())
                Text(settings.hostedBadge)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text("服务器")
            }
            Section {
                TextField("https://sync.example", text: $settings.newOriginText)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
                if let error = settings.originInlineError {
                    Label(error, systemImage: "exclamationmark.circle")
                        .font(.footnote)
                        .foregroundStyle(KeyrefTheme.danger)
                } else if !newOriginEmpty {
                    Label(settings.newOriginText.hasPrefix("https://sync.keyref.app")
                          ? "官方托管" : "自托管",
                          systemImage: "server.rack")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("新 origin")
            } footer: {
                Text("归属实时预览：输入官方域名显示「官方托管」，否则「自托管」。")
            }
            Section {
                Button {
                    if app.backend.hasVault {
                        showConfirm = true
                    } else {
                        // 空库：直接改，无确认页（§2.15）。
                        Task {
                            await settings.applyOrigin()
                            dismiss()
                        }
                    }
                } label: {
                    Text(settings.migrating ? "迁移中…" : "切换")
                }
                .disabled(!SettingsStore.isValidOrigin(settings.newOriginText) || settings.migrating)
                if let failed = settings.migrationFailed {
                    Text(failed)
                        .font(.footnote)
                        .foregroundStyle(KeyrefTheme.danger)
                }
                if let step = settings.migrationStep {
                    LabeledContent("进行中", value: stepLabel(step))
                        .font(.footnote)
                }
            }
        }
        .navigationTitle("服务器")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
        .onAppear {
            settings.newOriginText = ""
        }
        // 确认页（保险库已有数据时）：三条后果逐条列出（§2.15）。
        .alert("切换服务器", isPresented: $showConfirm) {
            Button("切换", role: .destructive) {
                Task {
                    await settings.applyOrigin()
                }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("新服务器上会重建这个保险库，并上传全部密文。\n所有 CLI 设备要改指向新地址并重新配对。\n旧服务器上的副本不会被自动删除。要清理时，把服务器改回旧地址执行删除。")
        }
    }

    func stepLabel(_ step: MigrationStep) -> String {
        switch step {
        case .createVaultOnNewOrigin: return "在新 origin 创建保险库"
        case .fullUpload: return "全量上传"
        case .verify: return "校验"
        }
    }
}

// MARK: - 2.17 quota & frozen status (S12, S13)

struct QuotaStatusView: View {
    let app: AppModel
    @Bindable var settings: SettingsStore
    @Bindable var items: ItemsStore

    init(app: AppModel) {
        self.app = app
        _settings = Bindable(wrappedValue: app.settings)
        _items = Bindable(wrappedValue: app.items)
    }

    var body: some View {
        List {
            if settings.account?.isFrozen == true {
                frozenBody
            } else {
                overQuotaBody
            }
        }
        .navigationTitle("保险库与配额")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
        .task { await settings.refreshAccount() }
    }

    /// 超额（S12）：原因行 + 仍可 / 不能 + 出路（没有升级按钮，Phase 1 不撒谎）。
    @ViewBuilder
    var overQuotaBody: some View {
        Section {
            Text("免费额度已用尽")
                .font(.title3.weight(.semibold))
            if let reason = settings.account?.overQuotaReason {
                Text(reason)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        Section("现在仍然可以") {
            Label("查看全部条目", systemImage: "checkmark.circle")
            Label("撤销设备", systemImage: "checkmark.circle")
            Label("收回授权", systemImage: "checkmark.circle")
            Label("删除条目", systemImage: "checkmark.circle")
            Label("删除保险库", systemImage: "checkmark.circle")
        }
        Section("现在不能") {
            Label("新增或修改条目", systemImage: "xmark.circle")
            Label("配对新设备", systemImage: "xmark.circle")
        }
        Section("出路") {
            NavigationLink {
                ItemsBySizeView(app: app)
            } label: {
                Label("删除条目，降回限额内（按密文大小排序）", systemImage: "arrow.down.circle")
            }
            NavigationLink {
                ServerOriginView(app: app)
            } label: {
                Label("改用自托管服务器", systemImage: "server.rack")
            }
            LabeledContent {
                Text("随内购上线。")
                    .foregroundStyle(.secondary)
            } label: {
                Text("Plus（$6/月）")
            }
            .disabled(true)
        }
    }

    /// 冻结（S13）：解冻是自动的——任何一次成功登录即解冻；页面职责是把
    /// 发生的事说清楚，不提供解冻按钮。
    var frozenBody: some View {
        Section {
            Label("保险库已冻结", systemImage: "snowflake")
                .font(.title3.weight(.semibold))
                .foregroundStyle(.cyan)
            Text("免费档连续 180 天没有设备成功登录，保险库转为只读。数据没有被删除。刚才的登录已触发解冻，现在可以正常使用。")
                .font(.callout)
        }
    }
}

// MARK: - §8.4 rotations (轮换 VMK 与恢复码 / 怀疑恢复码泄露)

enum RotationKind {
    case vmkLayer
    case recoveryLeak

    var title: String {
        switch self {
        case .vmkLayer: return "轮换 VMK 与恢复码"
        case .recoveryLeak: return "怀疑恢复码泄露"
        }
    }

    var confirmCopy: String {
        switch self {
        case .vmkLayer:
            return "怀疑主密钥材料暴露、但条目没有泄露时使用。只换包裹层，条目密文不动。"
        case .recoveryLeak:
            return "新恢复码 + 轮换全部条目密钥并重加密。旧恢复码的持有者从此解不开任何新密文。条目较多时需要几分钟。"
        }
    }
}

struct RotationEntryView: View {
    let app: AppModel
    let kind: RotationKind
    @Bindable var settings: SettingsStore

    init(app: AppModel, kind: RotationKind) {
        self.app = app
        self.kind = kind
        _settings = Bindable(wrappedValue: app.settings)
    }

    var body: some View {
        Form {
            Section {
                Text(kind.confirmCopy)
                    .font(.callout)
            }
            Section {
                Button(role: .destructive) {
                    Task {
                        let ok = kind == .vmkLayer
                            ? await settings.rotateVMKAndRecovery(authenticator: app.authenticator)
                            : await settings.rotateRecoveryCodeFull(authenticator: app.authenticator)
                        if ok { showNewCode = true }
                    }
                } label: {
                    Text(kind.title)
                        .frame(maxWidth: .infinity)
                }
                .disabled(settings.rotating)
                if settings.rotating {
                    ProgressView()
                }
            }
        }
        .navigationTitle(kind.title)
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        // 新恢复码只显示一次（复用 2.2 的展示与回填，S9）。
        .sheet(isPresented: $showNewCode) {
            if let code = settings.newRecoveryCode {
                NavigationStack {
                    RecoveryCodeReShowView(code: code)
                }
            }
        }
    }

    @State private var showNewCode = false
}

/// 新恢复码展示 + 回填（复用 2.2 的展示与回填，S9；故意无拷贝按钮）。
struct RecoveryCodeReShowView: View {
    let code: String
    @State private var backfill: RecoveryBackfillModel?
    @Environment(\.dismiss) private var dismiss

    var groups: [String] { RecoveryCodeGroups.groups(of: code) }

    var body: some View {
        ZStack {
            KeyrefBackdrop()
            if let backfill {
                backfillPage(backfill)
            } else {
                displayPage
            }
        }
        .navigationTitle("新恢复码")
        .navigationBarTitleDisplayMode(.inline)
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
        .onAppear {
            if backfill == nil {
                backfill = RecoveryBackfillModel(targetGroups: groups)
            }
        }
    }

    var displayPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("抄下新恢复码")
                    .font(.title2.weight(.semibold))
                Text("这是它唯一一次出现。旧恢复码从现在起解不开任何新密文。抄在纸上，或放进另一个你信任的保险库。")
                    .font(.callout)
                KeyrefNotice(systemName: "exclamationmark.triangle.fill",
                             tint: KeyrefTheme.warning,
                             text: "手机和恢复码同时丢失＝数据永久丢失。",
                             emphasis: true)
                RecoveryCodeDisplay(groups: groups)
                Button {
                    self.backfill = RecoveryBackfillModel(targetGroups: groups)
                } label: {
                    Text("我已抄写，开始校验")
                }
                .buttonStyle(KeyrefPrimaryButtonStyle())
                .padding(.top, 8)
            }
            .padding(24)
            .scrollEdgeEffectStyle(.soft, for: .top)
        }
    }

    func backfillPage(_ backfill: RecoveryBackfillModel) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("对照校验")
                    .font(.title2.weight(.semibold))
                GroupBackfillInput(model: backfill)
                if backfill.allMatched {
                    Text("全部匹配。")
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(.green)
                } else if let mismatch = backfill.firstMismatchIndex {
                    Text("有一组和屏幕上的不一致，请对照你抄写的那份修改。")
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(KeyrefTheme.danger)
                        .accessibilityLabel("第 \(mismatch + 1) 组不一致")
                }
                Button {
                    dismiss()
                } label: {
                    Text("完成")
                }
                .buttonStyle(KeyrefPrimaryButtonStyle())
                .disabled(!backfill.allMatched)
            }
            .padding(24)
            .scrollEdgeEffectStyle(.soft, for: .top)
        }
    }
}

// MARK: - 2.16 delete vault (two steps)

struct DeleteVaultView: View {
    let app: AppModel
    @Bindable var settings: SettingsStore
    @Environment(\.dismiss) private var dismiss

    init(app: AppModel) {
        self.app = app
        _settings = Bindable(wrappedValue: app.settings)
    }

    var body: some View {
        Group {
            if settings.deleteConfirmed {
                donePage
            } else {
                confirmPage
            }
        }
        .navigationTitle("删除保险库")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }

    /// 第一页：后果清单 + 手输「删除」（不可粘贴）→ Face ID → 签名提交。
    var confirmPage: some View {
        Form {
            Section {
                Text("删除整个保险库")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(KeyrefTheme.danger)
                consequence("服务器上全部密文、设备与授权记录立即级联清空。")
                consequence("所有 agent 的引用立即失效。")
                consequence("恢复码随之作废。")
                consequence("本机缓存在删除应用时清掉。")
            }
            Section {
                TextField("输入「删除」以确认", text: $settings.deleteConfirmText)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if let failed = settings.deleteFailed {
                    Text(failed)
                        .font(.footnote)
                        .foregroundStyle(KeyrefTheme.danger)
                }
                Button(role: .destructive) {
                    Task {
                        let ok = await settings.deleteVault(authenticator: app.authenticator)
                        if ok {
                            // 第二页：完成 → 欢迎页（S1）。
                            app.enterOnboarding()
                        }
                    }
                } label: {
                    Text(settings.deleting ? "提交中…" : "删除")
                        .frame(maxWidth: .infinity)
                }
                .disabled(!settings.deleteConfirmValid || settings.deleting)
            } footer: {
                Text("绝不显示「已删除」，除非服务器确认成功。")
            }
        }
    }

    func consequence(_ text: String) -> some View {
        Label(text, systemImage: "exclamationmark.triangle")
            .font(.callout)
            .foregroundStyle(.secondary)
    }

    /// 失败态绝不假装成功（§2.16）。
    var donePage: some View {
        VStack(spacing: 0) {
            Spacer()
            ResultHero(systemName: "checkmark.seal.fill",
                       tint: KeyrefTheme.success,
                       title: "保险库已删除")
            Spacer()
            Button("返回") { dismiss() }
                .buttonStyle(KeyrefPrimaryButtonStyle())
        }
        .padding(28)
    }
}
