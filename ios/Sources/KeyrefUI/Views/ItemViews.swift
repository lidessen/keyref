// Items tab (docs/ios-ui.md §2.4 list with S5/S6, §2.5 detail with the
// Face ID–gated reveal / rotation / delete, §2.6 new+edit with policy
// editing, the allowArgv alert and the paste-leak save check, §2.17 quota
// banner).
import SwiftUI
import KeyrefCore

// MARK: - 2.4 list (S5, S6)

struct ItemListView: View {
    let app: AppModel
    @Bindable var items: ItemsStore
    @State private var showAdd = false
    @State private var showSyncDetail = false

    init(app: AppModel) {
        self.app = app
        _items = Bindable(wrappedValue: app.items)
    }

    var body: some View {
        @Bindable var app = app
        NavigationStack {
            Group {
                if items.rows.isEmpty {
                    emptyState
                } else {
                    list
                }
            }
            .navigationTitle("条目")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showAdd = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("添加条目")
                }
            }
            .searchable(text: $items.searchText, prompt: "搜索名称、ref 或描述")
            .refreshable {
                await items.syncNow()
            }
            .sheet(isPresented: $showAdd) {
                NavigationStack {
                    ItemEditView(app: app, mode: .create)
                }
            }
            .overlay(alignment: .top) {
                banners.padding(.horizontal, 16).padding(.top, 4)
            }
            .overlay(alignment: .top) {
                if let toast = items.toast {
                    ToastView(text: toast)
                        .task {
                            try? await Task.sleep(for: .seconds(2))
                            items.toast = nil
                        }
                }
            }
            // 同步状态入口已迁到 Tab 栏上方的玻璃胶囊（§3.8）：
            // 胶囊点按 → 在列表顶部展开失败详情（S6 的展开逻辑保留）。
            .onChange(of: items.showFailureDetail) { _, requested in
                guard requested else { return }
                items.showFailureDetail = false
                showSyncDetail = true
            }
        }
    }

    @ViewBuilder
    var banners: some View {
        // S6 同步失败横幅已迁到 tabViewBottomAccessory 玻璃胶囊（§3.8）；
        // 列表顶部只保留 S12 / S13 状态横幅。
        VStack(spacing: 8) {
            if items.overQuota { QuotaBanner() }
            if items.isFrozen { FrozenBanner() }
        }
        .sheet(isPresented: $showSyncDetail) {
            if let failure = items.syncFailure {
                NavigationStack {
                    SyncFailureDetailView(app: app, failure: failure)
                }
            }
        }
    }

    /// 空态（S5）。
    var emptyState: some View {
        ContentUnavailableView {
            Label("还没有条目", systemImage: "key")
        } description: {
            Text("添加第一条密钥，配对时再把它授予 agent。")
        } actions: {
            Button("添加条目") { showAdd = true }
                .buttonStyle(.glassProminent)
        }
    }

    /// 行：名称 + `ref` 与掩码（等宽、次要色）+ 类型徽标；按更新时间倒序。
    var list: some View {
        List {
            ForEach(items.filtered) { row in
                NavigationLink {
                    ItemDetailView(app: app, row: row)
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(row.name).font(.body.weight(.medium))
                            Spacer()
                            TypeBadge(type: row.type)
                        }
                        MaskText(row: row)
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .listStyle(.plain)
        // §3.8：滚动边缘柔和过渡，内容从导航栏与 Tab 栏下自然穿过。
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }
}

// MARK: - S6 sync failure detail

struct SyncFailureDetailView: View {
    let app: AppModel
    var failure: SyncMessage?

    init(app: AppModel, failure: SyncMessage? = nil) {
        self.app = app
        self.failure = failure ?? app.items.syncFailure
    }

    var body: some View {
        Form {
            Section("最近一次错误") {
                if let failure {
                    Text(failure.headline)
                        .font(.body.weight(.medium))
                    if let subline = failure.subline {
                        Text(subline)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("目前没有同步错误。")
                        .foregroundStyle(.secondary)
                }
                if let at = app.items.failureAt {
                    LabeledContent("时间", value: Format.dateTime(Int64(at.timeIntervalSince1970 * 1000)))
                }
            }
            if failure?.isVerification == true {
                Section {
                    Text("签名 / revision 校验失败时不自动重试，等下一次手动刷新（§10.6：验证失败就停止应用这一批）。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            if case .deviceRevoked = failure {
                Section {
                    NavigationLink {
                        RecoveryFlowView(app: app, mode: .takeover)
                    } label: {
                        Label("用恢复码接管", systemImage: "arrow.counterclockwise")
                    }
                }
            }
            if case .quotaExceeded = failure {
                Section {
                    NavigationLink {
                        QuotaStatusView(app: app)
                    } label: {
                        Text("查看超额详情")
                    }
                }
            }
        }
        .navigationTitle("同步失败详情")
        .navigationBarTitleDisplayMode(.inline)
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }
}

// MARK: - 2.5 detail

struct ItemDetailView: View {
    let app: AppModel
    let row: ItemRow
    @Environment(\.dismiss) private var dismiss
    @State private var plaintext: String?
    @State private var plaintextHidden = true
    @State private var showRotate = false
    @State private var showEdit = false
    @State private var confirmDelete = false

    var body: some View {
        List {
            Section {
                InfoRow(label: "ref", value: row.ref, mono: true)
                InfoRow(label: "类型", value: Format.typeBadge(row.type))
                InfoRow(label: "掩码", value: row.masked, mono: true)
                if !row.itemDescription.isEmpty {
                    InfoRow(label: "描述", value: row.itemDescription)
                }
                InfoRow(label: "创建时间", value: Format.dateTime(row.createdAt))
                InfoRow(label: "修改时间", value: Format.dateTime(row.updatedAt))
            } header: {
                Text("基本信息")
            } footer: {
                PolicySummaryRow(row: row)
            }

            plaintextSection

            Section("已授权设备") {
                if row.grants.isEmpty {
                    Text("还没有设备被授予这条条目。")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(row.grants) { grant in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(app.devices.device(id: grant.deviceID)?.label ?? "设备")
                                Text("\(Format.grantLevelLabel(grant.kind)) · 到期 \(Format.dateTime(grant.expiresAt))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            ExpiryChip(mark: .mark(expiresAt: Date(timeIntervalSince1970: Double(grant.expiresAt) / 1000)))
                        }
                    }
                }
            }
        }
        .navigationTitle(row.name)
        .navigationBarTitleDisplayMode(.inline)
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("编辑") { showEdit = true }
            }
        }
        .sheet(isPresented: $showRotate) {
            RotateSheet(app: app, row: row)
        }
        .sheet(isPresented: $showEdit) {
            NavigationStack {
                ItemEditView(app: app, mode: .edit(existing: row))
            }
        }
        .confirmationDialog("删除 \(row.ref)？", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive) {
                Task {
                    let auth = await app.authenticator.authenticate(reason: "删除 \(row.ref)")
                    guard case .success = auth else { return }
                    let ok = await app.items.delete(itemID: row.id)
                    if ok { dismiss() }
                }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("agent 对它的引用会立刻失效，同步后不可撤销。")
        }
    }

    /// 查看明文：每次点开都要 Face ID（§3.1），30 秒无操作自动收起；
    /// 「拷贝」只存在于明文层（§3.4）。展开层的收起/拷贝按钮是 §3.8 的
    /// `glassEffect(.regular)` 胶囊，同屏两个玻璃元素包进 GlassEffectContainer。
    @ViewBuilder
    var plaintextSection: some View {
        Section("明文") {
            if let plaintext {
                HStack {
                    Group {
                        if plaintextHidden {
                            Text(String(repeating: "•", count: 12))
                                .textSelection(.disabled)
                        } else {
                            Text(plaintext)
                                .textSelection(.enabled)
                        }
                    }
                    .font(.body.monospaced())
                    .lineLimit(plaintextHidden ? 1 : 4)
                    Spacer()
                    if plaintextHidden {
                        Button {
                            plaintextHidden.toggle()
                        } label: {
                            Image(systemName: "eye")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("显示明文")
                    } else {
                        GlassEffectContainer(spacing: 10) {
                            HStack(spacing: 10) {
                                Button {
                                    app.backendCopyPlaintext(plaintext)
                                } label: {
                                    Image(systemName: "doc.on.doc")
                                        .padding(8)
                                }
                                .glassEffect(.regular)
                                .accessibilityLabel("拷贝")
                                Button {
                                    plaintextHidden.toggle()
                                } label: {
                                    Image(systemName: "eye.slash")
                                        .padding(8)
                                }
                                .glassEffect(.regular)
                                .accessibilityLabel("收起明文")
                            }
                        }
                    }
                }
            } else {
                Button {
                    Task {
                        app.haptics.fire(.lightImpact)
                        if let value = await app.items.reveal(itemID: row.id,
                                                              authenticator: app.authenticator) {
                            plaintext = value
                            plaintextHidden = false
                            scheduleAutoCollapse()
                        }
                    }
                } label: {
                    Label("查看明文", systemImage: "faceid")
                }
            }
        }
    }

    /// 30 秒无操作自动收起（肩窥面；不打断 30 秒内完成的核对或抄写）。
    func scheduleAutoCollapse() {
        Task {
            try? await Task.sleep(for: .seconds(30))
            plaintextHidden = true
        }
    }
}

/// 替换值（轮换）sheet：新值输入框（不回显旧值）→ 确认行 → Face ID。
struct RotateSheet: View {
    let app: AppModel
    let row: ItemRow
    @Environment(\.dismiss) private var dismiss
    @State private var newValue = ""
    @State private var working = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("新值", text: $newValue)
                        .font(.body.monospaced())
                    Text("保存后将生成新的条目密钥，重新加密并重新下发给所有已授权设备（\(row.grants.count) 台）。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("替换值（轮换）")
                } footer: {
                    Text("ref、名称、策略不动。旧值不会显示。")
                }
            }
            .navigationTitle("替换值")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        Task {
                            working = true
                            let auth = await app.authenticator.authenticate(reason: "轮换 \(row.ref)")
                            guard case .success = auth else {
                                working = false
                                return
                            }
                            _ = await app.items.rotate(itemID: row.id, newValue: newValue)
                            working = false
                            dismiss()
                        }
                    }
                    .disabled(newValue.isEmpty || working)
                }
            }
        }
        .presentationDetents([.medium])
    }
}

// MARK: - 2.6 new / edit

struct ItemEditView: View {
    let app: AppModel
    @State private var model: ItemEditorModel
    @Environment(\.dismiss) private var dismiss

    init(app: AppModel, mode: ItemEditorModel.Mode) {
        self.app = app
        let refs = Dictionary(uniqueKeysWithValues:
            app.items.rows.map { ($0.ref.lowercased(), $0.name) })
        _model = State(initialValue: ItemEditorModel(mode: mode, backend: app.backend,
                                                     haptics: app.haptics,
                                                     existingRefs: refs))
    }

    var body: some View {
        Form {
            fieldsSection
            policySection
        }
        .navigationTitle(model.isCreate ? "新建条目" : "编辑条目")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("取消") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("保存") {
                    Task { await save(force: false) }
                }
                .disabled(!model.canSave || model.saving)
            }
        }
        // §7.3：添加的名字命中默认拒绝名单时，保存前弹一次确认。
        .confirmationDialog("“\(model.pendingDenyListWarning ?? "")” 在默认拒绝名单上",
                            isPresented: Binding(
                                get: { model.pendingDenyListWarning != nil },
                                set: { if !$0 { model.pendingDenyListWarning = nil } }),
                            titleVisibility: .visible) {
            Button("仍然加入", role: .destructive) {
                model.pendingDenyListWarning = nil
                Task { await save(force: true) }
            }
            Button("取消", role: .cancel) {
                model.pendingDenyListWarning = nil
            }
        } message: {
            Text("把它加入白名单后，agent 可以启动解释器，输出脱敏对解释器内部打印的内容无效。Phase 1 没有审批机制兜底，除非确有需要，不要放行。")
        }
        // §12.1 流程 3：名称/描述与条目值及常见编码比对；可强制保存。
        .confirmationDialog(leakTitle,
                            isPresented: Binding(
                                get: { model.pendingLeakWarning != nil },
                                set: { if !$0 { model.pendingLeakWarning = nil } }),
                            titleVisibility: .visible) {
            Button("回去修改", role: .cancel) {
                model.pendingLeakWarning = nil
            }
            Button("我知道，仍然保存", role: .destructive) {
                model.pendingLeakWarning = nil
                Task { await save(force: true) }
            }
        } message: {
            Text("名称与描述会进入 agent 的上下文，agent 能直接读到。检测到与条目值或其 Base64 / hex / URL 编码一致。")
        }
        .alert("保存失败", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } })) {
            Button("好", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }

    var leakTitle: String {
        guard let finding = model.pendingLeakWarning?.first else { return "" }
        return "名称里出现了这条秘密".replacingOccurrences(of: "名称", with: finding.field)
    }

    @ViewBuilder
    var fieldsSection: some View {
        Section {
            TextField("名称", text: $model.name)
            if model.isCreate {
                TextField("ref", text: $model.ref)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
                if !model.refIsValid {
                    Label("ref 需要是小写字母开头的短横线串。", systemImage: "exclamationmark.circle")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                if let conflict = model.refConflictMessage {
                    Label(conflict, systemImage: "exclamationmark.circle")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                Picker("类型", selection: $model.type) {
                    Text("API key").tag("api_key")
                    Text("Token").tag("token")
                    Text("密码").tag("password")
                    Text("笔记").tag("note")
                    Text("通用").tag("generic")
                }
            } else {
                LabeledContent("ref", value: model.ref)
                    .font(.body.monospaced())
            }
            SecureField(model.isCreate ? "值" : "值（留空 = 不修改）", text: $model.value)
                .font(.body.monospaced())
            TextField("描述", text: $model.itemDescription)
        } header: {
            Text("字段")
        } footer: {
            if !model.isCreate {
                Text("ref 是脚本和对话里的稳定引用，创建后不可改名。")
            }
        }
    }

    /// 策略区（Phase 1 基础编辑，§13）。
    @ViewBuilder
    var policySection: some View {
        Section {
            // Phase 1 固定「标准」，不提供 approval 档位。
            LabeledContent("敏感级别", value: "标准")
            Toggle(isOn: $model.denyShells) {
                Text("拒绝 shell 与解释器")
            }
            TextField("命令白名单（逗号分隔）", text: $model.allowCommandsText)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.body.monospaced())
            TextField("允许的主机（逗号分隔）", text: $model.allowedHostsText)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .font(.body.monospaced())
            Toggle(isOn: Binding(
                get: { model.allowArgv },
                set: { newValue in
                    if newValue {
                        app.haptics.fire(.warning)
                        model.pendingAllowArgvAlert = true
                    } else {
                        model.allowArgv = false
                    }
                })) {
                Text("允许放进进程参数（--allow-argv）")
            }
            if model.type == "note" {
                Toggle(isOn: $model.injectable) {
                    Text("允许注入命令")
                }
            }
        } header: {
            Text("策略")
        } footer: {
            Text("只检查命令参数里出现的 http(s) 主机名，必须与列表完全一致。重定向、IP 直连、程序内拼出的 URL 都查不到——这不是网络隔离。")
        }
        .alert("进程参数对本机所有用户可见", isPresented: $model.pendingAllowArgvAlert) {
            Button("允许", role: .destructive) {
                model.allowArgv = true
            }
            Button("不允许", role: .cancel) {
                model.allowArgv = false
            }
        } message: {
            Text("打开后，秘密可以出现在命令行参数里。同一台机器上的任何用户都能通过进程列表（ps、活动监视器）看到。CLI 侧还必须显式加 --allow-argv，两边都打开才生效。")
        }
    }

    func save(force: Bool) async {
        let outcome = await model.save(force: force)
        switch outcome {
        case .saved:
            await app.items.refresh()
            dismiss()
        case .needsDenyListConfirmation(let name):
            model.pendingDenyListWarning = name
        case .needsLeakConfirmation(let findings):
            model.pendingLeakWarning = findings
        case .failed(let message):
            model.errorMessage = message
        }
    }
}
