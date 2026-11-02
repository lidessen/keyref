// Auto-approval delegation (design v0.8 §14.8, docs/ios-ui.md): the
// settings entry row, the editing page (senders, age and rate caps, CLI
// allowlist) and the withdraw action. Flat page, hairlines, monospace
// metadata — nothing here draws a card.
//
// The page is deliberately explicit about what the decider gets: the
// plaintext of every message inside the TTL, and a review step that
// cannot be switched off. And it never pretends a save succeeded — the
// store only moves the shown state after the server accepted the new
// revision.
import SwiftUI
import KeyrefCore

// MARK: - settings entry (§2.14)

/// The row Settings renders: name + one-word status, nothing else.
struct DelegationStatusRow: View {
    let app: AppModel

    var body: some View {
        HStack(spacing: 12) {
            IconGlyph(systemName: "checkmark.seal", size: 18)
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent("自动审批委托",
                               value: app.delegation.statusLabel)
                Text(summary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var summary: String {
        guard let state = app.delegation.state, state.isActive else {
            return "每条短信的消费都要在手机上确认"
        }
        var parts: [String] = []
        parts.append("\(state.policy.senders.count) 个发信号码")
        if state.policy.maxAgeMin > 0 { parts.append("最长 \(state.policy.maxAgeMin) 分钟") }
        if state.policy.perCLIHourly > 0 { parts.append("每小时 \(state.policy.perCLIHourly) 次") }
        if state.policy.perCLIDaily > 0 { parts.append("每天 \(state.policy.perCLIDaily) 次") }
        parts.append(state.policy.cliDevices.isEmpty ? "CLI 不限" : "\(state.policy.cliDevices.count) 台 CLI")
        return parts.joined(separator: " · ")
    }
}

// MARK: - editing page

struct DelegationEditView: View {
    let app: AppModel
    @Bindable var delegation: DelegationStore

    /// Draft edits. Seeded once from the server state, then owned by the
    /// page — a background refresh must not silently discard typing.
    @State private var senders: [String] = []
    @State private var newSender = ""
    @State private var maxAgeMin = 0
    @State private var perCLIHourly = 0
    @State private var perCLIDaily = 0
    @State private var cliDevices: Set<String> = []
    @State private var seeded = false
    @State private var showWithdrawConfirm = false
    /// Inline hint when 发信号码 is over the 64-byte policy bound —
    /// silently dropping the input would look like a dead button.
    @State private var senderError: String?

    init(app: AppModel) {
        self.app = app
        _delegation = Bindable(wrappedValue: app.delegation)
    }

    private var cliCandidates: [DeviceRow] {
        app.devices.rows.filter { $0.isCLI && $0.isActive }
    }

    private var draftEmpty: Bool { senders.isEmpty }

    var body: some View {
        Form {
            warningSection
            statusSection
            sendersSection
            limitsSection
            cliSection
            actionsSection
        }
        .navigationTitle("自动审批委托")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
        .task {
            guard !seeded else { return }
            await delegation.refresh()
            await app.devices.refresh()
            seedDraft()
            seeded = true
        }
        .overlay(alignment: .top) {
            if let toast = delegation.toast {
                ToastView(text: toast)
                    .task {
                        try? await Task.sleep(for: .seconds(2))
                        delegation.toast = nil
                    }
            }
        }
        .alert("撤回委托", isPresented: $showWithdrawConfirm) {
            Button("撤回", role: .destructive) {
                Task { await delegation.withdraw() }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("会签一份新的空策略，决策器从此批不了任何短信，每条消费都回到手机上确认。它在撤回前已经拿到的短信明文，最长保留到各自到期。")
        }
    }

    // MARK: sections

    /// 两块明示：决策器拿到什么、哪一步关不掉（design §14.8）。
    var warningSection: some View {
        Section {
            KeyrefNotice(systemName: "exclamationmark.triangle.fill",
                         tint: KeyrefTheme.warning,
                         text: "决策器持有有效期内全部短信的明文——它要读正文才能判断。妥协一台决策器的损失止于这批短信，碰不到条目与授权。",
                         emphasis: true)
            KeyrefNotice(systemName: "checkmark.shield.fill",
                         tint: KeyrefTheme.info,
                         text: "decision API 复核是自动放行的必要步骤，不可关闭。结构策略命中只是必要条件，复核否决就保持待审批。",
                         emphasis: true)
        } header: {
            KeyrefSectionLabel(text: "先读这些")
        }
        .listRowSeparator(.hidden)
    }

    var statusSection: some View {
        Section {
            LabeledContent("状态", value: delegation.statusLabel)
            LabeledContent("当前版本",
                           value: delegation.state.map { "\($0.revision)" } ?? "—")
                .font(.callout.monospacedDigit())
            if let error = delegation.lastError {
                Label(error, systemImage: "exclamationmark.circle")
                    .font(.footnote)
                    .foregroundStyle(KeyrefTheme.danger)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } header: {
            KeyrefSectionLabel(text: "委托")
        } footer: {
            Text("每保存一次版本号加一，服务器只接受比现在更大的版本。")
        }
    }

    var sendersSection: some View {
        Section {
            ForEach(senders, id: \.self) { sender in
                HStack {
                    Text(sender)
                        .font(.body.monospaced())
                    Spacer()
                    Button {
                        senders.removeAll { $0 == sender }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("移除 \(sender)")
                }
            }
            HStack {
                TextField("添加发信号码（如 10086）", text: $newSender)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
                    .onChange(of: newSender) { _, _ in senderError = nil }
                    .onSubmit(addSender)
                Button("添加", action: addSender)
                    .disabled(newSender.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if let senderError {
                Text(senderError)
                    .font(.footnote)
                    .foregroundStyle(KeyrefTheme.danger)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } header: {
            Text("允许的发信号码")
        } footer: {
            Text("必须与短信里的发信号码逐字节一致——不做前缀匹配，也不认国家码。留空等于撤回：没有任何发信号码能被自动批准。")
        }
    }

    var limitsSection: some View {
        Section {
            Stepper(value: $maxAgeMin, in: 0...1440) {
                LabeledContent("消息最大年龄",
                               value: maxAgeMin == 0 ? "不限" : "\(maxAgeMin) 分钟")
            }
            Stepper(value: $perCLIHourly, in: 0...1000) {
                LabeledContent("每台 CLI 每小时上限",
                               value: perCLIHourly == 0 ? "不限" : "\(perCLIHourly) 次")
            }
            Stepper(value: $perCLIDaily, in: 0...10000) {
                LabeledContent("每台 CLI 每天上限",
                               value: perCLIDaily == 0 ? "不限" : "\(perCLIDaily) 次")
            }
        } header: {
            Text("年龄与频次")
        } footer: {
            Text("年龄按服务器收到的时间算，不是短信里写的时间。0 表示不设这一项限制——留 0 不是「关掉委托」，发信号码那节才是。")
        }
    }

    var cliSection: some View {
        Section {
            if cliCandidates.isEmpty {
                Text("还没有可用的 CLI 设备。先配对一台，再回来限制。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ForEach(cliCandidates) { device in
                Button {
                    if cliDevices.contains(device.id) {
                        cliDevices.remove(device.id)
                    } else {
                        cliDevices.insert(device.id)
                    }
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: cliDevices.contains(device.id)
                              ? "checkmark.circle.fill" : "circle")
                            .foregroundStyle(cliDevices.contains(device.id)
                                             ? KeyrefTheme.success : KeyrefTheme.muted)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(device.label)
                            Text(device.id)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        Spacer(minLength: 0)
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(device.label)，\(cliDevices.contains(device.id) ? "已允许" : "未允许")")
            }
        } header: {
            Text("允许的 CLI 设备")
        } footer: {
            Text("一个都不勾＝不限制，任何 CLI 都可能被自动批准。勾上之后只有列出的设备能走委托，其余一律回到人工审批。")
        }
    }

    var actionsSection: some View {
        Section {
            Button {
                Task {
                    if await delegation.save(draftPolicy()) {
                        seedDraft()
                    }
                }
            } label: {
                Text(delegation.saving ? "签署中…" : "保存并签署")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(KeyrefPrimaryButtonStyle())
            .disabled(delegation.saving || (draftEmpty && !delegation.isActive))

            if delegation.isActive {
                Button(role: .destructive) {
                    showWithdrawConfirm = true
                } label: {
                    Text("撤回委托")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(KeyrefSecondaryButtonStyle())
                .disabled(delegation.saving)
            }
        } footer: {
            if let state = delegation.state {
                Text("保存会用这台 iPhone 的 owner 密钥签署新版本（当前 \(state.revision)，下一次 \(state.revision + 1)）。失败不会改动已经生效的委托。")
            } else {
                Text("保存会用这台 iPhone 的 owner 密钥签署第一版（版本 1）。失败不会留下任何委托。")
            }
        }
    }

    // MARK: draft

    private func seedDraft() {
        let policy = delegation.state?.policy ?? .revocation
        senders = policy.senders
        maxAgeMin = Int(policy.maxAgeMin)
        perCLIHourly = Int(policy.perCLIHourly)
        perCLIDaily = Int(policy.perCLIDaily)
        cliDevices = Set(policy.cliDevices)
        newSender = ""
    }

    private func draftPolicy() -> KeyrefDelegationPolicy {
        KeyrefDelegationPolicy(
            senders: senders,
            maxAgeMin: Int64(maxAgeMin),
            perCLIHourly: Int64(perCLIHourly),
            perCLIDaily: Int64(perCLIDaily),
            cliDevices: cliDevices.sorted())
    }

    private func addSender() {
        let trimmed = newSender.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        // Same bounds the policy enforces — catch them before the save path.
        guard trimmed.utf8.count <= 64 else {
            senderError = "发信号码最长 64 字节，这一条没有加上。"
            return
        }
        guard !senders.contains(trimmed) else {
            senderError = "这个发信号码已经在列表里了。"
            return
        }
        senderError = nil
        senders.append(trimmed)
        newSender = ""
    }
}
