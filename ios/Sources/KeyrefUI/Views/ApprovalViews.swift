// Approval inbox (Phase 2, docs/design.md §8.3, docs/ios-ui.md §5): the
// device-tab entry point with its badge, the inbox list (S8 empty copy), and
// the detail page showing argv 原文（含 {{keyref:REF}} 占位符与 --allow-argv
// / --reply 模式）、条目名称与 ref、注入方式、发起设备、倒计时，批准与拒绝
// 同页。批准需 Face ID（§8.3）；拒绝不动任何密钥材料。
import SwiftUI
import KeyrefCore

// MARK: - inbox

struct ApprovalInboxView: View {
    let app: AppModel
    @Bindable var approvals: ApprovalsStore

    init(app: AppModel) {
        self.app = app
        _approvals = Bindable(wrappedValue: app.approvals)
    }

    var body: some View {
        Group {
            if approvals.displayEntries.isEmpty {
                emptyState
            } else {
                inboxList
            }
        }
        .navigationTitle("待审批")
        .navigationBarTitleDisplayMode(.inline)
        .task { await approvals.refresh() }
        .overlay(alignment: .bottom) {
            if let toast = approvals.toast {
                ToastView(text: toast)
                    .task {
                        try? await Task.sleep(for: .seconds(2))
                        approvals.toast = nil
                    }
            }
        }
    }

    /// S8（§5）：空态文案。
    var emptyState: some View {
        ZStack {
            KeyrefBackdrop()
            VStack(spacing: 14) {
                KeyrefGlyphCircle(systemName: "checkmark.shield.fill",
                                  tint: KeyrefTheme.success)
                Text("没有待审批的请求")
                    .font(.title3.weight(.semibold))
                Text("当 agent 发起需要批准的执行时，请求会出现在这里，2 分钟内有效。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 12)
            }
            .padding(28)
        }
    }

    var inboxList: some View {
        List {
            ForEach(approvals.displayEntries) { entry in
                if entry.valid {
                    NavigationLink {
                        ApprovalDetailView(app: app, approvals: approvals, entry: entry)
                    } label: {
                        ApprovalRowView(entry: entry)
                    }
                    .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 0, trailing: 12))
                    .listRowBackground(Color.clear)
                    .listRowSeparatorTint(KeyrefTheme.hairline)
                } else {
                    invalidRow(entry)
                        .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 0, trailing: 12))
                        .listRowBackground(Color.clear)
                        .listRowSeparatorTint(KeyrefTheme.hairline)
                }
            }
        }
        .listStyle(.plain)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }

    /// 验不过的请求显示为无效并可忽略（§8.3）：不进入详情、不提交任何决定。
    func invalidRow(_ entry: ApprovalInboxEntry) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("无效的审批请求")
                    .font(.body.weight(.medium))
                Text("签名没有通过校验，或请求已损坏。可以忽略。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("忽略") {
                approvals.ignore(entry)
            }
            .buttonStyle(.borderless)
        }
    }
}

// MARK: - row

struct ApprovalRowView: View {
    let entry: ApprovalInboxEntry

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            IconGlyph(systemName: "checkmark.shield.fill", size: 20)
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(entry.itemName)
                        .font(.subheadline.weight(.semibold))
                    Spacer(minLength: 4)
                    ApprovalCountdown(expiresAt: entry.expiresAt)
                }
                Text(entry.argv.joined(separator: " "))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                Text("\(entry.cliDeviceLabel) · \(entry.injectionLabel)")
                    .font(.caption2)
                    .foregroundStyle(KeyrefTheme.muted)
            }
        }
        .padding(.vertical, 12)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(entry.itemName)，来自 \(entry.cliDeviceLabel)，\(entry.injectionLabel)")
    }
}

/// 倒计时（§8.3：2 分钟超时，包裹 60 秒）。过期后禁批。
struct ApprovalCountdown: View {
    let expiresAt: Int64

    var expiryDate: Date {
        Date(timeIntervalSince1970: Double(expiresAt) / 1000)
    }

    var expired: Bool { expiryDate <= Date() }

    var body: some View {
        if expired {
            Text("已过期")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(KeyrefTheme.muted)
        } else {
            Text(timerInterval: Date()...expiryDate, countsDown: true)
                .font(.caption.monospacedDigit().weight(.semibold))
                .foregroundStyle(KeyrefTheme.warning)
                .accessibilityLabel("剩余 \(Int(expiryDate.timeIntervalSinceNow / 60)) 分钟")
        }
    }
}

// MARK: - detail (批准 / 拒绝同页)

struct ApprovalDetailView: View {
    let app: AppModel
    @Bindable var approvals: ApprovalsStore
    let entry: ApprovalInboxEntry
    @Environment(\.dismiss) private var dismiss
    @State private var working = false

    var body: some View {
        List {
            commandSection
            contextSection
            decisionSection
        }
        .navigationTitle("审批请求")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }

    /// argv 原文：占位符形式，keyref 不记录替换后的秘密（§7.5）。
    var commandSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 7) {
                ForEach(Array(entry.argv.enumerated()), id: \.offset) { _, arg in
                    Text(arg)
                        .font(.footnote.monospaced())
                        .foregroundStyle(KeyrefTheme.onSlab)
                        .textSelection(.enabled)
                        .accessibilityLabel(Format.argvSpokenForm(arg))
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
            .background(KeyrefTheme.slab,
                        in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(KeyrefTheme.onSlab.opacity(0.18), lineWidth: 1)
            )
        } header: {
            Text("命令原文")
        } footer: {
            Text("argv 显示的是占位符形式，keyref 不会在这里替换出秘密。--allow-argv 与 --reply 的完整模式都在原文里，由你把关。")
        }
    }

    var contextSection: some View {
        Section("请求内容") {
            InfoRow(label: "条目", value: entry.itemName)
            if !entry.itemRef.isEmpty {
                InfoRow(label: "ref", value: entry.itemRef, mono: true)
            }
            InfoRow(label: "注入方式", value: entry.injectionLabel)
            InfoRow(label: "refs", value: entry.refs.joined(separator: ", "), mono: true)
            if !entry.hosts.isEmpty {
                InfoRow(label: "主机（参数检查）", value: entry.hosts.joined(separator: ", "), mono: true)
            }
            InfoRow(label: "发起设备", value: entry.cliDeviceLabel)
            HStack {
                Text("剩余时间")
                    .foregroundStyle(.secondary)
                    .font(.callout)
                Spacer()
                ApprovalCountdown(expiresAt: entry.expiresAt)
            }
        }
    }

    var decisionSection: some View {
        Section {
            Button {
                Task { await decide(true) }
            } label: {
                if working {
                    ProgressView()
                } else {
                    Label("批准（Face ID）", systemImage: "checkmark.shield.fill")
                        .frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(KeyrefPrimaryButtonStyle())
            .disabled(expired || working)
            Button(role: .destructive) {
                Task { await decide(false) }
            } label: {
                Text("拒绝")
                    .frame(maxWidth: .infinity)
            }
            .disabled(expired || working)
        } footer: {
            Text("批准后，这条条目的密钥会以一次性包裹发给发起设备，只对这次请求有效（60 秒内取走，§8.3）。")
        }
    }

    var expired: Bool {
        Date(timeIntervalSince1970: Double(entry.expiresAt) / 1000) <= Date()
    }

    func decide(_ approve: Bool) async {
        working = true
        defer { working = false }
        let ok = await approvals.decide(entry, approve: approve,
                                        authenticator: app.authenticator)
        if ok { dismiss() }
    }
}
