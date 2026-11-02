// SMS inbox (design v0.8 §14.4): the verification codes this iPhone can
// read, grouped by the source phone's plaintext label, newest first, with
// the per-message delete and the clear-all. Every row is already decrypted
// and expiry-filtered — a message this device was not a recipient of never
// reaches the list.
import SwiftUI
import KeyrefCore

struct MessageInboxView: View {
    let app: AppModel
    @Bindable var messages: MessagesStore
    @Environment(\.dismiss) private var dismiss
    @State private var confirmClear = false
    @State private var selected: MessageInboxEntry?

    init(app: AppModel) {
        self.app = app
        _messages = Bindable(wrappedValue: app.messages)
    }

    var body: some View {
        Group {
            if messages.entries.isEmpty {
                emptyState
            } else {
                list
            }
        }
        .navigationTitle("收件箱")
        .navigationBarTitleDisplayMode(.inline)
        .keyrefListSurface()
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
        .toolbar {
            if !messages.entries.isEmpty {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("清空") { confirmClear = true }
                }
            }
        }
        .confirmationDialog("清空收件箱？", isPresented: $confirmClear,
                            titleVisibility: .visible) {
            Button("清空", role: .destructive) {
                Task { await messages.clear() }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("删除后无法找回。agent 已用掉的验证码不会重新出现。")
        }
        .sheet(item: $selected) { entry in
            NavigationStack {
                MessageDetailView(entry: entry) {
                    Task { await messages.delete(entry) }
                    selected = nil
                }
            }
        }
        .task { await messages.refresh() }
        .refreshable { await messages.refresh() }
        .overlay(alignment: .bottom) {
            if let toast = messages.toast {
                ToastView(text: toast)
                    .task {
                        try? await Task.sleep(for: .seconds(2))
                        messages.toast = nil
                    }
            }
        }
    }

    /// 空态：没有验证码时不是一句道歉，而是说明这条链路怎么工作。
    var emptyState: some View {
        VStack(spacing: 14) {
            KeyrefGlyphCircle(systemName: "envelope", tint: KeyrefTheme.muted)
            Text("没有新的验证码")
                .font(.title3.weight(.semibold))
            Text("采集设备收到验证码短信后会加密上传到这里。消息 24 小时后自动销毁，agent 用掉一次就消失。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(KeyrefBackdrop())
    }

    /// 按来源设备分组（§14.4：明文 label 正是「哪一台手机」）。
    var list: some View {
        List {
            ForEach(messages.sourceLabels, id: \.self) { label in
                Section {
                    ForEach(messages.entries(from: label)) { entry in
                        Button {
                            selected = entry
                        } label: {
                            MessageRowView(entry: entry)
                        }
                        .buttonStyle(.plain)
                        #if os(iOS)
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                Task { await messages.delete(entry) }
                            } label: {
                                Label("删除", systemImage: "trash")
                            }
                        }
                        #endif
                    }
                } header: {
                    KeyrefSectionLabel(text: label)
                }
            }
        }
        .listStyle(.plain)
    }
}

/// 一行验证码：发信号码、正文（正文里就是验证码本身）、到达时间与剩余有效期。
struct MessageRowView: View {
    let entry: MessageInboxEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                Text(entry.sender.isEmpty ? "未知号码" : entry.sender)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                Spacer(minLength: 4)
                Text(Format.shortClock(entry.receivedAt))
                    .font(.caption2.monospaced())
                    .foregroundStyle(KeyrefTheme.muted)
            }
            Text(entry.body)
                .font(.callout)
                .foregroundStyle(KeyrefTheme.foreground)
                .lineLimit(3)
                .multilineTextAlignment(.leading)
            Text(entry.remainingLabel())
                .font(.caption2)
                .foregroundStyle(entry.remainingSeconds() < 3600 ? KeyrefTheme.warning : KeyrefTheme.muted)
        }
        .padding(.vertical, 10)
        .contentShape(Rectangle())
    }
}

/// 详情：完整正文（可能比列表里的三行长），以及删除。
struct MessageDetailView: View {
    let entry: MessageInboxEntry
    let onDelete: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    IconGlyph(systemName: "envelope", size: 18)
                    Text(entry.sender.isEmpty ? "未知号码" : entry.sender)
                        .font(.headline)
                    Spacer(minLength: 0)
                }
                Text(entry.body)
                    .font(.body)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                KeyrefBlock {
                    VStack(alignment: .leading, spacing: 8) {
                        InfoRow(label: "来源设备", value: entry.sourceLabel)
                        InfoRow(label: "到达时间", value: Format.dateTime(entry.receivedAt), mono: true)
                        InfoRow(label: "剩余有效期", value: entry.remainingLabel())
                        if !entry.sim.isEmpty {
                            InfoRow(label: "SIM", value: entry.sim)
                        }
                    }
                }
                Text("发信号码可以伪造，它只是参考信号。用掉这条验证码的是你在审批页批准的那一次执行。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .padding(24)
        }
        .background(KeyrefBackdrop())
        .navigationTitle("验证码")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("关闭") { dismiss() }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button(role: .destructive) { onDelete() } label: {
                    Image(systemName: "trash")
                }
                .accessibilityLabel("删除这条验证码")
            }
        }
    }
}
