// Audit tab (docs/ios-ui.md §2.11): the locally decrypted event stream with
// device / ref / result filters, the event detail with placeholder-form argv
// and its VoiceOver reading, and the retention footnote.
import SwiftUI
import KeyrefCore

struct AuditListView: View {
    let app: AppModel
    @Bindable var audit: AuditStore
    var initialDeviceFilter: String?

    init(app: AppModel, initialDeviceFilter: String? = nil) {
        self.app = app
        _audit = Bindable(wrappedValue: app.audit)
        self.initialDeviceFilter = initialDeviceFilter
    }

    var body: some View {
        NavigationStack {
            Group {
                if audit.rows.isEmpty && !audit.batchFailed {
                    emptyState
                } else if audit.batchFailed {
                    batchFailedState
                } else {
                    list
                }
            }
            .navigationTitle("审计")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    filterMenu
                }
            }
            .refreshable {
                await audit.refresh(authenticator: app.authenticator)
            }
            .task {
                if let initialDeviceFilter { audit.deviceFilter = initialDeviceFilter }
                await audit.refresh(authenticator: app.authenticator)
            }
        }
    }

    /// 空态（§2.11）。
    var emptyState: some View {
        ContentUnavailableView {
            Label("还没有审计记录", systemImage: "list.bullet.rectangle")
        } description: {
            Text("agent 第一次用 keyref exec 之后，每一次尝试——包括被拒绝的——都会出现在这里。")
        }
    }

    /// 整批失败（§2.11 失败态）。
    var batchFailedState: some View {
        ContentUnavailableView {
            Label("审计解密失败，下拉重试。", systemImage: "lock.rotation")
        } description: {
            Text("审计正文加密给 owner，只在本机解密；解不开就不显示占位内容冒充数据。")
        }
    }

    var filterMenu: some View {
        Menu {
            Picker("设备", selection: $audit.deviceFilter) {
                Text("全部设备").tag(String?.none)
                ForEach(audit.deviceNames, id: \.self) { name in
                    Text(name).tag(String?.some(name))
                }
            }
            Picker("结果", selection: $audit.resultFilter) {
                ForEach(AuditResultFilter.allCases, id: \.self) { f in
                    Text(f.label).tag(f)
                }
            }
            Picker("ref", selection: $audit.refFilter) {
                Text("全部 ref").tag(String?.none)
                ForEach(audit.refs, id: \.self) { ref in
                    Text(ref).tag(String?.some(ref))
                }
            }
        } label: {
            Image(systemName: "line.3.horizontal.decrease.circle")
        }
        .accessibilityLabel("筛选")
    }

    var list: some View {
        List {
            Section {
                ForEach(audit.filtered) { row in
                    NavigationLink {
                        AuditDetailView(app: app, row: row)
                    } label: {
                        AuditRowView(row: row, deviceLabel: audit.deviceLabel(row.deviceID))
                    }
                }
            } footer: {
                Text(AuditStore.retentionFootnote)
            }
        }
        .listStyle(.plain)
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }
}

/// 列表行：时间、设备名、`ref` 列表（截断）、结果徽标、脱敏替换次数。
struct AuditRowView: View {
    let row: AuditRow
    let deviceLabel: String

    var body: some View {
        if row.decryptFailed || row.payload == nil {
            VStack(alignment: .leading, spacing: 2) {
                Text("一条无法解密的记录")
                    .font(.body)
                    .foregroundStyle(.secondary)
                Text(Format.dateTime(row.createdAt))
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        } else if let payload = row.payload {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(Format.dateTime(row.createdAt))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    resultBadge(payload)
                }
                Text(deviceLabel)
                    .font(.footnote.weight(.medium))
                Text(payload.refs.isEmpty ? "（无 ref）" : payload.refs.joined(separator: "、"))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Text("脱敏替换 \(payload.redactions) 次")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            .padding(.vertical, 2)
        }
    }

    @ViewBuilder
    func resultBadge(_ payload: AuditEventPayload) -> some View {
        let text = Format.auditResultBadge(policyResult: payload.policyResult,
                                           childExit: payload.childExit)
        let denied = text == "被拒绝"
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background((denied ? Color.red : Color.green).opacity(0.14), in: Capsule())
            .foregroundStyle(denied ? Color.red : Color.green)
    }
}

/// 事件详情：完整 argv（占位符形式、等宽）、注入方式、策略结果、退出码、
/// 脱敏替换次数、时间与设备。只读（§1.2 深度原则）。
struct AuditDetailView: View {
    let app: AppModel
    let row: AuditRow

    var body: some View {
        List {
            if let payload = row.payload {
                Section("命令") {
                    ForEach(Array(payload.argv.enumerated()), id: \.offset) { _, arg in
                        Text(arg)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                            .accessibilityLabel(Format.argvSpokenForm(arg))
                    }
                }
                Section("详情") {
                    InfoRow(label: "注入方式", value: payload.injection.joined(separator: " / ").uppercased())
                    InfoRow(label: "策略结果", value: payload.policyResult)
                    if let approval = payload.approvalResult {
                        InfoRow(label: "审批结果", value: approval == "approved" ? "已批准" : "已拒绝")
                    }
                    InfoRow(label: "退出码", value: String(payload.childExit))
                    InfoRow(label: "脱敏替换次数", value: String(payload.redactions))
                    InfoRow(label: "时间", value: Format.dateTime(row.createdAt))
                    InfoRow(label: "设备", value: app.audit.deviceLabel(row.deviceID))
                }
                Section {
                    Text("argv 显示的是占位符形式，keyref 不会记录替换后的秘密。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else {
                Section {
                    Text("一条无法解密的记录")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("事件详情")
        .navigationBarTitleDisplayMode(.inline)
    }
}
