// Shared SwiftUI building blocks for the keyref UI (docs/ios-ui.md §2–§3):
// the sync accessory capsule (§3.8), quota/frozen banners (S12, S13), type
// badges, expiry chips (S14), fingerprint text, masks with their VoiceOver
// readings, and the recovery-code display + grouped backfill input (S9).
// Liquid Glass rules (§3.8): system chrome stays system; self-drawn floating
// layers use glassEffect; no hand-drawn translucent materials.
import SwiftUI
import KeyrefCore

// MARK: - environment

public enum AppEnvironmentKey: EnvironmentKey {
    public static let defaultValue: AppModel? = nil
}

public extension EnvironmentValues {
    var appModel: AppModel? {
        get { self[AppEnvironmentKey.self] }
        set { self[AppEnvironmentKey.self] = newValue }
    }
}

// MARK: - toast

struct ToastView: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.footnote)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .glassEffect(.regular, in: Capsule())
            .transition(.move(edge: .top).combined(with: .opacity))
    }
}

// MARK: - banners (S12, S13; S6 已迁到 §3.8 的玻璃胶囊)

struct QuotaBanner: View {
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.yellow)
            Text("免费额度已用尽 · 仍可查看与删除")
                .font(.footnote.weight(.medium))
            Spacer()
        }
        .padding(12)
        .background(Color.yellow.opacity(0.14), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct FrozenBanner: View {
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "snowflake")
                .foregroundStyle(.cyan)
            Text("保险库已冻结")
                .font(.footnote.weight(.medium))
            Spacer()
        }
        .padding(12)
        .background(Color.cyan.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
    }
}

// MARK: - sync accessory capsule (§3.8 tabViewBottomAccessory)

// §2.4 的工具栏圆点已迁到下面的玻璃胶囊（SyncDot 枚举仍在 ItemsStore 上）。

/// Tab 栏上方的玻璃小胶囊：同步中 / 失败 / 已同步三态（§3.8）。失败态点按
/// 展开列表顶部的失败详情（S6 语义从横幅迁过来，横幅位让给 S12/S13）。
struct SyncStatusAccessory: View {
    let app: AppModel

    /// 胶囊三态：offline 归入「失败」（网络不可达也是一次同步失败，S6 文案）。
    var capsuleState: SyncDot {
        switch app.items.syncDot {
        case .offline, .failed: return .failed
        case .syncing: return .syncing
        case .idle: return .idle
        }
    }

    var label: String {
        switch capsuleState {
        case .syncing: return "同步中"
        case .failed: return "同步失败"
        default: return "已同步"
        }
    }

    var icon: String {
        switch capsuleState {
        case .syncing: return "arrow.triangle.2.circlepath"
        case .failed: return "wifi.exclamationmark"
        default: return "checkmark.circle.fill"
        }
    }

    var tint: Color {
        switch capsuleState {
        case .syncing: return .orange
        case .failed: return .red
        default: return .green
        }
    }

    var body: some View {
        Button {
            guard capsuleState == .failed, app.items.syncFailure != nil else { return }
            app.selectedTab = 0                  // 条目 Tab（tag 0）
            app.items.showFailureDetail = true   // 列表顶部展开失败详情
        } label: {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .foregroundStyle(tint)
                    .symbolEffect(.pulse, isActive: capsuleState == .syncing)
                Text(label)
                    .font(.footnote.weight(.medium))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .buttonStyle(.plain)
        .glassEffect(.regular, in: Capsule())
        .accessibilityLabel("同步状态：\(label)")
        .accessibilityHint(capsuleState == .failed ? "点按查看失败详情" : "")
    }
}

// MARK: - type badge (§2.4)

struct TypeBadge: View {
    let type: String

    var body: some View {
        Text(Format.typeBadge(type))
            .font(.caption2.weight(.semibold))
            .monospaced()
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Color.secondary.opacity(0.14), in: RoundedRectangle(cornerRadius: 4))
            .foregroundStyle(.secondary)
    }
}

// MARK: - S14 expiry chip (§2.5, §2.9)

struct ExpiryChip: View {
    let mark: ExpiryMark

    var body: some View {
        switch mark {
        case .none:
            EmptyView()
        case .inSevenDays:
            chip(text: mark.text, color: .yellow)
        case .tomorrow:
            chip(text: mark.text, color: .red)
        }
    }

    func chip(text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.16), in: Capsule())
            .foregroundStyle(color)
    }
}

// MARK: - fingerprint (§2.8: 最显眼的元素, VoiceOver 按组朗读)

struct FingerprintText: View {
    let fingerprint: String
    var size: Font = .title3

    var body: some View {
        Text(fingerprint)
            .font(size.weight(.bold))
            .monospaced()
            .kerning(1)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(fingerprint.split(separator: "-").map { "组 \($0)" }.joined(separator: "，"))
    }
}

// MARK: - mask (§3.5, §3.6)

struct MaskText: View {
    let row: ItemRow

    var body: some View {
        Text("\(row.ref) · \(row.masked)")
            .font(.footnote)
            .monospaced()
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("\(row.ref)，\(Format.maskSpoken(masked: row.masked, type: row.type))")
    }
}

// MARK: - info rows

struct InfoRow: View {
    let label: String
    let value: String
    var mono = false

    var body: some View {
        HStack {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(mono ? .footnote.monospaced() : .body)
                .foregroundStyle(.primary)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .font(.callout)
    }
}

struct PolicySummaryRow: View {
    let row: ItemRow

    /// 策略摘要行（§2.5）：敏感级别 / 拒绝 shell / 参数检查 / 进程参数注入。
    var summary: String {
        var parts: [String] = []
        parts.append("标准")
        parts.append(row.policy.commandPolicy == "deny-shells" ? "拒绝 shell：开" : "拒绝 shell：关")
        parts.append(row.policy.allowedHosts.isEmpty
                     ? "参数检查：关"
                     : "参数检查：\(row.policy.allowedHosts.count) 个主机")
        parts.append(row.policy.allowArgv ? "进程参数注入：开" : "进程参数注入：关")
        return parts.joined(separator: " · ")
    }

    var body: some View {
        Text(summary)
            .font(.footnote)
            .foregroundStyle(.secondary)
    }
}

// MARK: - recovery code display (S9 — 故意不提供拷贝按钮, §3.4)

struct RecoveryCodeDisplay: View {
    let groups: [String]

    /// 恢复码分组框在特大字号下横向滚动成组，不缩字号（§3.6）。
    /// 分组框所在的横条是自绘浮层 → 一条 `glassEffect(.regular)` 胶囊
    /// （§3.8）；分组框本体只剩描边，标红/变绿的语义只属于回填输入框。
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            LazyHStack(spacing: 8) {
                ForEach(Array(groups.enumerated()), id: \.offset) { index, group in
                    Text(group)
                        .font(.system(size: 24, weight: .semibold, design: .monospaced))
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .overlay(RoundedRectangle(cornerRadius: 8)
                            .strokeBorder(Color.secondary.opacity(0.4)))
                        .accessibilityLabel("第 \(index + 1) 组，\(group)")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 4)
            .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 14))
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("恢复码，共 \(groups.count) 组")
    }
}

// MARK: - grouped backfill input (§2.2 校验抄写)

struct GroupBackfillInput: View {
    @Bindable var model: RecoveryBackfillModel
    @FocusState var focus: Int?

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(model.targetGroups.indices, id: \.self) { index in
                    groupField(index)
                }
            }
            .padding(.horizontal, 1)
        }
        .onAppear {
            focus = model.focusIndex
        }
        .onChange(of: model.focusIndex) { _, newValue in
            focus = newValue
        }
    }

    @ViewBuilder
    func groupField(_ index: Int) -> some View {
        let status = model.results[index]
        TextField("", text: Binding(
            get: { model.inputs[index] },
            set: { model.update(group: index, raw: $0) }))
            .font(.system(size: 24, weight: .semibold, design: .monospaced))
            .multilineTextAlignment(.center)
            .frame(width: 92)
            .padding(.vertical, 8)
            .background(color(for: status).opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8)
                .strokeBorder(color(for: status).opacity(status == nil ? 0.3 : 0.9)))
            .focused($focus, equals: index)
            .submitLabel(.next)
            .onSubmit {
                if index + 1 < model.targetGroups.count {
                    focus = index + 1
                }
            }
            .accessibilityLabel("第 \(index + 1) 组")
    }

    func color(for status: Bool?) -> Color {
        switch status {
        case .some(true): return .green
        case .some(false): return .red
        case .none: return .secondary
        }
    }
}

// MARK: - checklist (§2.10 进度页, §2.12 进度页)

struct StepChecklist: View {
    struct Item {
        let label: String
        let done: Bool
        let active: Bool
    }

    let items: [Item]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                HStack(spacing: 12) {
                    Image(systemName: item.done ? "checkmark.circle.fill"
                            : item.active ? "circle.dotted" : "circle")
                        .foregroundStyle(item.done ? .green : item.active ? Color.accentColor : .secondary)
                        .symbolEffect(.pulse, isActive: item.active)
                    Text(item.label)
                        .font(.body)
                        .foregroundStyle(item.done ? .primary : .secondary)
                }
            }
        }
    }
}

// MARK: - flow step bar (§2.2 步骤条)

struct FlowStepBar: View {
    let steps: [String]
    let currentIndex: Int

    var body: some View {
        HStack(spacing: 4) {
            ForEach(steps.indices, id: \.self) { i in
                RoundedRectangle(cornerRadius: 2)
                    .fill(i <= currentIndex ? Color.accentColor : Color.secondary.opacity(0.25))
                    .frame(height: 4)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("步骤 \(currentIndex + 1)，共 \(steps.count)：\(steps[currentIndex])")
    }
}

// MARK: - warning card (S11 红色警示卡, §2.8)

struct WarningCard: View {
    let title: String
    let body_: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.red)
            Text(body_)
                .font(.callout)
                .foregroundStyle(.primary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.red.opacity(0.4)))
    }
}
