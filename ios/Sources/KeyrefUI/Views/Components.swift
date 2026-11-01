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
        HStack(spacing: 8) {
            Image(systemName: "checkmark.circle.fill")
                .font(.caption)
                .foregroundStyle(KeyrefTheme.success)
            Text(text)
                .font(.footnote.weight(.medium))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .glassEffect(.regular, in: Capsule())
        .transition(.move(edge: .top).combined(with: .opacity))
    }
}

// MARK: - banners (S12, S13; S6 已迁到 §3.8 的玻璃胶囊)

/// 状态横幅：一条发丝线上下夹住的一行字 + 一个裸图标。没有填充的圆角
/// 卡片——整页只靠发丝线分层（§3.8）。
struct QuotaBanner: View {
    var body: some View {
        KeyrefBlock {
            HStack(spacing: 10) {
                IconGlyph(systemName: "exclamationmark.triangle.fill",
                          tint: KeyrefTheme.warning, size: 18)
                Text("免费额度已用尽 · 仍可查看与删除")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(KeyrefTheme.foreground)
                Spacer(minLength: 0)
            }
        }
    }
}

struct FrozenBanner: View {
    var body: some View {
        KeyrefBlock {
            HStack(spacing: 10) {
                IconGlyph(systemName: "snowflake", tint: KeyrefTheme.info, size: 18)
                Text("保险库已冻结")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(KeyrefTheme.foreground)
                Spacer(minLength: 0)
            }
        }
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
        case .syncing: return KeyrefTheme.warning
        case .failed: return KeyrefTheme.danger
        default: return KeyrefTheme.success
        }
    }

    var body: some View {
        // 底部配件区会给出整条宽度；胶囊本身要收住自己的宽度，居中浮着，
        // 否则玻璃会拉成一条横贯屏幕的带子。
        HStack(spacing: 0) {
            Spacer(minLength: 0)
            capsule
            Spacer(minLength: 0)
        }
    }

    private var capsule: some View {
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
            .fixedSize(horizontal: true, vertical: false)
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

/// 类型徽标：等宽小字，不带底色。类型由旁边的图形区分，徽标只把它写成
/// 文字（§2.4）。
struct TypeBadge: View {
    let type: String

    var body: some View {
        Text(Format.typeBadge(type))
            .font(.caption2.weight(.semibold))
            .monospaced()
            .foregroundStyle(KeyrefTheme.muted)
    }
}

// MARK: - S14 expiry chip (§2.5, §2.9)

/// 到期标记：一行彩色小字，不再是彩色胶囊。
struct ExpiryChip: View {
    let mark: ExpiryMark

    var body: some View {
        switch mark {
        case .none:
            EmptyView()
        case .inSevenDays:
            chip(text: mark.text, color: KeyrefTheme.warning)
        case .tomorrow:
            chip(text: mark.text, color: KeyrefTheme.danger)
        }
    }

    func chip(text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .monospacedDigit()
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
        HStack(spacing: 6) {
            Text(row.ref)
                .foregroundStyle(KeyrefTheme.foreground)
            Text("·")
                .foregroundStyle(.tertiary)
            Text(row.masked)
                .foregroundStyle(.secondary)
        }
        .font(.caption.monospaced())
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
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .foregroundStyle(.secondary)
                .layoutPriority(1)
            Spacer(minLength: 8)
            // 右边一列要能换行（时间戳比标签长），否则会被截成「04:…」。
            Text(value)
                .font(mono ? .footnote.monospaced() : .body)
                .foregroundStyle(.primary)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .trailing)
                .fixedSize(horizontal: false, vertical: true)
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
    /// 恢复码是整页里唯一的暗块（明文层）：实心 slab + 等宽字，不是玻璃，
    /// 也不是半透明。手绘半透明是 §3.8 明令禁止的「假玻璃」。
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            LazyHStack(spacing: 8) {
                ForEach(Array(groups.enumerated()), id: \.offset) { index, group in
                    Text(group)
                        .font(.system(size: 24, weight: .semibold, design: .monospaced))
                        .foregroundStyle(KeyrefTheme.onSlab)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 11)
                        .overlay(
                            RoundedRectangle(cornerRadius: 9, style: .continuous)
                                .strokeBorder(KeyrefTheme.onSlab.opacity(0.35), lineWidth: 1)
                        )
                        .accessibilityLabel("第 \(index + 1) 组，\(group)")
                }
            }
            .padding(12)
        }
        .background(KeyrefTheme.slab,
                    in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("恢复码，共 \(groups.count) 组")
        // The full code in one value lets VoiceOver read it without
        // horizontal scrolling and gives UI tests a deterministic source
        // (the lazy horizontal stack only materializes visible groups).
        .accessibilityValue(groups.joined(separator: " "))
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
            .padding(.vertical, 9)
            .background(KeyrefTheme.surface,
                        in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(color(for: status).opacity(status == nil ? 0.30 : 0.9),
                                  lineWidth: status == nil ? 1 : 1.5)
            )
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
        VStack(alignment: .leading, spacing: 12) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                HStack(spacing: 12) {
                    // 裸字形：不做彩色圆底（没有图标瓦片底色）。
                    Image(systemName: item.done ? "checkmark"
                            : item.active ? "circle.dotted" : "circle")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(item.done ? KeyrefTheme.success
                                         : item.active ? KeyrefTheme.foreground : KeyrefTheme.muted)
                        .frame(width: 20)
                        .symbolEffect(.pulse, isActive: item.active)
                    Text(item.label)
                        .font(.callout)
                        .foregroundStyle(item.done ? .primary : .secondary)
                    Spacer(minLength: 0)
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
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 4) {
                ForEach(steps.indices, id: \.self) { i in
                    Capsule()
                        .fill(i < currentIndex ? KeyrefTheme.accent.opacity(0.35)
                              : i == currentIndex ? KeyrefTheme.accent
                              : KeyrefTheme.hairline)
                        .frame(height: 4)
                }
            }
            HStack(alignment: .firstTextBaseline) {
                Text("步骤 \(currentIndex + 1)/\(steps.count)")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(KeyrefTheme.muted)
                Spacer()
                Text(steps[currentIndex])
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("步骤 \(currentIndex + 1)，共 \(steps.count)：\(steps[currentIndex])")
    }
}

// MARK: - warning card (S11 红色警示卡, §2.8)

/// 警示卡（S11）：发丝线上下夹住的一行图标 + 标题 + 正文。红色只在标题
/// 和图标上出现——没有红色底块。
struct WarningCard: View {
    let title: String
    let body_: String

    var body: some View {
        KeyrefBlock {
            HStack(alignment: .top, spacing: 10) {
                IconGlyph(systemName: "exclamationmark.triangle.fill",
                          tint: KeyrefTheme.danger, size: 18)
                VStack(alignment: .leading, spacing: 5) {
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(KeyrefTheme.danger)
                    Text(body_)
                        .font(.callout)
                        .foregroundStyle(KeyrefTheme.foreground)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}
