// Onboarding (docs/ios-ui.md §2.1 welcome, §2.2 create vault): the only
// entry point before a vault exists, and the five-step creation flow with
// the show-once recovery code and the full group backfill check.
import SwiftUI
import KeyrefCore

// MARK: - 2.1 welcome (S1)

struct WelcomeView: View {
    let app: AppModel
    @State private var showCreate = false
    @State private var showRecovery = false
    @State private var showJoin = false

    var body: some View {
        ZStack {
            KeyrefBackdrop()
            VStack(spacing: 0) {
                Spacer()
                BrandMark(size: 96)
                Text("keyref")
                    .font(.system(size: 40, weight: .bold, design: .monospaced))
                    .tracking(-1.5)
                    .foregroundStyle(KeyrefTheme.foreground)
                    .padding(.top, 20)
                Text("你的秘密保险库。agent 只拿引用，拿不到明文。")
                    .font(.callout)
                    .foregroundStyle(KeyrefTheme.muted)
                    .multilineTextAlignment(.center)
                    .padding(.top, 8)
                Spacer()
                VStack(spacing: 10) {
                    Button {
                        showCreate = true
                    } label: {
                        Text("创建保险库")
                    }
                    .buttonStyle(KeyrefPrimaryButtonStyle())
                    Button {
                        showRecovery = true
                    } label: {
                        Text("用恢复码恢复")
                    }
                    .buttonStyle(KeyrefSecondaryButtonStyle())
                    // 第三级用纯文字按钮：整页只有一级实心块，多的都是文字。
                    Button {
                        showJoin = true
                    } label: {
                        Text("加入已有保险库")
                    }
                    .buttonStyle(.plain)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(KeyrefTheme.foreground)
                }
                KeyrefBlock(padding: 13) {
                    HStack(alignment: .top, spacing: 9) {
                        Image(systemName: "lock.shield.fill")
                            .font(.caption)
                            .foregroundStyle(KeyrefTheme.accent)
                            .padding(.top, 1)
                        Text("主密钥只活在这台手机的安全隔区里。服务器只保存密文。没有账号，也没有客服重置。")
                            .font(.footnote)
                            .foregroundStyle(KeyrefTheme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.top, 20)
                .padding(.bottom, 18)
            }
            .padding(.horizontal, 28)
        }
        // §3.8：S1 欢迎页背景用 backgroundExtensionEffect 承接状态栏与底部。
        .backgroundExtensionEffect()
        .fullScreenCover(isPresented: $showCreate) {
            NavigationStack {
                CreateVaultFlowView(app: app)
            }
        }
        .fullScreenCover(isPresented: $showRecovery) {
            NavigationStack {
                RecoveryFlowView(app: app, mode: .takeover)
            }
        }
        // Phase 2（§9.4 path 2）：旧手机还在时的第二台 iPhone 在线配对。
        .fullScreenCover(isPresented: $showJoin) {
            NavigationStack {
                SecondDeviceFlowView(app: app, role: .newPhone)
            }
        }
    }
}

// MARK: - 2.2 create vault

struct CreateVaultFlowView: View {
    @State private var model: CreateVaultModel
    @Environment(\.appModel) private var app
    @Environment(\.dismiss) private var dismiss

    init(app: AppModel) {
        _model = State(initialValue: CreateVaultModel(backend: app.backend, haptics: app.haptics))
    }

    static let steps = ["前置检查", "生成密钥", "抄写恢复码", "校验抄写", "完成"]

    var currentIndex: Int {
        switch model.step {
        case .prerequisites: return 0
        case .generating: return 1
        case .recoveryCode: return 2
        case .backfill: return 3
        case .done: return 4
        }
    }

    var body: some View {
        ZStack {
            KeyrefBackdrop()
            VStack(spacing: 0) {
                FlowStepBar(steps: Self.steps, currentIndex: currentIndex)
                    .padding(.horizontal, 24)
                    .padding(.top, 10)
                    .padding(.bottom, 2)
                switch model.step {
                case .prerequisites:
                    PrerequisitesPage(model: model)
                case .generating:
                    GeneratingPage(model: model)
                case .recoveryCode:
                    RecoveryCodeShowOncePage(model: model)
                case .backfill:
                    if let backfill = model.backfill {
                        RecoveryBackfillPage(model: model, backfill: backfill)
                    }
                case .done:
                    CreateDonePage(model: model) {
                        Task { await app?.vaultBecameReady(unlock: true) }
                        dismiss()
                    }
                }
            }
        }
        .navigationTitle("创建保险库")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("取消") { dismiss() }
            }
        }
        .onAppear { model.loadPrerequisites() }
    }
}

/// 前置检查：设备密码已设置、Face ID 已录入，缺一不可（§9.3）。
struct PrerequisitesPage: View {
    @Bindable var model: CreateVaultModel

    var body: some View {
        VStack(spacing: 18) {
            // 一块发丝线清单：行与行之间一条线，没有各自的卡片底。
            KeyrefBlock(padding: 0) {
                VStack(spacing: 0) {
                    ForEach(Array(model.prerequisites.enumerated()), id: \.offset) { index, item in
                        if index > 0 {
                            Divider().overlay(KeyrefTheme.hairline)
                        }
                        HStack(spacing: 12) {
                            IconGlyph(systemName: item.satisfied ? "checkmark" : "exclamationmark",
                                      tint: item.satisfied ? KeyrefTheme.success : KeyrefTheme.danger,
                                      size: 18)
                            Text(item.title)
                                .font(.callout.weight(.medium))
                            Spacer()
                            StatusText(text: item.satisfied ? "就绪" : "缺少",
                                       tint: item.satisfied ? KeyrefTheme.success : KeyrefTheme.danger,
                                       showDot: true)
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 12)
                    }
                }
            }
            if !model.missingPrerequisites.isEmpty {
                Label {
                    Text("先在系统设置里开启设备密码 / Face ID，再回来创建。")
                } icon: {
                    Image(systemName: "gear")
                }
                .font(.callout)
                .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await model.startGeneration() }
            } label: {
                Text("继续")
            }
            .buttonStyle(KeyrefPrimaryButtonStyle())
            .disabled(!model.canProceedFromPrerequisites || model.generating)
        }
        .padding(24)
    }
}

/// 生成页：逐行列出要创建的东西（§8.4）；系统会在生成隔区密钥时自行要求认证。
struct GeneratingPage: View {
    let model: CreateVaultModel

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 14) {
                BrandMark(size: 60)
                VStack(alignment: .leading, spacing: 4) {
                    Text("正在生成安全隔区密钥…")
                        .font(.headline)
                    Text("密钥只在这台手机上生成")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.top, 8)
            KeyrefBlock(padding: 0) {
                VStack(alignment: .leading, spacing: 0) {
                    generationRow("安全隔区协定密钥与签名密钥")
                    Divider().overlay(KeyrefTheme.hairline)
                    generationRow("主密钥 VMK")
                    Divider().overlay(KeyrefTheme.hairline)
                    generationRow("恢复码")
                    Divider().overlay(KeyrefTheme.hairline)
                    generationRow("续期密钥对")
                }
            }
            ProgressView()
                .controlSize(.large)
                .tint(KeyrefTheme.tint)
                .frame(maxWidth: .infinity)
                .padding(.top, 8)
            Spacer()
        }
        .padding(24)
    }

    func generationRow(_ label: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "circle.dotted")
                .foregroundStyle(KeyrefTheme.foreground)
                .symbolEffect(.pulse)
            Text(label)
                .font(.callout)
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 13)
    }
}

/// 恢复码展示页（S9）：只显示一次，故意不提供拷贝按钮（§3.4）。
struct RecoveryCodeShowOncePage: View {
    @Bindable var model: CreateVaultModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("抄下恢复码")
                    .font(.title2.weight(.semibold))
                Text("这是它唯一一次出现。恢复码等于全部数据：keyref 不保存它，设置里也没有再次查看的入口。抄在纸上，或放进另一个你信任的保险库。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                KeyrefNotice(systemName: "exclamationmark.triangle.fill",
                             tint: KeyrefTheme.warning,
                             text: "手机和恢复码同时丢失＝数据永久丢失。",
                             emphasis: true)
                if let groups = model.draft?.recoveryGroups {
                    RecoveryCodeDisplay(groups: groups)
                }
                Text("回填校验的对象是「你抄下来的那份副本」，不是「你是否动手抄了」。抄错一位等于将来恢复必败。它防不了拍照——它不防「没抄」，只防「抄错」。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button {
                    model.beginBackfill()
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
}

/// 校验抄写页（分组回填，全量）：自动聚焦、写满自动跳组、支持整段粘贴、
/// Crockford 归一化；填错的组实时标红。
struct RecoveryBackfillPage: View {
    @Bindable var model: CreateVaultModel
    @Bindable var backfill: RecoveryBackfillModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("对照校验")
                    .font(.title2.weight(.semibold))
                Text("按顺序重输全部分组。支持整段粘贴（自动去掉空格与连字符、按组拆分）。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                GroupBackfillInput(model: backfill)
                if let mismatch = backfill.firstMismatchIndex {
                    Text(backfill.errorMessage ?? "")
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(KeyrefTheme.danger)
                        .accessibilityLabel("第 \(mismatch + 1) 组不一致。\(backfill.errorMessage ?? "")")
                }
                if backfill.allMatched {
                    Label("全部匹配。", systemImage: "checkmark.circle.fill")
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(KeyrefTheme.success)
                }
                Text("它防不了拍照——它不防「没抄」，只防「抄错」。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button {
                    model.finishBackfill()
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

/// 完成页：标题 + 同步状态 + 底注（逐字）+「进入保险库」。
struct CreateDonePage: View {
    @Bindable var model: CreateVaultModel
    let onEnter: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            ResultHero(systemName: "checkmark.seal.fill",
                       tint: KeyrefTheme.success,
                       title: "保险库已创建")
            if model.uploadFailed {
                VStack(spacing: 12) {
                    Text("保险库已在本机创建，但还没同步到服务器。")
                        .font(.callout)
                        .foregroundStyle(KeyrefTheme.warning)
                        .multilineTextAlignment(.center)
                    Button("重试上传") {
                        Task { await model.upload() }
                    }
                    .buttonStyle(KeyrefSecondaryButtonStyle())
                }
                .padding(.top, 18)
            } else if model.uploaded {
                StatusText(text: "已同步", tint: KeyrefTheme.success, showDot: true)
                    .padding(.top, 18)
            } else {
                HStack(spacing: 8) {
                    ProgressView()
                        .controlSize(.small)
                    Text("上传中")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 18)
            }
            Spacer()
            Text("恢复码是唯一的恢复方式。keyref 无法帮你重置。")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                onEnter()
            } label: {
                Text("进入保险库")
            }
            .buttonStyle(KeyrefPrimaryButtonStyle())
            .padding(.top, 12)
        }
        .padding(24)
        .task {
            await model.upload()
        }
    }
}
