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
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "key.fill")
                .font(.system(size: 48))
                .foregroundStyle(.tint)
            Text("keyref")
                .font(.largeTitle.weight(.bold))
            Text("你的秘密保险库。agent 只拿引用，拿不到明文。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            Button {
                showCreate = true
            } label: {
                Text("创建保险库")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glassProminent)
            Button {
                showRecovery = true
            } label: {
                Text("用恢复码恢复")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glass)
            Button {
                showJoin = true
            } label: {
                Text("加入已有保险库")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glass)
            Text("主密钥只活在这台手机的安全隔区里。服务器只保存密文。没有账号，也没有客服重置。")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.bottom, 16)
        }
        .padding(.horizontal, 28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.keyrefBackground)
        // §3.8：背景向上、向下延伸到状态栏与底部栏之下（S1 欢迎页）。
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
        VStack(spacing: 0) {
            FlowStepBar(steps: Self.steps, currentIndex: currentIndex)
                .padding(.horizontal, 24)
                .padding(.top, 8)
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
            ForEach(model.prerequisites) { item in
                HStack(spacing: 12) {
                    Image(systemName: item.satisfied ? "checkmark.circle.fill" : "xmark.circle")
                        .foregroundStyle(item.satisfied ? .green : .red)
                    Text(item.title)
                    Spacer()
                }
                .padding(16)
                .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
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
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glassProminent)
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
            Text("正在生成安全隔区密钥…")
                .font(.headline)
            VStack(alignment: .leading, spacing: 12) {
                generationRow("安全隔区协定密钥与签名密钥")
                generationRow("主密钥 VMK")
                generationRow("恢复码")
                generationRow("续期密钥对")
            }
            .padding(16)
            .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
            ProgressView()
            Spacer()
        }
        .padding(24)
    }

    func generationRow(_ label: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "circle.dotted")
                .foregroundStyle(.tint)
                .symbolEffect(.pulse)
            Text(label)
                .font(.callout)
        }
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
                Label("手机和恢复码同时丢失＝数据永久丢失。", systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(.orange)
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
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
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(.glassProminent)
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
                        .foregroundStyle(.red)
                        .accessibilityLabel("第 \(mismatch + 1) 组不一致。\(backfill.errorMessage ?? "")")
                }
                if backfill.allMatched {
                    Text("全部匹配。")
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(.green)
                }
                Text("它防不了拍照——它不防「没抄」，只防「抄错」。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button {
                    model.finishBackfill()
                } label: {
                    Text("完成")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(.glassProminent)
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
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 48))
                .foregroundStyle(.green)
            Text("保险库已创建")
                .font(.title2.weight(.semibold))
            if model.uploadFailed {
                VStack(spacing: 12) {
                    Text("保险库已在本机创建，但还没同步到服务器。")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.center)
                    Button("重试上传") {
                        Task { await model.upload() }
                    }
                    .buttonStyle(.glass)
                }
            } else if model.uploaded {
                Text("已同步")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                Text("上传中")
                    .font(.callout)
                    .foregroundStyle(.secondary)
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
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glassProminent)
        }
        .padding(24)
        .task {
            await model.upload()
        }
    }
}
