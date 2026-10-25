// Recovery flows (docs/ios-ui.md §2.12 takeover, §2.13 local rebuild): the
// shared screen skeleton with the three §2.13 copy/step differences applied
// by mode.
import SwiftUI
import KeyrefCore

struct RecoveryFlowView: View {
    let app: AppModel
    let mode: RecoveryFlowModel.Mode
    @State private var model: RecoveryFlowModel?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Group {
            if let model {
                RecoveryFlowBody(app: app, model: model, onClose: {
                    dismiss()
                })
            } else {
                ProgressView()
            }
        }
        .onAppear {
            if model == nil {
                model = RecoveryFlowModel(backend: app.backend, haptics: app.haptics, mode: mode)
            }
        }
        .interactiveDismissDisabled(model?.commitStarted ?? false)
    }
}

struct RecoveryFlowBody: View {
    let app: AppModel
    @Bindable var model: RecoveryFlowModel
    let onClose: () -> Void

    var title: String {
        model.mode == .takeover ? "用恢复码接管保险库" : "本机恢复"
    }

    var body: some View {
        Group {
            switch model.phase {
            case .intro:
                introPage
            case .input:
                inputPage
            case .preparing:
                ProgressView("正在准备…")
            case .confirmCommit:
                if let prep = model.preparation {
                    confirmPage(prep)
                }
            case .running:
                progressPage
            case .done:
                donePage
            case .repairGuide:
                repairGuidePage
            case .failed(let message):
                failedPage(message: message)
            }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("关闭") { onClose() }
                    .disabled(model.commitStarted)  // 生效后只能继续（§2.12）
            }
        }
    }

    /// 说明页（§2.12 vs §2.13 差异一：文案）。
    var introPage: some View {
        VStack(alignment: .leading, spacing: 18) {
            if model.mode == .takeover {
                Text("输入恢复码后，这台手机会解开主密钥、成为唯一的 owner 设备，并把之前登记的所有设备——包括丢失的那台 iPhone 和全部 CLI——标记为撤销。如果旧手机还在手上且能正常解锁，Phase 1 没有更温和的迁移方式：接管就是迁移。")
                    .font(.callout)
            } else {
                Text("输入恢复码，在这台手机上重新包裹主密钥。其他设备不受影响，CLI 不需要重新配对。")
                    .font(.callout)
            }
            Spacer()
            Button {
                model.goToInput()
            } label: {
                Text("输入恢复码")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glassProminent)
        }
        .padding(24)
    }

    /// 输入页：与 2.2 回填同一套分组输入控件（粘贴自动归一）。
    var inputPage: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("恢复码")
                .font(.title3.weight(.semibold))
            TextField("XXXXX-XXXXX-…（支持整段粘贴）", text: $model.codeInput, axis: .vertical)
                .font(.body.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .lineLimit(3...5)
                .padding(10)
                .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            if let error = model.inputError {
                VStack(alignment: .leading, spacing: 4) {
                    Text(error)
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(.red)
                    if error.contains("找不到") {
                        Text("恢复码自带保险库地址。如果你是自托管，先在设置 → 服务器里改到你的 origin，再回来输入。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Spacer()
            Button {
                Task { await model.submitCode() }
            } label: {
                Text("下一步")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glassProminent)
            .disabled(model.codeInput.isEmpty)
        }
        .padding(24)
    }

    /// 第 4 步前的确认警报（仅接管）：「提交后，之前的所有设备立即失去同步，
    /// CLI 需要重新配对。」
    func confirmPage(_ prep: RecoveryPreparation) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
            Text("提交接管")
                .font(.title3.weight(.semibold))
            Text("提交后，之前的所有设备立即失去同步，CLI 需要重新配对。")
                .font(.callout)
            InfoRow(label: "将撤销的设备数", value: "\(prep.deviceCountToRevoke)")
            Spacer()
            HStack(spacing: 12) {
                Button("取消") { model.cancel() }
                    .frame(maxWidth: .infinity)
                    .buttonStyle(.glass)
                Button("提交接管") {
                    Task { await model.commit() }
                }
                .frame(maxWidth: .infinity)
                .buttonStyle(.glassProminent)
            }
        }
        .padding(24)
    }

    /// 进度页（清单逐项；§2.13 差异二：第 4 步是「更新本机在设备目录中的
    /// 登记」，第 5 步是「校验本地密文」而非全量下载）。
    var progressPage: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepChecklist(items: checklist)
            if case .rotateItems(let remaining) = model.currentStep, remaining > 0 {
                Text("轮换条目密钥，还剩 \(remaining) 条…")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(24)
    }

    var checklist: [StepChecklist.Item] {
        let takeover = model.mode == .takeover
        let reached: RecoveryStep? = model.currentStep
        func at(_ step: RecoveryStep) -> Bool {
            guard let reached else { return false }
            switch (step, reached) {
            case (.fetchMaterials, _), (.unwrapVMK, _), (.generateOwnerKeys, _),
                 (.signTranscript, _):
                return true  // preparing finished all of these before commit
            case (.download, .download), (.download, .rotateItems):
                return true
            case (.rotateItems, .rotateItems(let remaining)):
                return remaining == 0
            default:
                return false
            }
        }
        let labels: [(String, RecoveryStep)] = takeover ? [
            ("取回恢复材料", .fetchMaterials),
            ("解开主密钥", .unwrapVMK),
            ("生成这台手机的新隔区密钥", .generateOwnerKeys),
            ("签署接管誊本", .signTranscript),
            ("下载全部密文", .download),
            ("轮换条目密钥并重加密", .rotateItems(remaining: 0)),
        ] : [
            ("取回恢复材料", .fetchMaterials),
            ("解开主密钥", .unwrapVMK),
            ("生成这台手机的新隔区密钥", .generateOwnerKeys),
            ("更新本机在设备目录中的登记", .signTranscript),
            ("校验本地密文", .download),
        ]
        return labels.map { label, step in
            StepChecklist.Item(label: label, done: at(step),
                               active: reached?.label == label)
        }
    }

    /// 完成页：同一句底注（§9.5 要求恢复完成页写明）。
    var donePage: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 48))
                .foregroundStyle(.green)
            Text(model.mode == .takeover ? "保险库已恢复" : "本机已恢复")
                .font(.title2.weight(.semibold))
            if let summary = model.summary {
                Text("\(summary.itemCount) 条条目、\(summary.revokedDeviceCount) 台设备已被撤销")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text("恢复码没有变化，仍然是唯一的恢复凭证。手机和恢复码同时丢失＝数据无法恢复。")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                if model.mode == .takeover {
                    model.goToRepairGuide()
                } else {
                    finishToVault()
                }
            } label: {
                Text(model.mode == .takeover ? "重新配对 CLI" : "进入保险库")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glassProminent)
        }
        .padding(24)
    }

    /// 重新配对指引页（仅接管）：三步说明。
    var repairGuidePage: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("重新配对 CLI")
                .font(.title3.weight(.semibold))
            VStack(alignment: .leading, spacing: 14) {
                guideRow("1. 在每台 agent 机器上重新运行 keyref pair。")
                guideRow("2. 用这台手机扫终端上的二维码。")
                guideRow("3. 重新勾选要授予的条目——旧授权不会自动恢复。")
            }
            Spacer()
            Button {
                finishToVault()
            } label: {
                Text("扫码配对")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.glassProminent)
        }
        .padding(24)
    }

    func guideRow(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "number.circle")
                .foregroundStyle(.tint)
            Text(text).font(.callout)
        }
    }

    func failedPage(message: String) -> some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "exclamationmark.octagon.fill")
                .font(.system(size: 44))
                .foregroundStyle(.red)
            Text(message)
                .font(.callout)
                .multilineTextAlignment(.center)
            Spacer()
            Button(model.commitStarted ? "继续" : "重试") {
                if model.commitStarted {
                    Task { await model.commit() }
                } else {
                    model.goToInput()
                }
            }
            .buttonStyle(.glassProminent)
        }
        .padding(24)
    }

    func finishToVault() {
        Task {
            await app.vaultBecameReady(unlock: true)
            onClose()
        }
    }
}

extension RecoveryStep {
    var label: String {
        switch self {
        case .fetchMaterials: return "取回恢复材料"
        case .unwrapVMK: return "解开主密钥"
        case .generateOwnerKeys: return "生成这台手机的新隔区密钥"
        case .signTranscript: return "签署接管誊本"
        case .download: return "下载全部密文"
        case .rotateItems: return "轮换条目密钥并重加密"
        }
    }
}

/// 超额页出路「删除条目，降回限额内」：按密文大小排序的精简列表。
struct ItemsBySizeView: View {
    let app: AppModel

    var sorted: [ItemRow] {
        app.items.rows.sorted { $0.ciphertextBytes > $1.ciphertextBytes }
    }

    var body: some View {
        List(sorted) { row in
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(row.name)
                    Text(Format.bytes(Int64(row.ciphertextBytes)))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button(role: .destructive) {
                    Task { _ = await app.items.delete(itemID: row.id) }
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
            }
        }
        .navigationTitle("按密文大小排序")
        .navigationBarTitleDisplayMode(.inline)
        .scrollEdgeEffectStyle(.soft, for: [.top, .bottom])
    }
}
