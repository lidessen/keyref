// v0.7 (design §6.6, §6.7, §8.4): settings screens for the iCloud
// whole-file replica of local-only items and the periodic item-key
// rotation ritual. Both are plain wrappers over the backend seam; all
// cryptography lives in KeyrefCore.
import SwiftUI

/// iCloud 副本（§6.7）：仅本机条目的整文件加密快照。开关 + 当前状态 +
/// 手动上传。CloudKit 不可用时显示「副本不可用」与原因，绝不阻塞本地功能。
struct CloudBackupView: View {
    let app: AppModel
    @Bindable var settings: SettingsStore
    @State private var status: CloudBackupStatus?
    @State private var uploading = false

    init(app: AppModel) {
        self.app = app
        _settings = Bindable(wrappedValue: app.settings)
    }

    var body: some View {
        Form {
            Section {
                Toggle("iCloud 副本", isOn: Binding(
                    get: { settings.cloudBackupOn },
                    set: { newValue in
                        settings.cloudBackupOn = newValue
                        // 开关必须真的控制上传（§6.7）：只写偏好不调 backend
                        // 时，关掉后照样上传、状态仍报 ready。
                        app.backend.setCloudBackupEnabled(newValue)
                        Task { await refresh() }
                    }))
            } header: {
                Text("仅本机条目的副本")
            } footer: {
                Text("把仅本机条目的加密快照存到你的 iCloud（一个整文件，内容全部是密文，Apple 看不到内容）。手机丢失时，恢复码 + iCloud = 全部找回。")
            }

            Section {
                switch status ?? .disabled {
                case .disabled:
                    Label("已关闭。仅本机条目目前只存在这台手机上。", systemImage: "icloud.slash")
                        .foregroundStyle(.secondary)
                case .noVault:
                    Label("还没有保险库。", systemImage: "exclamationmark.circle")
                        .foregroundStyle(.secondary)
                case .unavailable(let reason):
                    Label("副本不可用：\(reason)", systemImage: "exclamationmark.icloud")
                        .foregroundStyle(.secondary)
                case .ready(let itemCount, let snapshotRevision):
                    LabeledContent("仅本机条目", value: "\(itemCount) 条")
                    LabeledContent("副本版本", value: "\(snapshotRevision)")
                    Button {
                        uploading = true
                        Task {
                            await app.backend.uploadSnapshotIfDirty()
                            await refresh()
                            uploading = false
                        }
                    } label: {
                        if uploading {
                            ProgressView()
                        } else {
                            Text("立即上传副本")
                        }
                    }
                    .disabled(uploading)
                }
            } header: {
                Text("状态")
            }
        }
        .navigationTitle("iCloud 副本")
        .keyrefListSurface()
        .task { await refresh() }
    }

    private func refresh() async {
        status = await app.backend.cloudBackupStatus()
    }
}

/// 密钥轮换（§8.4 定期轮换）：为全部同步条目生成新 item key、重新包裹、
/// 重加密，逐条原子提交；仅本机条目只轮换本地包裹。90 天周期提醒。
struct ItemKeyRotationView: View {
    let app: AppModel
    @Bindable var settings: SettingsStore
    @State private var running = false
    @State private var progress: RotationProgress?
    @State private var summary: RotationSummary?
    @State private var errorMessage: String?

    init(app: AppModel) {
        self.app = app
        _settings = Bindable(wrappedValue: app.settings)
    }

    var body: some View {
        Form {
            Section {
                Toggle("每 90 天提醒", isOn: $settings.rotationReminderOn)
            } header: {
                Text("周期")
            } footer: {
                Text("轮换防的是密钥长期不换的疲劳，不是过期：服务器密文永不因超时失效（§10.5）。")
            }

            Section {
                if let progress {
                    LabeledContent("进度", value: "\(progress.rotated)/\(progress.total)")
                    ProgressView(value: progress.total > 0 ? Double(progress.rotated) / Double(progress.total) : 0)
                }
                if let summary {
                    LabeledContent("已轮换", value: "\(summary.rotatedCount) 条")
                    if summary.failedCount > 0 {
                        Label("\(summary.failedCount) 条失败，可重试（逐条自洽）。", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(KeyrefTheme.warning)
                    }
                }
                Button {
                    runRotation()
                } label: {
                    if running {
                        ProgressView()
                    } else {
                        Text("立即轮换全部同步条目")
                    }
                }
                .disabled(running)
            } header: {
                Text("手动轮换")
            } footer: {
                Text("逐条原子完成：新密钥落库的同时旧包裹被覆盖，没有中间失效窗口。仅本机条目只轮换本地包裹。")
            }

            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "xmark.octagon")
                        .foregroundStyle(KeyrefTheme.danger)
                }
            }
        }
        .navigationTitle("轮换条目密钥")
        .keyrefListSurface()
    }

    private func runRotation() {
        running = true
        summary = nil
        errorMessage = nil
        Task {
            do {
                let s = try await app.backend.rotateAllItems { p in
                    await MainActor.run { progress = p }
                }
                await MainActor.run {
                    summary = s
                    running = false
                    if s.failedCount == 0 {
                        settings.markRotationCompleted()   // 90 天提醒的基准（§8.4）
                        settings.toast = "已轮换 \(s.rotatedCount) 条"
                    } else {
                        settings.toast = "已轮换 \(s.rotatedCount) 条，\(s.failedCount) 条失败"
                    }
                }
            } catch {
                await MainActor.run {
                    errorMessage = "轮换失败：\(error.localizedDescription)"
                    running = false
                }
            }
        }
    }
}
