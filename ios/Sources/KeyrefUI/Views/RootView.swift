// The app shell (docs/ios-ui.md §1): four tabs, the self-drawn lock overlay
// (the LA dialog can be cancelled — the content layer never shows through,
// §3.1) and the full-screen onboarding flow when no vault exists (S1).
import SwiftUI
import KeyrefCore

public struct RootView: View {
    @State private var app: AppModel
    @Environment(\.scenePhase) private var scenePhase

    public init(app: AppModel) {
        _app = State(initialValue: app)
    }

    public var body: some View {
        ZStack {
            if app.phase == .onboarding {
                WelcomeView(app: app)
            } else {
                MainTabView(app: app)
                    .accessibilityHidden(app.phase == .locked)
            }
            if app.phase == .locked {
                LockScreenView(app: app)
                    .transition(.opacity)
                    .zIndex(10)
            }
            if app.showRecoveryFromLock, app.phase == .locked {
                NavigationStack {
                    RecoveryFlowView(app: app, mode: .localRebuild)
                }
                .transition(.opacity)
                .zIndex(20)
            }
        }
        .animation(.easeOut(duration: 0.18), value: app.phase)
        // 系统控件的 accent 跟着前景色走：链接、开关、Tab 选中都是近黑
        // （浅色）/近白（深色），不染彩色。琥珀只留在自绘的信号位上——品牌
        // 标记里的钥匙、步骤条上的当前步、待审批角标的小方点。
        .tint(KeyrefTheme.tint)
        .environment(\.appModel, app)
        .task {
            await app.boot()
        }
        .onChange(of: scenePhase) { _, newPhase in
            app.handleScenePhase(newPhase)
        }
    }
}

struct MainTabView: View {
    @Bindable var app: AppModel

    var body: some View {
        TabView(selection: $app.selectedTab) {
            ItemListView(app: app)
                .tabItem {
                    Label("条目", systemImage: "key.fill")
                }
                .tag(0)
            DeviceListView(app: app)
                .tabItem {
                    // 待审批角标（Phase 2, §8.3）：待审批数挂在设备 Tab 上。
                    Label("设备", systemImage: "laptopcomputer.and.iphone")
                        .badge(app.approvals.badgeCount)
                }
                .tag(1)
            AuditListView(app: app)
                .tabItem {
                    Label("审计", systemImage: "list.bullet.rectangle.fill")
                }
                .tag(2)
            SettingsView(app: app)
                .tabItem {
                    Label("设置", systemImage: "gearshape.fill")
                }
                .tag(3)
        }
        // §3.8：系统浮动玻璃 Tab 栏；同步状态是 Tab 栏上方的玻璃小胶囊
        // （同步中 / 失败 / 已同步），失败态点按展开列表顶部的失败详情。
        // API 仅 iOS（macOS 无此修饰符），包级 macOS 编译走 #if 隔离。
        #if os(iOS)
        .tabViewBottomAccessory {
            SyncStatusAccessory(app: app)
        }
        #endif
    }
}

// MARK: - 2.3 lock screen (S2, S3, S4)

struct LockScreenView: View {
    let app: AppModel

    var body: some View {
        ZStack {
            KeyrefBackdrop()
            switch app.lockDisplay {
            case .waiting:
                waitingFace
            case .biometricFailed(let attempts):
                waitingFace
                    .overlay(alignment: .bottom) { failureLine(attempts: attempts) }
            case .wrapInvalid:
                WrapInvalidFace(app: app)
            }
        }
    }

    /// S2 正常态：品牌门面、状态行（缓存的非敏感计数）、主按钮、底注。
    var waitingFace: some View {
        VStack(spacing: 0) {
            Spacer()
            BrandMark(size: 112)
            Text("keyref 已锁定")
                .font(.title2.weight(.semibold))
                .foregroundStyle(KeyrefTheme.foreground)
                .padding(.top, 22)
            HStack(spacing: 7) {
                Image(systemName: "tray.full.fill")
                    .font(.caption2)
                Text("\(app.backend.cachedItemCount) 条条目已就绪")
                    .monospacedDigit()
            }
            .font(.footnote)
            .foregroundStyle(KeyrefTheme.muted)
            .padding(.top, 10)
            Spacer()
            Button {
                Task { await app.attemptUnlock() }
            } label: {
                Label("使用 Face ID 解锁", systemImage: "faceid")
            }
            .buttonStyle(KeyrefPrimaryButtonStyle())
            Text("解锁只发生在这台手机上。")
                .font(.footnote)
                .foregroundStyle(KeyrefTheme.muted.opacity(0.8))
                .padding(.top, 16)
                .padding(.bottom, 28)
        }
        .padding(.horizontal, 24)
    }

    /// S3 失败态一：包裹完好，重试即可。连续多次失败后追加提示。
    /// 没有「用设备密码解锁保险库」按钮——放假按钮是撒谎（§2.3）。
    func failureLine(attempts: Int) -> some View {
        VStack(spacing: 8) {
            Text("Face ID 没有识别成功，再试一次即可。")
                .font(.footnote.weight(.medium))
                .foregroundStyle(KeyrefTheme.warning)
            if attempts >= 2 {
                Text("先解锁手机，正对摄像头再回到 keyref。")
                    .font(.footnote)
                    .foregroundStyle(KeyrefTheme.muted)
            }
        }
        .padding(.bottom, 100)
        .padding(.horizontal, 24)
    }
}

/// S4 失败态二：本机包裹已失效——重试在密码学上不可能，没有「再试一次」。
struct WrapInvalidFace: View {
    let app: AppModel
    @State private var showExplanation = false

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            ZStack {
                // 只有一圈发丝线，没有彩色圆底（没有图标瓦片底色）。
                Circle()
                    .strokeBorder(KeyrefTheme.danger.opacity(0.30), lineWidth: 1)
                    .frame(width: 98, height: 98)
                Image(systemName: "lock.slash.fill")
                    .font(.system(size: 40, weight: .semibold))
                    .foregroundStyle(KeyrefTheme.danger)
            }
            Text("本机包裹已失效")
                .font(.title2.weight(.semibold))
                .foregroundStyle(KeyrefTheme.foreground)
                .padding(.top, 20)
            Text("重录 Face ID、增删指纹或更改设备密码后，原来的加密包裹会永久作废——这是「新的生物特征集合不再被信任」的定义，不是故障。你的数据还在本机，没有被读取或删除。")
                .font(.callout)
                .foregroundStyle(KeyrefTheme.muted)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 28)
                .padding(.top, 10)
            Spacer()
            Button {
                app.showRecoveryFromLock = true  // → 2.13 本机重建流程
            } label: {
                Text("用恢复码在本机重建")
            }
            .buttonStyle(KeyrefPrimaryButtonStyle())
            Button {
                showExplanation = true
            } label: {
                Text("了解发生了什么")
            }
            .buttonStyle(KeyrefSecondaryButtonStyle())
            .padding(.top, 10)
            .padding(.bottom, 28)
        }
        .padding(.horizontal, 24)
        .sheet(isPresented: $showExplanation) {
            SecurityExplanationView()
        }
    }
}

/// Face ID 说明行（§2.14 安全分区）与 S4 的「了解发生了什么」共用。
struct SecurityExplanationView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ZStack {
                KeyrefBackdrop()
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        FaceIDExplanation()
                        Text("重录面容、增删指纹或更改设备密码会使本机包裹失效，需要用恢复码重建。")
                            .font(.body)
                        Text("这不是故障：隔区私钥被绑定在「当前生物特征集合」上。集合一变，旧的包裹就不再被信任——数据没有丢，用恢复码即可在本机重建（重新解 VMK、在新隔区重新包裹）。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                        Text("keyref 不提供「用设备密码解锁保险库」：.biometryCurrentSet 下的隔区私钥在密码学上不接受口令。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .padding(20)
                }
            }
            .navigationTitle("Face ID 与本机包裹")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
        }
    }
}

private struct FaceIDExplanation: View {
    var body: some View {
        HStack(spacing: 14) {
            IconGlyph(systemName: "faceid", tint: KeyrefTheme.foreground, size: 44)
            VStack(alignment: .leading, spacing: 3) {
                Text("隔区私钥绑定面容集合")
                    .font(.subheadline.weight(.semibold))
                Text("集合变化，旧包裹即失效")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.bottom, 4)
    }
}
