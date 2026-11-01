# ios

人用的管理端。Agent 不在这里运行；这里负责保管主密钥、编辑条目、配对 CLI、批准敏感的 `exec`。

设计见 [docs/design.md](../docs/design.md) 的「iOS 应用」和「密码学」两节。

- Swift + SwiftUI。最低系统 **iOS 26**（design v0.5 起随 Liquid Glass 提升；CryptoKit 原生 RFC 9180 HPKE，隔区私钥原生接入）。
- 解锁用 Face ID / Touch ID（`LocalAuthentication`）。包裹 VMK 的协定密钥放在 Secure Enclave，曲线只能是 P-256。
- 另有一把 Secure Enclave 的 P-256 签名密钥，用来给条目密文和配对记录签名。
- 条目的创建、修改、删除、轮换只发生在这台（或以后的另一台）owner 设备上。CLI 不能改保险库。
- 界面文案用简体中文。`ref`、算法名、API 路径保持英文。
- 可以展示明文，但每次「显示」都要再走一次生物识别。不要把明文写进系统日志、崩溃报告或分析 SDK。
- 同步服务器默认是官方托管。设置里可以改成任意 HTTPS origin，用来连自托管。扫到的配对二维码若指向另一台服务器，先显示域名再请人确认。不要因为官方托管是自己人运营就少做端到端加密。

当前布局：

```
ios/
├── Package.swift            # KeyrefCore（密码学/协议/同步/审批/双机配对）+ KeyrefUI（全部界面）
├── Sources/KeyrefCore/      # UI-free 核心：加密、APIClient、SyncEngine、VaultFlows、ApprovalFlows、OwnerPairing
├── Sources/KeyrefUI/        # SwiftUI 界面层（docs/ios-ui.md 的 17 屏，iOS 26 Liquid Glass）
├── Tests/                   # KeyrefCoreTests + KeyrefUITests（两套都跑模拟器与 macOS）
├── Keyref.xcodeproj         # App 壳（target "Keyref"，iOS 26+）
└── Keyref/                  # @main 入口与 Info.plist
```

构建：`scripts/dev/xcodebuild.sh -project Keyref.xcodeproj -scheme Keyref -destination 'platform=iOS Simulator,name=iPhone 17' build|test`。脚本把 `DEVELOPER_DIR` 指到 `/Applications/Xcode.app/Contents/Developer`——xcode-select 指向 CommandLineTools 的机器上直接跑 `xcodebuild` 会报 "tool 'xcodebuild' requires Xcode"；已把 xcode-select 切到完整 Xcode 的机器可以直接用 `xcodebuild` 本体。

### 视觉语言

界面共用一套设计系统，在 `Sources/KeyrefUI/DesignSystem/`：

- `Theme.swift` — 调色板。冷调编辑排版：整页近白（浅色）/ 近黑（深色），字近黑 /
  近白，只有一条发丝线的分层色，另有一块「明文层」实面（浅色下近黑、深色下近白）
  ——秘密在整页里是唯一的暗块，一眼能找到。琥珀是唯一的强调色，只作小面积信号
  （品牌标记里的钥匙、步骤条的当前步、待审批角标的小方点）。自适应色一律走
  `UIColor` 动态 provider，深浅两套是同一套逻辑（macOS 分支固定浅色——包在 macOS
  上只做编译与测试）。
- `DesignSystem.swift` — 通用件：页面底色、品牌标记、发丝线块、裸字形、字形圆圈、
  分区标签、状态文字、结果英雄图、两个按钮样式、列表底纹。

约定：**我们画的东西一律是平的**——没有渐变、光晕、阴影，没有卡片，没有图标瓦片
底色；分层只靠发丝线和留白。主按钮 `KeyrefPrimaryButtonStyle`（前景色实心块 +
页面色字）、次级 `KeyrefSecondaryButtonStyle`（同形描边）；其余控件（Toggle /
Picker / SecureField / searchable / 导航栏 / Tab 栏 / 底部配件）是 SwiftUI 原样，
accent 走 `.tint(KeyrefTheme.tint)`——跟着前景色走，不染彩色。

系统给了材质的（导航栏、Tab 栏、底部配件）不自绘模仿；真正浮在内容之上的自绘控件
（明文层的收起/拷贝按钮、同步胶囊、扫码页手电筒）用 `glassEffect` 而不是手画半透明
——见 docs/ios-ui.md §3.8。恢复码与 argv 原文不是浮层，它们是实心明文块（slab）。

`ref`、指纹、掩码、恢复码一律等宽字体；时间戳用紧凑写法 `2026-11-01 04:37`
（中文长日期在标签—值行里放不下，会被截成「2026年11月1日 04:…」）。

### 模拟器 UI 端到端（可选）

```sh
scripts/dev/ui-test.sh
```

起一个真实的 `keyref-server`（`KEYREF_ENFORCE_QUOTAS=1`，建库走 PoW），然后在 iPhone 17
模拟器里驱动真实 App：创建保险库（含恢复码回填）→ 添加条目 → 冷启动解锁 → 通过模拟器的
粘贴入口配对 CLI（测试进程扮演 CLI，并校验 pair/status 与授权）。需要本机 `go`；只在 macOS
上运行。

- 单元/流程测试仍走默认 scheme（`KeyrefCoreTests` + `KeyrefUITests`）；UI 自动化在独立的
  `KeyrefUIAutomation` scheme，不会拖慢默认门禁。
- DEBUG 构建用 `Info-Debug.plist` 放行 `127.0.0.1` 的明文回环（`NSAllowsLocalNetworking`），
  Release 继续用 `Info.plist`，不放开 ATS。UI 测试的启动参数（`-keyref-reset`、
  `-keyref-origin`、`-keyref-assume-prerequisites`、`-keyref-skip-push`、
  `-keyref-auto-auth`、`-keyref-initial-tab`）都编译在 `#if DEBUG` 里，Release 构建忽略。
- 模拟器的相机不可用，配对走 `NoCameraView` 的粘贴入口；iOS 26/27 的浮动玻璃 Tab 栏在
  XCUITest 下不接受点击，测试用 `-keyref-initial-tab` 冷启动到目标 Tab。

界面规格见 [docs/ios-ui.md](../docs/ios-ui.md)。已实现：四 Tab、创建/恢复/接管/配对/撤销/审计/设置、审批收件箱（前台轮询 + Face ID 批准）、allowCommands/allowedHosts 精细编辑、第二台 iPhone 在线配对。推送（APNs）与 Plus 内购需要 Apple 开发者凭据，另行接入。
