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
