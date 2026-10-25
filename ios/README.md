# ios

人用的管理端。Agent 不在这里运行；这里负责保管主密钥、编辑条目、配对 CLI、批准敏感的 `exec`。

设计见 [docs/design.md](../docs/design.md) 的「iOS 应用」和「密码学」两节。

- Swift + SwiftUI。最低系统按 iOS 17 规划（CryptoKit 的 HPKE 与 Swift 并发模型都比较完整）。
- 解锁用 Face ID / Touch ID（`LocalAuthentication`）。包裹 VMK 的协定密钥放在 Secure Enclave，曲线只能是 P-256。
- 另有一把 Secure Enclave 的 P-256 签名密钥，用来给条目密文和配对记录签名。
- 条目的创建、修改、删除、轮换只发生在这台（或以后的另一台）owner 设备上。CLI 不能改保险库。
- 界面文案用简体中文。`ref`、算法名、API 路径保持英文。
- 可以展示明文，但每次「显示」都要再走一次生物识别。不要把明文写进系统日志、崩溃报告或分析 SDK。
- 同步服务器默认是官方托管。设置里可以改成任意 HTTPS origin，用来连自托管。扫到的配对二维码若指向另一台服务器，先显示域名再请人确认。不要因为官方托管是自己人运营就少做端到端加密。

当前布局：

```
ios/
├── Package.swift            # KeyrefCore（密码学/协议/同步）+ KeyrefUI（全部界面）
├── Sources/KeyrefCore/      # UI-free 核心：加密、APIClient、SyncEngine、VaultFlows
├── Sources/KeyrefUI/        # SwiftUI 界面层（docs/ios-ui.md 的 17 屏）
├── Tests/                   # KeyrefCoreTests + KeyrefUITests（两套都跑模拟器与 macOS）
├── Keyref.xcodeproj         # App 壳（target "Keyref"，iOS 17+）
└── Keyref/                  # @main 入口与 Info.plist
```

构建：`xcodebuild -project Keyref.xcodeproj -scheme Keyref -destination 'platform=iOS Simulator,name=iPhone 17' build|test`。

界面规格见 [docs/ios-ui.md](../docs/ios-ui.md)（Phase 1 范围：四 Tab、创建/恢复/配对/撤销/审计/设置；审批收件箱与 Plus 内购在 Phase 2）。
