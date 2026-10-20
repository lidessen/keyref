# ios

人用的管理端。**尚未实现。** Agent 不在这里运行；这里负责保管主密钥、编辑条目、配对 CLI、批准敏感的 `exec`。

设计见 [docs/design.md](../docs/design.md) 的「iOS 应用」和「密码学」两节。

- Swift + SwiftUI。最低系统按 iOS 17 规划（CryptoKit 的 HPKE 与 Swift 并发模型都比较完整）。
- 解锁用 Face ID / Touch ID（`LocalAuthentication`）。包裹 VMK 的协定密钥放在 Secure Enclave，曲线只能是 P-256。
- 另有一把 Secure Enclave 的 P-256 签名密钥，用来给条目密文和配对记录签名。
- 条目的创建、修改、删除、轮换只发生在这台（或以后的另一台）owner 设备上。CLI 不能改保险库。
- 界面文案用简体中文。`ref`、算法名、API 路径保持英文。
- 可以展示明文，但每次「显示」都要再走一次生物识别。不要把明文写进系统日志、崩溃报告或分析 SDK。

建议的后续布局：

```
ios/
└── Keyref/
    ├── Keyref.xcodeproj
    └── Keyref/
        ├── App/
        ├── Vault/
        ├── Crypto/
        └── Pairing/
```

Phase 0 可以先做成本地保险库：没有服务器也能创建条目、解锁、生成恢复密钥。同步和扫码配对从 Phase 1 开始。
