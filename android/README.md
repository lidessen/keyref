# keyref source（安卓验证码采集端）

design.md v0.8 §14 的 `kind = source` 设备：读取本机短信、按本机过滤规则筛出
验证码、在**收到时即加密**（信封直封 active owner + 有效委托期内的决策器，
§14.3）、经 WorkManager 队列补传到 keyref 服务器。只上传、永不读取——
它连条目密钥都没有（§14.2）。

## 构建

1. Android Studio（自带 JDK/SDK）`File → Open` 打开本目录，等 Gradle 同步。
2. Run 到测试机，或 `Build → Build APK(s)` 生成 APK 侧载。

本机（macOS 开发机）没有 Android 构建环境，这批代码未经编译——同步或编译
报错直接贴给维护者即可。

## 使用

1. 安装后**打开一次 App**（系统不向从未启动的 App 投递广播）。
2. 授权短信权限、加入电池优化白名单。
3. 填服务器地址 → 「生成配对二维码」→ 用已配对的 iOS keyref App 扫码
   （二维码带 `t=source`，§9.1 v1.2）。确认页会写明「只能上传短信」。
4. 添加发信号码白名单 → 开启采集。

采集规则（design §14.2）：发信号码命中白名单 **且** 正文含 4–8 位数字码形。
白名单为空时什么都不采集。规则只存本机——source 解不开任何密文，规则没有
可加密同步的去处。

## 实现注记

- **HPKE 互操作面**：`crypto/Envelope.kt` 隔离了 BouncyCastle 的
  RFC 9180 实现（DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM）。它必须与
  `proto/crypto`（circl）逐字节互通——design §9.2 的跨语言金向量是准入
  门槛，接通 iOS 前先跑向量。
- **誊本**：`crypto/Transcripts.kt` 逐字节实现 §3.5/§3.6/§3.9/§3.3；
  目录解析与 CLI `audit.parseDirectory` 同策略（定长 + 重建比对，fail-closed）。
- **私钥落盘**：AndroidKeyStore 不支持 X25519/Ed25519（design §14.2 已声明），
  私钥由 Keystore 内 AES-GCM 密钥加密后存私有文件。设备丢失 = 撤销重配，
  它本来就什么都不读。
- **队列**：信封在收到短信的那一刻就封好落盘（密文先落本地），WorkManager
  指数退避补传；401 续会话重试一次；配额类 4xx 丢弃并记日志。

## 已知边界

- iOS 收件箱 / 审批界面 / 决策器管理（design §14.4、§14.8 的 iOS 侧）尚未
  实现，本 App 配对后上传的消息暂无 iOS 端消费界面。
- BC 的 HPKE 与 circl 的互操作向量尚未生成（design §9.2 的既有任务）。
