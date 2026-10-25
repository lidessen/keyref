# 安全政策

## 支持范围

- `server/`（keyref-server）
- `cli/`（keyref CLI）
- `ios/`（KeyrefCore / KeyrefUI）
- `proto/` 与 `docs/protocol.md` 定义的线协议

## 如何报告漏洞

**不要开公开 issue。** 使用 GitHub 的「私下报告安全漏洞」（仓库 Security 标签页 → Report a vulnerability）。你提交的内容只有维护者可见。

- 描述问题、复现步骤、影响的组件与威胁模型条目（design.md §4.1 的 A1–A7、§4.2 的 B1–B8）。
- 收到后 96 小时内确认，修复前不公开细节；修复后致谢（除非你要求匿名）。

## 明确不在范围

design.md §4.2（B1–B8）声明为「接受边界」的场合不在漏洞之列，例如：

- 运行 CLI 的主机被完全控制（root、调试器、`LD_PRELOAD` 注入 keyref 本身）；
- agent 的 harness 另有通用 shell 且能观察同机进程；
- 恢复码或已解锁手机本身泄露。

其中任何一条若你有**超出设计声明**的新攻击面（例如：满足 §4.3 集成约束的前提下仍能泄密），仍然欢迎按上面的渠道私下报告。

## 设计承诺速查

- 服务器与日志不出现明文、名称与 `ref`（design.md §15）。
- `list` / `get` 不解密 secret；不存在 `--reveal` 类开关。
- 跨工具秘密传递只有 §7.8 的三种形态。
