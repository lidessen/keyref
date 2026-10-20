# cli

给 AI agent 用的命令行。**尚未实现。** 二进制名叫 `keyref`。它的 stdout 里永远没有秘密的明文。

设计见 [docs/design.md](../docs/design.md) 的「引用语法」「exec」和「CLI」几节。

计划中的命令：

| 命令 | 作用 |
| --- | --- |
| `keyref pair` | 生成设备密钥，在终端显示二维码，和 iOS 保险库配对 |
| `keyref status` | 配对状态、会话是否解锁、上次同步时间 |
| `keyref lock` / `keyref unlock` | 丢掉或恢复内存里的条目密钥 |
| `keyref sync` | 拉取授权范围内的密文 |
| `keyref list` | 名称、描述、`ref`、掩码。没有明文 |
| `keyref get <ref>` | 单条的同样视图 |
| `keyref exec -- ...` | 把秘密注入子进程，脱敏 stdout/stderr |
| `keyref server` | 查看或设置同步服务器的 URL |

没有 `reveal`、`export` 或 `--print`。`get` 的 JSON 里不设 `value` 字段。

默认服务器是官方托管。`keyref server set https://keys.example.com` 或环境变量 `KEYREF_SERVER` 指向自托管。配对二维码里带上这个 origin，手机在改服务器前会请人确认。两端的加密不因为服务器是谁在运行而不同。

- 语言用 Rust，方便 `zeroize`、直接 `posix_spawn`，以及打出单个静态二进制。
- 私钥进操作系统密钥环（macOS Keychain、Linux Secret Service）。解开后的条目密钥只放内存。
- 不要用 shell 去跑用户命令。`sh -c`、`echo`、`env` 一类默认拒绝。
- 机器可读输出用英文表头，方便 agent 解析。

建议的后续布局：

```
cli/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── exec.rs
    ├── redact.rs
    └── crypto.rs
```

验收时用固定夹具：夹具里的明文不得出现在 `list`、`get`、`exec` 的 stdout/stderr 里，包括 base64、hex 和 URL 编码。
