# cli

给 AI agent 用的命令行。二进制名叫 `keyref`。它的 stdout 里永远没有秘密的明文。

设计见 [docs/design.md](../docs/design.md) 的「引用语法」「exec」和「CLI」几节；线格式以 [docs/protocol.md](../docs/protocol.md) 为准。

命令（design §12.2，已实现）：

| 命令 | 作用 |
| --- | --- |
| `keyref pair` | 生成设备密钥，在终端显示二维码，和 iOS 保险库配对 |
| `keyref session` | 建立或续期服务器会话（挑战换令牌，protocol §6.7） |
| `keyref status` | 配对状态、会话是否解锁、授予剩余有效期 |
| `keyref lock` / `keyref unlock` | 丢掉或恢复内存里的条目密钥 |
| `keyref sync` | 拉取授权范围内的密文 |
| `keyref list` | 名称、描述、`ref`、掩码。没有明文 |
| `keyref get <ref>` | 单条的同样视图 |
| `keyref exec -- ...` | 把秘密注入子进程，脱敏 stdout/stderr；支持 `--env`、`--stdin`、`--fd`、`--pty`/`--reply` |
| `keyref server` | 查看或设置同步服务器的 URL |
| `keyref mcp` | stdio 上的 JSON-RPC 2.0（MCP）：工具只有 `list` / `get` / `exec`，语义与 CLI 同构（design §7.8） |
| `keyref local init\|set\|delete` | 显式管理独立的本地凭据库，不需要配对或同步 |

没有 `reveal`、`export` 或 `--print`。`get` 的 JSON 里不设 `value` 字段。

### 独立本地凭据库

此模式与同步 vault 分开，不使用其授权、owner 审批或远程审计。它需要一个绝对路径；父目录须为私有目录。每次命令均从 `--master-env` 指定的环境变量读取同一个主密钥：该值是 **32 个随机字节的标准 base64 编码**。Keyref 不持久化主密钥，也不会自动生成或恢复它；请先通过可信的方式保管并注入它。丢失或更换主密钥会导致无法读取既有条目。环境变量和进程内存并非对同一用户的恶意进程提供隔离。

```sh
keyref local init --vault /absolute/private/directory/vault.db --master-env KEYREF_LOCAL_MASTER
keyref local set --vault /absolute/private/directory/vault.db --master-env KEYREF_LOCAL_MASTER my-ref < /path/to/secret-input
keyref local delete --vault /absolute/private/directory/vault.db --master-env KEYREF_LOCAL_MASTER my-ref
```

`init` 不覆盖已有文件；`set` 从 stdin 读取 1 字节至 1 MiB，逐字节保存（包括末尾换行），不会把秘密放进命令参数或输出。准备输入时应避免 shell 历史、终端回显及不受信文件造成泄露；本命令不会擦除输入文件。`delete` 只能删除显式引用的条目。代码清理内存仅是尽力而为。

### Go 库：可注册的存储 provider

`github.com/lidessen/keyref/cli/store` 提供统一的 `Store` 接口（`Put`、`Use`、`Delete`、`Close`）。`Use` 仅在回调中提供明文，调用者应避免保留或记录；内存清理不是同用户进程隔离。每个 `store.NewRegistry()` 默认注册独立本地库：

```go
registry := store.NewRegistry()
vault, err := registry.Open(store.Options{Config: store.LocalOptions{Path: path, Key: masterKey}})
// 检查 err；使用 vault 后调用 Close。
```

`Create` 使用同一 Options 并按后端语义创建。空 `Provider` 选择 `local`；显式的未知 provider 或后端错误直接返回错误，绝不回退。应用可用 `Registry.Register(name, factory)` 注册自己的后端；工厂接收该 provider 的配置以及 create/open 标记，并负责验证配置和实现存储语义。注册是实例级的，Keyref 当前内置的只有 local，不意味着同步 vault 或云服务已经可用。CLI 的 `local` 子命令也通过这个入口调用同一个本地后端。


默认服务器是官方托管。`keyref server set https://keys.example.com` 或环境变量 `KEYREF_SERVER` 指向自托管。配对二维码里带上这个 origin，手机在改服务器前会请人确认。两端的加密不因为服务器是谁在运行而不同。

- 语言用 **Go**（design v0.4 起，与服务器同一门语言；早期「Rust + zeroize」的决定已推翻，内存卫生降级为守护分配加显式清零，见 design §12.2）。
- 私钥进操作系统密钥环（macOS Keychain、Linux Secret Service）。解开后的条目密钥与秘密明文只活在守护分配的内存里（memguard：mlock、GC 不可见、`lock` 与退出显式清零）。
- 不要用 shell 去跑用户命令。`sh -c`、`echo`、`env` 一类默认拒绝。
- 机器可读输出用英文表头，方便 agent 解析。

目录布局（实际树，2026-10-27 核对；`cli/internal` 共 17 个包）：

```
cli/
├── cmd/keyref/          # 命令入口（main.go + mcp.go：stdio JSON-RPC）
├── internal/approval/   # approval 条目的审批请求/轮询/一次性解包（design §8.3）
├── internal/audit/      # exec 审计事件的封箱与上传
├── internal/client/     # 同步 API 的薄 HTTP 客户端
├── internal/config/     # origin 配置（0700 目录）
├── internal/device/     # 设备身份：X25519 HPKE 密钥 + 签名密钥
├── internal/exec/       # 策略（含 shebang 解析）、注入、脱敏、pty/reply
├── internal/exitcode/   # design §7.6 退出码表
├── internal/itemcrypt/  # grant 解包、meta/secret 解密
├── internal/keyring/    # SecretStore 接口；go-keyring 实现；测试用目录实现
├── internal/meta/       # list/get：只解 meta，输出掩码
├── internal/pair/       # 二维码生成、pair/register、pair/status 轮询
├── internal/qr/         # 终端二维码渲染
├── internal/secret/     # memguard 守护缓冲区、秘密 JSON 无字符串解析
├── internal/session/    # 挑战→令牌、token 复用与续期
├── internal/store/      # cache.sqlite（0600，密文缓存）
├── internal/syncing/    # 服务器变更应用到本地缓存
├── internal/testowner/  # 测试与 e2e 用的软件 P-256 owner
└── e2e/                 # //go:build e2e 端到端测试
```

验收时用固定夹具：夹具里的明文不得出现在 `list`、`get`、`exec` 的 stdout/stderr 里，包括 base64、hex 和 URL 编码。
