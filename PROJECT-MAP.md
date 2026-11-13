# keyref 项目地图

- 状态：current
- 最后核对：9eca165 / 2026-11-14
- 维护者：keyref 项目窗
- 战略健康：正常 —— 信任边界与双 source 结构稳定，S1/S2 已收口；下一个风险点是 K1 引入的 `import-env` 明文入口。
- 用途：给技术型决策者判断项目有没有走歪；不写日常任务、决策清单或未验证项。

> 详细设计以链接文档和代码为准。本页只保留治理判断所需的结构、方法和风险。

## 1. 战略目标

- 要解决的问题：AI agent 使用 API key、token、密码时，明文很容易进入提示词、终端输出、日志和回执，人既无法看清 agent 用了什么，也没有可靠的授权、撤销和轮换手段。
- 目标状态：人把秘密放在 iOS 的 Secure Enclave 后面，用手机批准敏感使用；agent 只写稳定 ref（如 `openai-prod`），CLI 把值注入子进程并把输出中的秘密脱敏掉；服务器只存储密文，永远不解密，也看不到 ref 和名字。
- 不做什么：不做团队共享 vault、多租户或浏览器密码管理器；不做通用密钥编排平台；服务器不提供解密、搜索明文或恢复主密钥的能力；CLI 不提供把 paired vault 明文打给模型的标准通道。
- 判断走对的标准：agent 完成任务时上下文里只有 ref 和脱敏后的输出；撤销一台 CLI 后它立即失去可用的 item key；服务器、日志、审计回执中不出现明文、ref 或名字；新增的注入路径默认不扩大明文暴露面。

## 2. 组织架构

```text
iOS owner app（VMK 在 Secure Enclave，加密/签名/批准）
        ↕ 密文 + 审批信封
sync server（只存密文、校验信封形状与配额）
        ↕
CLI（local / sync 两种 source，exec 注入与脱敏）
        ↕
Agent / 子进程（只看到被注入的值）
```

| 部分 | 职责 | 不负责 / 边界 | 关键入口 | 状态 |
| --- | --- | --- | --- | --- |
| iOS 主端 | 持有 VMK、加密条目与目录、签署批准、第二设备配对、SMS 委派 | 不充当服务器；不替 CLI 常驻运行 | `ios/` | 可用 |
| CLI | 两种 source 的选择与读取、`exec` 注入、输出脱敏、MCP、decider | 不能写 paired vault；approval 条目的一次性 key 不落盘；不默认输出明文 | `cli/` | 可用 |
| sync server | 密文同步、设备与授予状态、配额、审计信封校验 | 不解密；不接触 ref、名字、明文 | `server/` | 可用 |
| 共享协议模块 | 字节级誊本、实体 id、签名、HPKE/AEAD、黄金向量参考实现 | 不包含 UI 或业务策略 | `proto/`、`tools/vectordump/` | 可用 |
| 本地存储库 | 离线加密 SQLite、加密 meta、`Use`/`Stat`/`List` | 不实现 grant、审批、同步或远程审计 | `cli/local/` | 可用 |
| Android 短信采集 | `kind = source` 设备读取短信、加密上传、24h 过期 | 不读取其他应用数据；不直接批准 | `android/` | 部分 |

## 3. 主要工作内容

- 核心能力 / 使用场景：人在 iOS 上管理秘密；agent 通过 `keyref exec` 使用秘密；两种 source 共用一套命令；敏感条目走手机批准；短信验证码经审批后作为 `sms:<message_id>` 使用；跨语言字节合同由黄金向量约束。
- 当前重点：lib/CLI 补完 S1（值语义与脱敏）和 S2（本地加密 meta、`list`/`get`、本地策略）已完成；下一步按协调端优先级交付 Neowind 的最小凭证注入路径，再做 `import-env`、审计与项目级 allowlist。
- 明确不做：不把 vault 扩展成多用户服务；不让 CLI 写 paired vault；不提供默认明文 `get`；不把服务器变成解密代理。

## 4. 工作方法

- 开发与合同：`docs/design.md` 是设计与威胁模型合同，`docs/protocol.md` 是线协议与字节合同，`proto/` 是字节参考实现。字节格式变更先改 Go，再重新生成黄金向量，iOS 与 Android 跟随；合同冲突先停下确认，不改文档绕开。
- 验证与评审：CI 为四模块 `go vet` + `go test`、`GOWORK=off` 构建和 CLI e2e；本地另跑 macOS 与 Linux 容器的全量 e2e、iOS `xcodebuild` 测试、Android 黄金向量门禁。每个切片一个本地提交，推送单独确认；安全敏感切片用 fresh-context reviewer 独立复核。
- 协作与迭代：按切片收敛，协调端决定优先级；不降低安全边界来换功能；未真正观察过的链路（如 Android 真机）明确标 `部分`，不用推断补全。
- 文档与知识：规格在 `docs/`（中文），README 为英文；`docs/handoff.md` 记录已完成与未完成；项目地图只做治理导航，不复制详细合同。

## 5. 核心机制与命令

### 核心机制

- **信任边界**：VMK 只在 iOS Secure Enclave；CLI 只持有被授予条目的 item key；服务器只存密文，日志、错误与审计都不含明文、ref 或名字。
- **两种 source**：`local` 是离线加密 SQLite（默认）；`sync` 是配对后的 iOS vault，只读。选择顺序为 `--source` → `KEYREF_SOURCE` → `sources.json` 默认 → `local`。
- **meta 与 secret 分离**：本地行用独立 HKDF 钥匙加密 meta（ref、mask、大小、描述、策略），AAD 绑定 store id 与行 id；`list` / `get` 只解 meta，`exec` 才解 secret。
- **执行路径**：`exec` 先解析 argv0 与 shebang，再做条目策略检查，全部通过才直接 spawn（不经 shell）；值可走 env、stdin、额外 fd 或 pty，输出按多种编码脱敏，脱敏失败以 exit 14 失败关闭。
- **审批**：`sensitivity = approval` 或本机没有可用的 `use` 授予时触发一轮手机批准；批准后交付一次性 HPKE wrap，绑定 `approval_id`、`item_id` 与请求誊本摘要。
- **验证后再落盘**：客户端对每条 item / grant 先验字段摘要与签名或密钥链，失败的行跳过；目录验不过则中止同步。

关键不变量：

- 服务器、其日志、错误与统计中不出现解密后的秘密、条目名或 ref。
- `list` / `get` 不解密 secret；paired vault 没有 reveal 路径，local source 的 `get --reveal` 是唯一例外。
- approval 条目的 item key 不进入 CLI keyring 或 `cache.sqlite`；VMK 不进入任何 `kind = cli` 信封。
- 配对完成时授予为空，直到人在手机上选择条目；撤销 CLI 会轮换它能触达的 item key。
- 执行检查先于 spawn；被拒绝的命令不会启动子进程。
- 本地非空 `allowCommands` 是精确白名单，空列表才回落到内置拒绝名单；内置拒绝名单只是防手滑，不是安全边界。

### 命令 / 接口

| 命令 / 接口 | 用途 | 状态 | 证据 |
| --- | --- | --- | --- |
| `keyref init` | 创建本地 vault，主密钥进 OS keyring | 可用 | [命令参考](cli/README.md) |
| `keyref set <ref>` | 从 stdin 存秘密；`--raw`、`--description`、`--allow-command`、`--allow-host` | 可用 | [命令参考](cli/README.md)、[本地存储库](cli/local/README.md) |
| `keyref get <ref>` | 从加密 meta 读一条；默认只显示 mask，`--reveal` 仅限 local | 可用 | [命令参考](cli/README.md) |
| `keyref list` | 列出 local 或 paired 的条目 meta | 可用 | [命令参考](cli/README.md) |
| `keyref delete <ref>` | 删除本地条目 | 可用 | [命令参考](cli/README.md) |
| `keyref exec -- <argv>` | 注入秘密并脱敏输出（env / stdin / fd / pty） | 可用 | [命令参考](cli/README.md)、[e2e](cli/e2e) |
| `keyref source list\|default\|add\|remove` | 查看或配置 source | 可用 | [命令参考](cli/README.md) |
| `keyref pair` / `session` / `sync` / `status` | 配对、会话、同步与状态 | 可用 | [命令参考](cli/README.md) |
| `keyref lock` / `unlock` | 阻止或恢复 key 解包 | 可用 | [命令参考](cli/README.md) |
| `keyref mcp` | 以 stdio MCP JSON-RPC 提供 list/get/exec | 部分 | [命令参考](cli/README.md) |
| `keyref decider run` | 在 owner 委派范围内自动批准 SMS 消费 | 部分 | [设计 §14.8](docs/design.md) |
| sync API（HTTP） | 密文同步、设备、配额与审计信封 | 可用 | [线协议](docs/protocol.md) |

## 6. 变化、风险与健康

- 最近变化：S1（`0047831`，2026-11-13）完成 `set` 值语义与 §7.4 空白匹配；S2（`9eca165`，2026-11-14）完成本地加密 meta、`list`、不解密的 `get` 和本地 `allowCommands` / `allowedHosts`；issue #2–#8 已修复，详见 `docs/handoff.md` 第 7 节。
- 走偏风险：keyref 成为 Neowind 与 Workcells 的凭证基础后，最容易滑向“通用 secret 平台”（多用户、团队共享、给模型直接读明文）。必须坚持 ref + 注入 + 脱敏，不新增默认明文通道。
- 组织 / 技术健康：三个角色和两种 source 的职责清楚；共享字节合同集中在 `proto/`，跨语言用黄金向量约束；剩余结构问题是 `cli/local` 仍在 `cli` module 内、执行引擎尚未独立导出。
- 债务 / 腐化信号：`get --reveal` 还没有控制终端确认；`keyref mcp` 只服务 paired vault；Android 真机链路未观察；`cli/local` 的库拆分未做；新增 `import-env` 时若不坚持“只解析文件、不经 shell、值不进日志与回执”，会成为新的泄露入口。
- 结论：**健康**。边界没有松动，S1/S2 已收口；最需要盯住的是 K1 的 `import-env`，它必须复用现有的注入与脱敏路径，不能新增明文回显或日志。

## 7. 深入阅读

- 架构 / 合同：[`docs/design.md`](docs/design.md)、[`docs/protocol.md`](docs/protocol.md)、[`docs/ios-ui.md`](docs/ios-ui.md)
- 命令参考：[`cli/README.md`](cli/README.md)、[`cli/local/README.md`](cli/local/README.md)
- 当前改造计划：[`docs/handoff.md`](docs/handoff.md)、[design §17.9](docs/design.md)
- 关键测试或验收证据：[`cli/e2e`](cli/e2e)、[`cli/internal/exec`](cli/internal/exec)、[`cli/local`](cli/local)、[黄金向量](ios/Tests/KeyrefCoreTests/Fixtures/vectors.json)
