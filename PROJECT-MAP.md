# keyref 项目地图

- 状态：current
- 最后核对：S1/S2 基线 `acb0aba` 与本次导入切片 / 2026-11-14
- 维护者：keyref 项目窗
- 战略健康：需关注 —— 注入与脱敏主线已可用，local 的 reveal 确认和项目授权仍不足以支撑 K1 整体承诺。
- 用途：给技术型决策者判断项目有没有走歪；具体合同与验收证据见链接文档。

## 1. 战略目标

- 要解决的问题：agent 使用凭证时，值容易进入对话、命令参数、日志、计划或回执。
- 目标状态：成为本机及 Neowind、Workcells 的凭证底座；人管理秘密，agent 只传 source/ref，Keyref 将值交给受信消费者并脱敏捕获的输出；需要人工授权的秘密由 iOS owner 批准。
- 不做什么：不做多租户、团队共享或通用秘密编排平台；服务器不解密，不提供明文搜索或主密钥恢复。
- 判断走对的标准：正常使用无需把值交给模型；失败在取值/启动前尽早拒绝；授权、撤销和残余能力有准确说明，不能用本地便利策略代替权限隔离。

## 2. 组织架构

| 部分 | 职责 | 不负责 / 边界 | 关键入口 | 状态 |
| --- | --- | --- | --- | --- |
| iOS owner | VMK、条目加密、目录签名、批准与撤销 | 不把 VMK 交给 CLI | [ios](ios/) | 可用 |
| CLI | source 选择、策略检查、直接启动子进程、注入与输出脱敏 | 不写 sync vault；不隔离同用户恶意进程 | [cli](cli/) | 可用 |
| 本地库 | 离线加密 SQLite、meta、Use/Stat/List | 不承担审批、远程审计或项目身份认证 | [local](cli/local/) | 可用 |
| 同步服务 | 保存密文、设备状态、授予与审计信封，检查形状和配额 | 不接触名字、ref 或明文 | [server](server/) | 可用 |
| 共享协议 | HKDF/AEAD/HPKE、签名誊本与黄金向量 | 不包含 UI 或消费端策略 | [proto](proto/)、[vectors](tools/vectordump/) | 可用 |
| Android 采集端 | source device 的短信捕获、加密与上传 | 不读取其他条目、不批准消费 | [android](android/) | 部分 |

## 3. 主要工作内容

- 核心能力：本机凭证管理、受控进程注入；手机管理的同步 vault；敏感条目审批；短信验证码经审批后消费。
- 当前重点：Neowind provider 的最小环境注入与本地审计、项目授权；显式变量映射的本地 `import-env` 已实现。
- 明确不做：不为集成增加默认明文出口，不把同步或服务端扩展作为本地使用的前置条件。

## 4. 工作方法

- 合同：设计与威胁模型在 `docs/design.md`，线协议在 `docs/protocol.md`；Go 的 `proto` 是字节参考，跨语言用黄金向量约束。
- 验证：复用四模块 vet/test、独立模块构建和 CLI e2e；安全切片独立复核，发现用具体回归关闭。移动端沿用各自检查，不能以 CLI 结果代替移动端验收。
- 协作：切片收敛后本地提交，推送单独确认，历史保持线性；本轮 K1 直接开发、验证与记录，不依赖 Workcells 的命令或守护进程。
- 知识：规格、交接和自查留在仓库；地图只提供治理入口，协调消息只传引用与证据，不传值。

## 5. 核心机制与命令

- **数据流**：agent 提交 ref → CLI 查 meta、检查策略 → local 解密或 sync 授予/审批 → 受信子进程得到值 → 被捕获的 stdout/stderr 脱敏后返回 agent。
- **状态归属**：local 主密钥在 OS keyring 或显式环境覆盖；sync 的 VMK 在 iOS 侧。服务器只是密文中继。source 按 `--source` → `KEYREF_SOURCE` → 配置默认 → `local` 选择。
- **meta/secret 分离**：本地两种密文使用不同钥匙和 AAD；默认 get/list 不解 secret。旧库的真实 meta 在已授权 Use 时回填，不能伪造原写入时间或覆盖并发写入。
- **策略边界**：非空 allowCommands 是名字白名单；本地空列表才用内置拒绝名单。allowedHosts 解析 argv 中 URL 的真实 hostname，不约束配置内 endpoint 或网络重定向。
- **关键不变量**：服务端无明文/ref；sync 无 reveal；配对初始授予为空；approval key 不落 CLI 缓存；验签后再落盘；策略拒绝不启动子进程；脱敏失败关闭。local 显式 reveal 是单独例外。

| 命令 / 接口 | 用途 | 状态 | 证据 |
| --- | --- | --- | --- |
| `keyref init` / `set <ref>` / `delete <ref>` | 本地创建与写入，set 从 stdin 收值并写条目策略 | 可用 | [CLI](cli/README.md) |
| `keyref import-env --file PATH --map NAME=REF` | 显式选择本地变量，整批写入并保留已有策略 | 可用 | [CLI](cli/README.md#importing-selected-environment-variables) |
| `keyref list` / `get <ref>` | local/sync 的加密 meta 与掩码；local reveal 另有确认债务 | 可用 | [设计 §17](docs/design.md) |
| `keyref exec --env NAME=REF -- <argv>` | 环境注入；另支持 stdin、fd、pty；捕获输出脱敏 | 可用 | [CLI](cli/README.md)、[e2e](cli/e2e/) |
| `keyref source list\|default\|add\|remove` | 配置凭据来源 | 可用 | [CLI](cli/README.md) |
| `keyref pair` / `session` / `sync` / `status` | 配对、会话、同步与状态 | 可用 | [CLI](cli/README.md) |
| `keyref lock` / `unlock` | 本机阻止或恢复解包 | 可用 | [CLI](cli/README.md) |
| `keyref mcp` | stdio list/get/exec；当前仅 sync | 部分 | [设计 §17.5](docs/design.md) |
| `keyref decider run` | owner 委派范围内的 SMS 自动批准 | 部分 | [设计 §14.8](docs/design.md) |

## 6. 变化、风险与健康

- 最近变化：`0047831` 落地 set 值语义和 trim 脱敏；`9eca165` 落地本地 meta 与策略；`acb0aba` 修复 URL userinfo 绕过、旧库迁移/并发和失败输入清零问题；本地导入支持显式映射、事务和幂等。
- 走偏风险：把 ref 前缀、source 名、命令名字白名单误当项目隔离，或把终端脱敏误当所有文件/网络出口的保护；接入越多，这两种错误承诺的影响越大。
- 组织 / 技术健康：三种角色与两个 source 边界明确，字节合同集中；公开嵌入接口仍受 CLI module 和 internal 执行引擎约束。
- 债务信号：local reveal 缺控制终端确认；MCP 尚有 source 不对称；K1 的本地审计和项目授权不能由现有注入功能替代。
- 结论：**需关注**。当前最需要守住的是消费端与项目授权边界，凭证注入可用不能被表述成 K1 全部完成。

## 7. 深入阅读

- 架构 / 合同：[设计](docs/design.md)、[线协议](docs/protocol.md)、[iOS 交互](docs/ios-ui.md)
- 命令 / 库：[CLI](cli/README.md)、[本地库](cli/local/README.md)
- 改造 / 证据：[交接](docs/handoff.md)、[K1 计划](docs/k1.md)、[K1 自查](docs/k1-self-check.md)、[注入证据](docs/k1-injection-evidence.md)、[迁移回归](cli/local/migration_test.go)、[CLI e2e](cli/e2e/)
