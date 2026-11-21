# keyref 项目地图

- 状态：current
- 最后核对：2026-11-19 清理切片（移除原生 app 与安卓采集端，server 冻结）
- 维护者：keyref 项目窗
- 战略健康：需关注 —— 注入与脱敏主线可用；owner app、审批与同步路径暂缓，项目授权与 remote 持钥模型仍是债务。
- 用途：给技术型决策者判断项目有没有走歪；具体合同与验收证据见链接文档。

## 0. 当前目标（2026-11-19）

把工程收敛到 **lib + cli**，owner app 与审批暂缓，server 保持冻结。

当前目标（完成后再进入下一项）：

1. **独立 lib module**（2026-11-19 完成）：导出本地库与执行引擎；公开接口不引用 CLI `internal` 类型；`GOWORK=off` 可构建；`cli` 改为依赖它且行为不变。
2. **local 路径稳定**（2026-11-19 完成）：`get --reveal` 有控制终端确认、无终端时拒绝；五模块 vet/test 与 CLI e2e 全绿；`cli/README.md`、`lib/local/README.md`、`CLAUDE.md` 与实现一致。
3. **`keyref mcp --source`**（2026-11-19 完成）：MCP 在启动时按 §17.3 选定 source 并固定整个会话（含库路径），list/get/exec 在两个 source 上形状相同，工具消息与锁、退出码一并进结果。
4. **库的错误分类**（2026-11-19 完成）：`lib/local` 至少区分库不存在/已存在、目录权限不安全、钥匙不对、ref 不合法、值大小不合法、条目不存在、写次数用尽、库损坏，`context` 取消与超时原样返回，CLI 按新分类给出人话。

下一项目标，尚未设计完成，不当作既定方案：

- remote 读写：自部署 `keyref-server` + CLI 配置 remote 端点 + GitHub 登录后可读写。
- 待拍板：remote 路径的根密钥归谁（CLI 侧 E2E / server 持钥 / 其他）。这项决定会改动 §16 不变量与威胁模型，必须先定再实现。

## 1. 战略目标

- 要解决的问题：agent 使用凭证时，值容易进入对话、命令参数、日志、计划或回执。
- 目标状态：成为本机及 Neowind、Workcells 的凭证底座；人管理秘密，agent 只传 source/ref，Keyref 将值交给受信消费者并脱敏捕获的输出；需要人工授权的秘密由 owner 客户端批准（该客户端暂缓，计划走 WebView）。
- 不做什么：不做多租户、团队共享或通用秘密编排平台；服务器不解密，不提供明文搜索或主密钥恢复。
- 判断走对的标准：正常使用无需把值交给模型；失败在取值/启动前尽早拒绝；授权、撤销和残余能力有准确说明，不能用本地便利策略代替权限隔离。

## 2. 组织架构

| 部分 | 职责 | 不负责 / 边界 | 关键入口 | 状态 |
| --- | --- | --- | --- | --- |
| CLI | source 选择、策略检查、直接启动子进程、注入与输出脱敏 | 不写 sync vault；不隔离同用户恶意进程 | [cli](cli/) | 可用 |
| 本地库 | 离线加密 SQLite、meta、Use/Stat/List | 不承担审批、远程审计或项目身份认证 | [lib/local](lib/local/) | 可用 |
| 独立 lib | 导出本地库与执行引擎（引擎用自有策略类型，不依赖 CLI internal） | 错误按 §17.7 分类，`Error()` 只出安全文本 | [lib](lib/) | 可用 |
| 同步服务 | 保存密文、设备状态、授予与审计信封，检查形状和配额 | 不接触名字、ref 或明文；暂停新增同步协议功能 | [server](server/) | 冻结 |
| 共享协议 | HKDF/AEAD/HPKE、签名誊本与黄金向量 | 不包含 UI 或消费端策略 | [proto](proto/)、[vectors](tools/vectordump/testdata/vectors.json) | 可用 |
| Owner app | VMK、条目加密、目录签名、批准与撤销 | 不把 VMK 交给 CLI | 暂缓（WebView 方向） | 未实现 |
| Android 采集端 | source device 的短信捕获、加密与上传 | 不读取其他条目、不批准消费 | 已移除 | 移除 |

## 3. 主要工作内容

- 核心能力：本机凭证管理与受控进程注入；owner 管理的同步 vault 与敏感条目审批（暂缓）；短信验证码经审批后消费（随安卓采集端移除）。
- 当前重点：稳定 lib 与 cli 的 local 路径；随后做自部署 server + CLI 配置 remote 端点 + GitHub 登录的读写路径（持钥模型待定）。
- 明确不做：不为集成增加默认明文出口，不把同步或服务端扩展作为本地使用的前置条件，也不在 owner app 缺位时把 sync 表述成可用路径。

## 4. 工作方法

- 合同：设计与威胁模型在 `docs/design.md`，线协议在 `docs/protocol.md`；Go 的 `proto` 是字节参考，跨语言用黄金向量约束。
- 验证：复用五模块 vet/test、独立模块构建和 CLI e2e；安全切片独立复核，发现用具体回归关闭。e2e 里的软件 owner 只用于守住冻结的同步协议，不能当成 owner app 的验收。
- 协作：切片收敛后本地提交，推送单独确认，历史保持线性；本轮 K1 直接开发、验证与记录，不依赖 Workcells 的命令或守护进程。
- 知识：规格、交接和自查留在仓库；地图只提供治理入口，协调消息只传引用与证据，不传值。

## 5. 核心机制与命令

- **数据流**：agent 提交 ref → CLI 查 meta、检查策略 → local 解密或 sync 授予/审批（冻结）→ 受信子进程得到值 → 被捕获的 stdout/stderr 脱敏后返回 agent。
- **状态归属**：local 主密钥在 OS keyring 或显式环境覆盖；sync 的 VMK 在已暂缓的 owner 侧。服务器只是密文中继。source 按 `--source` → `KEYREF_SOURCE` → 配置默认 → `local` 选择。
- **meta/secret 分离**：本地两种密文使用不同钥匙和 AAD；默认 get/list 不解 secret。旧库的真实 meta 在已授权 Use 时回填，不能伪造原写入时间或覆盖并发写入。
- **策略边界**：非空 allowCommands 是名字白名单；本地空列表才用内置拒绝名单。allowedHosts 解析 argv 中 URL 的真实 hostname，不约束配置内 endpoint 或网络重定向。
- **关键不变量**：服务端无明文/ref；sync 无 reveal；配对初始授予为空；approval key 不落 CLI 缓存；验签后再落盘；策略拒绝不启动子进程；脱敏失败关闭。local 显式 reveal 是单独例外。

| 命令 / 接口 | 用途 | 状态 | 证据 |
| --- | --- | --- | --- |
| `keyref init` / `set <ref>` / `delete <ref>` | 本地创建与写入，set 从 stdin 收值并写条目策略 | 可用 | [CLI](cli/README.md) |
| `keyref import-env --file PATH --map NAME=REF` | 显式选择本地变量，整批写入并保留已有策略 | 可用 | [CLI](cli/README.md#importing-selected-environment-variables) |
| `keyref list` / `get <ref>` | local/sync 的加密 meta 与掩码；local reveal 需控制终端确认 | 可用 | [设计 §17](docs/design.md) |
| `keyref exec --env NAME=REF -- <argv>` | 环境注入；另支持 stdin、fd、pty；捕获输出脱敏 | 可用 | [CLI](cli/README.md)、[e2e](cli/e2e/) |
| `keyref source list\|default\|add\|remove` | 配置凭据来源 | 可用 | [CLI](cli/README.md) |
| `keyref pair` / `session` / `sync` / `status` | 配对、会话、同步与状态；owner app 缺位，冻结 | 冻结 | [CLI](cli/README.md) |
| `keyref lock` / `unlock` | 本机阻止或恢复解包 | 可用 | [CLI](cli/README.md) |
| `keyref mcp [--source NAME]` | stdio list/get/exec；启动时选定 source 并固定整个会话 | 可用 | [设计 §17.5](docs/design.md)、[e2e](cli/e2e/mcp_local_test.go) |
| `keyref decider run` | owner 委派范围内的 SMS 自动批准；随安卓采集端冻结 | 冻结 | [设计 §14.8](docs/design.md) |

## 6. 变化、风险与健康

- 最近变化：2026-11-19 移除原生 iOS app 与 Android 采集端，server 冻结；跨语言金向量移至 `tools/vectordump/testdata/`；同日拆出独立 `lib` module（cli 改为依赖它）、补上 `get --reveal` 的控制终端确认、落地 `keyref mcp --source`（启动选定并固定 source，本地库可走 MCP）与 §17.7 的库错误分类（`lib/local/README.md` 有对照表），五模块 vet/test 与 CLI e2e 全绿。此前 `0047831` 落地 set 值语义和 trim 脱敏；`9eca165` 落地本地 meta 与策略；`acb0aba` 修复 URL userinfo 绕过、旧库迁移/并发和失败输入清零问题。
- 走偏风险：把 ref 前缀、source 名、命令名字白名单误当项目隔离，或把终端脱敏误当所有文件/网络出口的保护；接入越多，这两种错误承诺的影响越大。另一个风险是在 owner app 缺位时把 `sync` 或审批说成能用的路径。
- 组织 / 技术健康：local 与冻结的 sync 边界明确，字节合同集中在 `proto`；独立 lib module 已落地（`lib/local`、`lib/exec`、`lib/secret`、`lib/exitcode`），引擎用自有 `exec.Policy`，`lib` 不依赖 `cli`。
- 债务信号：K1 的本地审计和项目授权不能由现有注入功能替代（两者都需要 §16 之外的设计决定）；remote 读写的持钥模型未定。
- 结论：**需关注**。当前最需要守住的是消费端与项目授权边界；凭证注入可用不能被表述成 owner/审批/同步已完成。

## 7. 深入阅读

- 架构 / 合同：[设计](docs/design.md)、[线协议](docs/protocol.md)、[owner app 交互规格（暂缓）](docs/ios-ui.md)
- 命令 / 库：[CLI](cli/README.md)、[本地库](lib/local/README.md)
- 改造 / 证据：[交接](docs/handoff.md)、[K1 计划](docs/k1.md)、[K1 自查](docs/k1-self-check.md)、[注入证据](docs/k1-injection-evidence.md)、[迁移回归](lib/local/migration_test.go)、[CLI e2e](cli/e2e/)
