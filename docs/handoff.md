# Handoff：2026-11 review 之后的状态与后续计划

本文记录一次完整 review（设计 + CLI + server + proto + iOS + Android）之后的状态：已经修了什么、哪些经过验证、还剩什么、按什么顺序做。协议层的变更方案单独写在 [protocol-v2.md](protocol-v2.md)。

分支：`claude/adoring-euler-2yzqeu`（已并入 `main`）。

## 0. 进展（2026-11-13，macOS）

第 5 节的前两步已完成：

- **第 1 步（验证）通过。** `TestStageFdFileUnlinksImmediately` 与 e2e 的 `TestPtyReplyFlow` 在本机通过（第 2 节的两个失败确认为沙箱环境所致）。`d7c3d6b` 的 iOS 改动在 macOS 上编译通过，`KeyrefCoreTests` 119 个用例全绿，含三条新回归；整个 `Keyref` scheme 也全绿。
- **第 2 步（v2 G）已实现。** 见 [protocol-v2.md](protocol-v2.md) §G 与 protocol.md §6.3/§6.15：目录是设备行的唯一真相来源，省略即撤销，`revoked` 终态，设备上限按目录记录投影。测试：`server/internal/store/directory_test.go`（新增）、`server/internal/api/regress_test.go`。
- **第 3 步（v2 A + B）已实现。** 见 [protocol-v2.md](protocol-v2.md) §A/§B 与 protocol.md §3.11/§3.12/§6.19–§6.22：审批请求改签结构化誊本（覆盖 subject、过期时间、一次性公钥、密文摘要），审批决定新增 `decision_signature`（服务器 approvals 表 schema v7，CLI 解包前先验签，失败退出码 13）。改动：`proto/wire`、`server/internal/api/approvals.go`、`server/internal/store/approvals.go`、`cli/internal/approval`、`cli/internal/decider`、`cli/e2e`、iOS `ApprovalFlows.swift` / `LiveBackend.decideApproval` / `ApprovalTranscripts.swift`（新增）、跨语言向量（新增三条 approval 誊本向量）。负例测试：CLI 拒绝没有签名或签名不对的决定；decider 拒绝它无法归属到目录里 active CLI 的请求；iOS 拒绝临时公钥被换掉的请求。

  注意这个新依赖：CLI 只在**本地保存的 owner 签名目录**里找决定设备，所以任何要给出决定的设备（owner、decider）必须已经出现在 owner 发布的目录里。iOS 的 `completePairing` 已经会在配对落地后重签并发布目录，因此这条链是通的；但 decider 目前仍被 iOS 当作 `kind = cli` 配对（v2 D 要修的 `t` 参数），而服务器只允许 `ios` / `decider` 做决定——decider 端到端要等 v2 D。e2e 里由测试自己发布一份含 owner / CLI / source / decider 的目录来覆盖这一段。

## 1. 已经提交的修复

| 提交 | 范围 | 验证情况 |
| --- | --- | --- |
| `d7c3d6b` | iOS | **未编译、未运行**（在 Linux 上改的，没有 Swift 工具链） |
| `be92fd7` | server | `go vet`、`go test -C server ./...` 通过 |
| `4f3f92c` | CLI | `go vet`、`go test -C cli ./...`、e2e 通过，例外见第 2 节 |

### iOS（`d7c3d6b`）——合并前必须在 macOS 上编译并跑 KeyrefCore 测试

- `SyncEngine.applyItem`：删除本地条目之前先验 tombstone 的 owner 签名。只在本地确实存在该条目时验，避免恢复接管后旧 owner 签的 tombstone 让同步中止。
- `SyncEngine.applyDirectory`：revision 不大于已保存目录的目录直接跳过，防止回放旧目录。
- `LiveBackend.reencryptItem`：`sealItem` 同时换了 metaKey 和 itemKey，但原来只重发 `use` 授予；现在 `view` 授予也重发。原先的后果是撤销或轮换之后，其余设备解不开被轮换条目的 meta。
- `AuditEnvelope.open`：消息体在**全部** wrap 之后，原来取的是当前 wrap 之后，多接收方时只有最后一个能解开。
- `SettingsStore.init`：启动时把持久化的 iCloud 副本开关推给 backend。原来 backend 默认 `true`，关掉开关后重启仍会上传快照。
- 新增测试：`testAuditEnvelopeTwoRecipientsBothOpen`、`testTombstoneWithBadSignatureIsRejected`、`testOlderDirectoryDoesNotReplaceNewer`。
- 需要重点看编译的地方：`AuditEnvelope.swift` 里的元组数组迭代、`reencryptItem` 循环的多行 `where` 子句。

### server（`be92fd7`）

- 审批决定：已过 `expires_at` 的 pending 行不能再被批准（原来会被「复活」并获得新的 60 秒窗口）。
- 创建审批和列出审批之前先把该 vault 过期的 pending 行置为 expired；计数与插入在同一个事务里。原来不轮询的 CLI 可以永久占满每个 vault 10 条的上限。
- 消息审批拒绝已过期的消息。
- `pair/register` 不再重置已消费或进行中的配对（nonce 一次性，重复注册返回 `pair_expired`）；过期的 `pair_sessions` 在注册时和周期清理里删除。
- `DeleteVaultCascade` 补上 `messages` 和 `message_usage_daily`。
- 每设备待处理消息计数不再把已过期的行算进去。
- `PUT /v1/delegation` 校验请求里的 revision 与签名字节里的 revision 一致。

### CLI（`4f3f92c`）

- `exec` 现在执行的是策略检查过的那个文件：spawn 用 `ResolveCommand` 解析出的绝对路径，不再让 `os/exec` 按父进程 PATH 重新查找；Start 之前再确认它仍然解析到被检查的真实文件。**这只是缩小了窗口**，普通文件的内容被原地替换仍然检测不到，彻底解决需要持有 fd 执行（`fexecve`）。
- argv[0] 里的占位符在所有模式下都拒绝（退出码 10）；「cannot start child」的错误文本经过脱敏。
- 默认拒绝名单按去掉版本后缀的名字匹配（`python3.13` → `python`）。这让原本在本机失败的 `TestShebangFollowedAndDenied` 转为通过。
- `--allow-argv` 遇到未知 ref 返回退出码 11，不再空指针。
- 脱敏失败时审计里记录子进程的真实退出码（原来记成「子进程未启动」）；pty 路径也检查 `Failed()`。
- 修正 `keyref decider run` 的分发（原来多切了一次参数，命令完全不可用，裸 `keyref decider` 会 panic）。

## 2. 当前测试状态

```sh
go vet  -C server ./... && go vet  -C cli ./... && go vet  -C proto ./... && go vet  -C tools/vectordump ./...
go test -C server ./... && go test -C cli ./... && go test -C proto ./... && go test -C tools/vectordump ./...
go test -C cli -tags=e2e ./e2e
```

在 review 用的 Linux 沙箱里有两个失败，**改动之前就失败，与本次改动无关**，在正常机器上应当通过，请确认：

- `cli/internal/exec` 的 `TestStageFdFileUnlinksImmediately`：断言在不存在的目录里暂存会失败，但沙箱里 memfd 路径直接成功。
- e2e 的 `TestPtyReplyFlow`：沙箱没有可用的 pty，`exec --pty` 以退出码 18 结束。因此本次对 pty 路径的改动（启动失败文本脱敏、`ChildExit`、`Failed()` 检查）**编译过但没有运行过**，请在有 pty 的机器上跑一遍 `go test -C cli ./internal/exec` 和这个 e2e。

iOS 和 Android 没有任何东西被编译或运行。

## 3. 已确认但尚未修复的问题

按优先级排列。标「→ v2 X」的由 [protocol-v2.md](protocol-v2.md) 的对应小节解决。

### 高

1. **decider 把短信明文包给未签名的公钥**（`cli/internal/decider/decider.go` 约 258–264 行）。恶意服务器替换审批行里的 `cli_ephemeral_public_key` 即可读到验证码。→ v2 A
2. **审批决定和 SMS 消息没有发送方认证。** 服务器可以伪造决定和消息。→ v2 B、C
3. **CLI 完全不验 item 行的签名**（`cli/internal/syncing/syncing.go` 约 97–127 行），服务器可以回放旧密文实现策略回滚。iOS 在两个 wrapped key 都为空时也跳过验签（`SyncEngine.swift` 约 157 行）。→ v2 E、F
4. **配对时 owner 公钥由服务器说了算**（`cli/internal/pair/pair.go` 约 179 行；Android `net/ApiClient.kt` 约 131–146 行）。→ v2 D
5. **默认拒绝名单拦不住外泄。** 版本后缀已修，但 `timeout sh -c`、`awk`、复制一份的 bash 等仍然通过。→ v2 H
6. **Android 采集端不可用。** 多处编译错误（`crypto/Transcripts.kt` 对 `ByteArray` 调 `addAll`；`store/SourceState.kt` 引用未定义的 `KEY_DIRECTORY`、缺 `android.util.Base64` 导入）；owner 的 P-256 HPKE 公钥被塞进 X25519 构造器（`crypto/Envelope.kt` 约 80 行）；消息体 AAD 没有传给 cipher（约 74 行）；`refreshDirectory` 无人调用；上传队列按过期的下标删除，会漏传和重传（`sms/UploadWorker.kt`）；5xx 直接丢弃消息。建议先接入 vectors 测试再谈功能。

### 中

**server**

- 被目录省略的 owner 设备仍然 active。→ v2 G
- `PUT /v1/vault/recovery` 可重放（誊本无 revision）。
- hosted 模式：未认证的 `POST /v1/vaults` 每次都往 PoW challenge 表里加一项（`pow/pow.go` 的 `Issue`，无 per-IP 限制，且每次全表 prune）；`healthz` 每次请求全表统计加一次写。
- `/v1/session` 无限流；任何人可以冲掉别人的登录 challenge（先删后验）。
- 任何 CLI 可对任意 item 发起审批（不要求授予）。
- 终态的审批行永不删除，也不计入存储配额。
- 配额检查在数据库出错时放行（多处 `err == nil &&`）。
- `http.Server` 只设了 `ReadHeaderTimeout`。

**CLI**

- 本地 source 不理会 `keyref lock`；`lock` 本身只是本地 kv 标志，`unlock` 不需要任何证明，读失败按未锁处理。
- 审批请求里没有 `--pass` 名、env 变量名、fd 模板、cwd、解析后的可执行文件，审批人看不到。
- `--pass` 只禁了 `LD_` / `DYLD_`，`GIT_SSH_COMMAND`、`NODE_OPTIONS`、`BASH_ENV` 等可以转发。
- 非 login 模式下 Ctrl-C 只杀 keyref，子进程成为孤儿并继续持有秘密；`--stdin` 的写 goroutine 与 `Value.Destroy()` 有竞争。
- 首次迁移时 `cache.sqlite` 打不开会被静默当作「未配对」，把默认 source 永久写成 `local`（`cmd/keyref/source.go` 约 53–61 行）。
- `metaByRef` 遇到一条 meta 解不开就整体失败，一条坏授予会挡住所有 ref。

**iOS（均未运行验证）**

- 删除的仅本机条目会在下次快照合并时复活（快照条目没有 tombstone）；删除 vault 不清 iCloud 快照。
- 恢复接管 / 本地重建时对服务器给的目录不验签就重新签名（`VaultFlows.swift` 约 127–141 行、`LiveBackend.swift` 约 1706–1727 行），恶意服务器可以塞进一台 active 的 CLI。
- 接管后的条目轮换失败被 `try?` 吞掉（`LiveBackend.swift` 约 1811 行）。
- Secure Enclave 不可用时静默降级为软件密钥（`OwnerKeys.swift` 约 92–105 行），与 design §9.2 相反；SE 密钥没有生物识别或口令要求（`biometryRequired: false`）。
- `lock()` 只清 `vmk`，审批记录里的短信明文和 bearer token 仍在内存。
- 快照信任集合包含已撤销的 owner 公钥（`LiveBackend.swift` 约 2293 行）。
- `SnapshotFormat.swift` 约 285 行：对未验签输入里的 `UInt64` 长度做 `Int(n)`，超大值会 trap；可经交接二维码的 `snap=` 触达。
- `Keyref.entitlements` 只有 `aps-environment`，没有 iCloud 权限，CloudKit 调用预计会失败。

## 4. 设计层面的问题

1. **核心承诺建立在拒绝名单上。** 见 v2 H。对外表述建议改成「明文不会意外进入模型上下文」；对抗性场景明确要求白名单加审批（以及 Phase 3 的沙箱）。
2. **「服务器不可信」只对最早的三种实体成立。** 之后每加一个功能就新开一条没有发送方认证的 HPKE 通道。见 v2 的总原则。
3. **`sensitivity`、存储类别、行形态三套概念叠在一起**，文档 §6.1 与 §6.6 互相矛盾。见 v2 I。
4. **设备状态有两个真相来源**（签名目录与 `devices` 表）。见 v2 G。
5. **多 owner 只设计了一半。** 服务器校验目录签名链，客户端只认一把公钥。见 v2 F。
6. **誊本编码不是单射。** 见 v2 E。
7. **授予过期是装饰性的。** 每次解锁静默续期；后台续期密钥没有落地。
8. **iOS 的关键逻辑不在可测的那一层。** 撤销、轮换、接管、快照的编排全在 `KeyrefUI/Backend/LiveBackend.swift`（约 2400 行），UI 测试跑的是平行实现 `MemoryBackend`。本次 iOS 的问题几乎都出在这里。建议把编排逻辑下沉到 `KeyrefCore`，让 `LiveBackend` 只做胶水。
9. **本地库占了四个包，其中两个叫 store**：`cli/local`、`cli/store`（只有一个 provider 的注册表）、`cli/internal/localvault`、`cli/internal/source`，另有 `cli/internal/store` 是同步缓存。
10. **「一套命令面」是名义上的。** `list` 只有 sync 有，`set` 和 `--reveal` 只有 local 有，`mcp` 只对 sync，`lock` 对 local 无效。本地 source 的主密钥在同一用户的 keyring 里，对同机 agent 没有保护，文档应当直说它是「防意外回显」的工具。
11. **未兑现的「已完成」和死代码。** `secret.Vault` 无人使用；决策摘要里的 Argon2id 恢复口令没有实现；`billing/apple` 是恒 404 的桩；`commandPolicy` 字段无人读取。
12. **design.md 是按版本追加的。** §14、§17 覆盖了前面章节却没有回头改（§2.2 仍写「MVP 不做 Android」，§12.2 的命令清单过时）。建议给每个功能标状态：已实现 / 部分 / 仅设计。

文档与实现的出入，需要改文档的：

- `CLAUDE.md` 的不变量「仅本机条目永不上传 secret 密文」不在 design §16 里，并且与 §6.7 冲突：iCloud 快照默认开启，上传的正是这份密文，交接二维码里也带。应改为「永不上传到 keyref 服务器」。
- protocol.md：`secret_ciphertext` 对 `view` 授予也返回（§6.9 / §8.3 写的是需要 `use`）；`/v1/session` 没有 `rate_limited`；撤销设备轮询审批得到的是 401 而不是 403；错误码表缺 `local_item_grant_conflict` 和 `invalid_receiver_role`；`healthz` 的返回体与 §10.2 不符；§6.3 说接管目录里旧设备全部 revoked，服务器并不检查。

## 5. 建议的实施顺序

每一步都是可独立合并的一块。Go 是参考实现，iOS 跟随；每一步改完 `proto/` 都要重新生成 vectors 并确认只有预期的键变化。

1. **在 macOS 上验证 `d7c3d6b`**，并在有 pty 的机器上确认第 2 节的两个失败不存在。
2. **v2 G**（server 设备行由目录派生）。只动 server，最小。
3. **v2 A + B**（审批请求与决定签名）。涉及 `proto/wire`、`server/internal/api/approvals.go` 与 store 迁移、`cli/internal/approval`、`cli/internal/decider`、`cli/internal/testowner`、e2e、vectors、iOS `ApprovalFlows.swift` 与 `LiveBackend.decideApproval`。负例测试：决定签名缺失或错误时 CLI 拒绝；临时公钥被替换时 decider 拒绝。
4. **v2 C**（SMS 签名）。`proto/wire`、`proto/crypto`（信封切分函数）、`server/internal/api/messages.go`、decider、iOS 收件箱加载、Android `Transcripts.kt`。
5. **v2 D**（配对 MAC）。`cli/internal/pair`、`proto`、server 的 pair 请求与结果、testowner、iOS `PairingClient.swift` 与 `completePairing`（同时遵守 `t`）、Android。
6. **v2 E + F**（item 誊本 v2 与 owner 密钥链）。改动面最大：`proto/wire`、server 的 item 读写与 sync 渲染、`cli/internal/syncing`、iOS `ItemCrypto`、`SyncEngine`、全部 item 相关向量。建议 E 和 F 一起做，因为 CLI 验 item 签名同时依赖两者。
7. **v2 H + I**（exec 默认白名单、审批两轴）。主要在 `cli/internal/exec` 与 `cli/cmd/keyref/main.go`；e2e 和 testowner 里的条目需要补 `allowCommands`。
8. **把 protocol-v2.md 并入 protocol.md / design.md**，修正第 4 节列出的文档出入，更新 `CLAUDE.md` 的不变量，然后删除 protocol-v2.md。
9. 第 3 节「中」里剩下的条目，以及 `LiveBackend` 下沉、CLI 包结构整理。
10. Android：先有构建环境和 vectors 测试，再按 v2 C、D 重写 `Envelope.kt` / `Transcripts.kt`。

## 6. 已经定下来的决定

- 协议直接做破坏性修改，不兼容旧客户端。
- 已配对的库 `exec` 默认白名单；本地 source 保持拒绝名单。
- 「存在哪」与「是否每次审批」是两个正交的轴，保留「同步 + 审批」。
- 多 owner 走链式验证，不移出范围。
