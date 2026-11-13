# Handoff：2026-11 review 之后的状态与后续计划

本文记录一次完整 review（设计 + CLI + server + proto + iOS + Android）之后的状态：已经修了什么、哪些经过验证、还剩什么、按什么顺序做。协议层的变更方案原写在 protocol-v2.md（2026-11 的协议 v2 破坏性变更批次规格），已随各步并入 protocol.md / design.md 并删除；文中「v2 X」即该批次的节标。

分支：`claude/adoring-euler-2yzqeu`（已并入 `main`）。

## 0. 进展（2026-11-13，macOS）

第 5 节的前八步、第 9 步的 lib + cli 部分与第 10 步已完成（第 9 步的 iOS / server 部分待办）：

- **第 1 步（验证）通过。** `TestStageFdFileUnlinksImmediately` 与 e2e 的 `TestPtyReplyFlow` 在本机通过。**更正（2026-11-13）：** 前者此前被当成沙箱所致，实际是 Linux 上 memfd 让断言不成立，已在 issue #4 修复（见第 2 节）；只有 pty 那条是环境所致。`d7c3d6b` 的 iOS 改动在 macOS 上编译通过，`KeyrefCoreTests` 119 个用例全绿，含三条新回归；整个 `Keyref` scheme 也全绿。
- **第 2 步（v2 G）已实现。** 见 protocol v2 §G 与 protocol.md §6.3/§6.15：目录是设备行的唯一真相来源，省略即撤销，`revoked` 终态，设备上限按目录记录投影。测试：`server/internal/store/directory_test.go`（新增）、`server/internal/api/regress_test.go`。
- **第 3 步（v2 A + B）已实现。** 见 protocol v2 §A/§B 与 protocol.md §3.11/§3.12/§6.19–§6.22：审批请求改签结构化誊本（覆盖 subject、过期时间、一次性公钥、密文摘要），审批决定新增 `decision_signature`（服务器 approvals 表 schema v7，CLI 解包前先验签，失败退出码 13）。改动：`proto/wire`、`server/internal/api/approvals.go`、`server/internal/store/approvals.go`、`cli/internal/approval`、`cli/internal/decider`、`cli/e2e`、iOS `ApprovalFlows.swift` / `LiveBackend.decideApproval` / `ApprovalTranscripts.swift`（新增）、跨语言向量（新增三条 approval 誊本向量）。负例测试：CLI 拒绝没有签名或签名不对的决定；decider 拒绝它无法归属到目录里 active CLI 的请求；iOS 拒绝临时公钥被换掉的请求。

  注意这个新依赖：CLI 只在**本地保存的 owner 签名目录**里找决定设备，所以任何要给出决定的设备（owner、decider）必须已经出现在 owner 发布的目录里。iOS 的 `completePairing` 已经会在配对落地后重签并发布目录，因此这条链是通的；decider 在配对时一度仍被 iOS 当作 `kind = cli` 接纳（v2 D 要修的 `t` 参数），而服务器只允许 `ios` / `decider` 做决定——第 5 步随 v2 D 修好后，decider 端到端可走生产路径。e2e 里由测试自己发布一份含 owner / CLI / source / decider 的目录来覆盖这一段。

- **第 4 步（v2 C）已实现。** 见 protocol v2 §C 与 protocol.md §3.9/§6.28/§6.29：`message-upload` 誊本末字段由整个信封改为 `H(body)`（body 用新公共函数 `crypto.SplitMessageEnvelope` 从信封切出），服务器按 kind → 形状 → 签名 → 配额 的顺序校验，`GET /v1/messages` 的行回传 `request_signature`，owner（iOS 收件箱与审批页）和 decider 在解包之前按 owner 签名目录里 `kind = source` 且 active 的条目验签，验不过的行直接跳过。包裹记录有意不签名：owner 之后要补写 decider 包裹（§6.30），伪造包裹也解不出消息密钥。改动：`proto/wire`、`proto/crypto`、`server/internal/api/messages.go`、`cli/internal/decider`、`cli/e2e`、iOS `MessageEnvelope.swift` / `Transcript.swift` / `ServerTypes.swift` / `LiveBackend.swift`、跨语言向量（新增 `message_upload_transcript`）。负例测试：decider 拒绝签不上、正文被改、received_at 被改、source 被换、目录里被撤销的消息（`TestRefusesMessageItCannotAttribute`、`TestRefusesRevokedSource`）；iOS 拒绝同样的篡改（`MessageEnvelopeTests`）。Android `Transcripts.kt` / `Envelope.kt` 已在第 10 步跟进（`H(body)` 誊本与严格信封切分）。
- **第 5 步（v2 D）已实现。** 见 protocol v2 §D 与 protocol.md §3.13/§6.17/§6.18/§9.1：二维码新增必填 `c`（32 字节配对秘密，只在二维码里，永不发给服务器），owner 在 `pair/complete` 提交必填的 `pairing_mac = HMAC-SHA256(c, "keyref v1 pair-confirm" NUL kind NUL §3.4 誊本字节)`，服务器只查长度、原样存进配对会话并经 `pair/status` 返回；被配对设备先验 §3.4 签名、再用自己的 `c` 常数时间比对 MAC，失败即中止——在钉 owner 公钥、写任何本地状态之前。签发方与验证方共用 `proto/wire.BuildPairConfirmMAC` 与 Swift `buildPairConfirmMAC`。同时修掉 iOS 忽略二维码 `t` 的问题：`PairingOffer` 解析 `t`/`c`，`LiveBackend.completePairing` 按 `t` 接纳设备（`DeviceInput` 与目录行同 kind），source 与 decider 从此可以正常配对。改动：`proto/wire/pair_confirm.go`（新增）、`cli/internal/pair`、server `internal/api/pair.go` 与 harness、`cli/e2e`、iOS `Transcript.swift` / `PairingClient.swift` / `ServerTypes.swift` / `LiveBackend.swift`、跨语言向量（新增 `pair_confirm_mac`）。负例测试：CLI 拒绝缺失、长度不对、用别的秘密算出的 MAC，且失败时什么都不钉（`TestPairCompleteRejectsForgedMAC`）；iOS 拒绝签名正确但 MAC 不对的完成（`testVerifyCompleteStatusRejectsBadSignatureAndBadMAC`）；服务器拒绝缺失或长度不对的 `pairing_mac`（`TestPairCompleteRequiresConfirmMAC`）。真实 CLI + 真实服务器 + iOS 的配对链路（`RealServerIntegrationTests`）通过。Android `net/ApiClient.kt` 已在第 10 步跟进（二维码 `c` 与 §3.13 MAC 验证）。

- **第 6 步（v2 E + F）已实现。** 见 protocol v2 §E/§F 与 protocol.md §3.1/§3.2/§6.9–§6.11/§8.3：item 誊本改为 `… u64be(revision) NUL tombstone(1 字节) NUL H(四个密文字段) … writer_device_id`，空字段按 SHA-256("") 计，tombstone 不再与「四个字段全空的活条目」同字节；`ItemData` 新增四个始终在场的摘要字段（服务器从落库行计算，裁剪过的行仍带），CLI 与 iOS 对每一条 item 行（含 tombstone）先核字段摘要、再按 `writer_device_id` 在 owner 密钥链里验签；grant 的 `hpke_enc`/`wrapped_key` 钉死 KEM 封装长度与 48 字节包裹长度。多 owner 密钥链（§F）：pin 的 owner 公钥加已保存目录里的 active owner key，新目录须由当前已保存目录里的 active `kind = ios` 设备签名（无已保存目录时只认 pin），item 按 writer 选 key，grant 逐个试 key；CLI 跳过验不过的行（stderr 一行警告）、验不过的目录中止同步，iOS 抛 `SyncError.tampered`（本地不存在的条目的 tombstone 直接忽略）；恢复接管时 `LiveBackend` 的重签失败不再被 `try?` 吞掉。改动：`proto/wire`（`ItemDigestTranscript`、`FieldDigest`、`ItemData.VerifyItemSignature`、grant 尺寸校验）、server `internal/api/items.go`、CLI `internal/syncing/chain.go`（新增）与 `syncing.go`、`cli/internal/testowner`、iOS `Transcript.swift` / `ItemCrypto.swift` / `ServerTypes.swift` / `SyncEngine.swift` / `LiveBackend.swift`、跨语言向量（`item_transcript` 改为摘要形态并新增 `item_tombstone_transcript`；stdlib 金标 `proto/crypto/testdata/vectors.json` 同步重算）。负例测试：CLI 跳过字段摘要不符 / 签名不符 / 未知 writer 的 item、跳过被篡改的 tombstone、拒绝被篡改的目录、接受第二个 active owner 签的目录并拒绝未知 key 签的目录、grant 删除行也验签；iOS 同样覆盖（`testKeyChainAcceptsDirectoryFromAnotherActiveOwner`、`testKeyChainRejectsDirectoryFromUnknownKey`、`testKeyChainRejectsItemFromUnknownWriter`、`testGrantDeletionFormIsVerified`、`testTombstoneWithBadSignatureIsRejected`）。已知限制同样落在文档里：服务器只存最新目录，错过引入当前签名者那版目录的客户端只能重新配对。Android（source 端）没有 item 行的消费面，第 10 步确认无需改动。
- **第 7 步（v2 H + I）已实现。** 见 protocol v2 §H/§I 与 design.md §6.1/§6.6/§7.3/§16。H：`exec` 的命令策略按 source 分叉——已配对库要求条目显式列出 `allowCommands`，为空则退出码 10（提示去 iOS 设置），`commandPolicy = allow-all` 是 owner 的显式放行（其余值含空白继续严格，`allowCommands` 非空时永远按白名单收紧）；本地源不读 `commandPolicy`，继续用内置拒绝名单。`commandPolicy` 从此真正被读取（选「成为开关」而不是删除）。I：审批轮次改为「meta 写了 `sensitivity = approval` **或** 本设备没有有效 `use` 授予」；投递内容由行决定（无 `secret_ciphertext` 投明文值，否则投一次性 item key），meta 只收紧不放松。改动：`cli/internal/exec/policy.go`（`ItemAllowsCommand`/`commandDenial`/`CheckCommand` 新签名）、`cli/internal/exec/exec.go`（`ResolvedRef.Paired`）、`cli/cmd/keyref/main.go`（`hasUsableUseGrant`、`resolveValue` 路由、usage）、`cli/internal/testowner`、e2e 的 `putItem` 默认策略与 `serveOneApprovalFor` 签名、新增 `cli/e2e/exec_policy_test.go`（`TestPairedVaultRequiresAllowCommands`、`TestAllowAllCommandPolicyOptsOut`、`TestStandardItemWithoutUseGrantRequiresApproval`）。文档：design.md §7.3 重写（不再把拒绝名单写成边界）、§6.6 改为两轴并订正「审批投递明文值」、CLAUDE.md 与 cli/README 的执行路径说明。未做（需要改界面，规格里列为后续）：iOS 创建条目时的命令预设、把 approval 从「仅本机」里拆出来的两轴界面。
- **第 8 步（并入与删除 protocol-v2.md）已完成。** 各节内容已随第 2–7 步先行并入 protocol.md / design.md；本步收尾：protocol.md 头部注明 v2 批次与「v2 X」标注的来历；design §16 首条加入 v2 §0 总原则（客户端消费的每个对象都要有可归属到目录设备的签名或服务器未见的 MAC）；v2「未纳入本规格」的五条开放问题移入 design §15（第 21–25 条：recovery 重放、审计发送方认证、pair-register/session 誊本覆盖面、授予过期续期、审批门槛）。
  第 4 节列出的文档出入逐条修正：protocol.md §1.3 补 `local_item_grant_conflict` / `invalid_receiver_role` 两个 400 错误码；§6.7 删掉 `/v1/session` 并不存在的 `rate_limited`；§6.9 与 §8.3 订正 `secret_ciphertext` 的可见规则（view 授予也给——审批条目要能拿到密文在批准后解开）；§6.22 写明审批轮询自做鉴权、非 active 设备得 401 而非 403，§8.3 的可见性说明相应加例外；§6.3 恢复接管不再声称「旧设备全部 revoked」（服务器不检查，只按目录应用）；§10.2 healthz 返回体改为实现的真实形状（tls 只报 mode/status、quotas 只报 enforced/degraded、reasons 的三种字符串码）。CLAUDE.md 的「仅本机条目永不上传 secret 密文」改为「不上传到 keyref 服务器」（iCloud 快照与交接二维码本来就带密文）。design §2.2 的「MVP 不做 Android」改为「不做完整客户端，只有 §14 采集端」；§12.2 的命令一览更新为 §17 的统一命令面（含 `init`/`set`/`delete`/`source`/`mcp`/`decider`，删掉不存在的 `sms` 子命令）。全部指向 protocol-v2.md 的文件链接（docs/README、ios-ui、代码注释、本文）改为指向并入后的章节。protocol-v2.md 已删除。
- **第 9 步（lib + cli 部分）已完成。** exec：`--env`/`--pass` 的禁用名单从 `LD_`/`DYLD_` 前缀扩到能注入代码的 shell/解释器启动与钩子变量（`BASH_ENV`、`NODE_OPTIONS`、`PERL5OPT`、`PYTHONPATH`、`RUBYOPT`、`JAVA_TOOL_OPTIONS`、`GIT_SSH_COMMAND`、`PAGER`、`LESSOPEN` 等，design §7.2 同步说明它仍是滑倒保护）；子进程在独立进程组里导致 Ctrl-C 只杀 keyref 的问题修掉——现在转发 SIGINT/SIGTERM/SIGHUP 给子进程组并以 128+signal 退出，`--stdin` 写协程在 Run 销毁守护内存之前 join（e2e `TestInterruptTerminatesTheChild`）。本地 source 遵守 `keyref lock`（所有解包路径退出 12），锁状态读失败按锁定处理（e2e `TestLockCoversLocalSources`）。首次迁移在 `cache.sqlite` 读不开时失败，不再把它当成「未配对」而永久写下 `local` 默认源（单测 `TestResolveSourceFailsClosedOnUnreadableCache`）。`metaByRef`/`decryptMetaFor` 跳过解不开的条目与授予，一条坏行不再挡住所有 ref。清理：删除无人引用的 `secret.Vault`（设计中的 8 小时 item key 缓存尚未实现，需要时再加回）；删除只有一个 provider 的 `cli/store` 注册表，`localvault` 与命令层直接用 `cli/local`；`cli/internal/store` 改名 `cli/internal/cache`，两个同名 store 消除；`proto/wire/pair_confirm.go` 补 gofmt。验证：`go test -C cli ./...`、`go test -C proto ./...`、全量 e2e 全绿。未做：`unlock` 仍不需要证明（锁本身是本地便利开关，不是边界，按设计取舍保留）；`LiveBackend` 下沉与 iOS / server 的其余「中」条目。
- **审批请求透明性字段（2026-11）已完成**（第 9 步「未做」列表里的第一项；无需改 server）。§6.19 的审批请求明文新增八个**总是出现**的执行上下文字段：`cwd`、`executable`（keyref 实际 spawn 的绝对路径）、`executable_real`（符号链接与 shebang 解析后内核运行的程序）、`executable_layers`（argv0 与每个 shebang 解释器的小写 basename，命令策略逐层检查的就是这条链）、`pass_names`（`--pass` 转发的变量名）、`env_names`（`--env` 注入秘密的变量名）、`fd_targets`（`--fd` 载荷的目的 fd）、`fd_template`（`--fd-template` 原文）；未使用时为空字符串/空数组。只含名字、路径和模板，绝不出现秘密值；位于 HPKE 密文内且被 §3.11 签名覆盖密文摘要，服务器改不了。CLI：`exec.Request` 新增 `OnPolicyPassed` 钩子（策略通过后、取值之前回调，把 `ResolvedCommand` 交给审批轮），`main.go` 把 cwd 与解析结果经新的 `approvalBaseOptions` 传入普通条目与短信两条审批路径。iOS：`ApprovalRequestPlaintext` 严格解码八个字段，审批详情新增 "Execution context" 一节（Executable / Runs / Interpreter chain / Working directory）并在「注入方式」之后按需显示 "Secret variable" / "Injection fd" / "fd template" / "Forwarded variables"（新增文案当前为英文，见 ios-ui.md §5）。测试：e2e `TestApprovalExecFlow` 与 `TestSMSConsumptionFlow` 的明文镜像都补上八个字段并断言执行上下文（短信那条之前会因为 `DisallowUnknownFields` 拒收新字段而超时）；iOS `RealServerIntegrationTests.testRealCliLocalOnlyApproval` 的夹具按 v2 H 补上 `allowCommands: ["awk"]`（此前在 HEAD 上就因空列表被策略拒绝而失败），失败信息现在带 CLI 输出。验证：`go vet`/`go test` 四个模块全绿、全量 e2e 全绿、`swift build`/`swift test --package-path ios` 全绿、跨语言向量除签名外无差异。
- **第 10 步（Android）已完成。** 构建环境：本机已装 Android Studio + SDK，但缺 Gradle、JDK 与 wrapper（仓库里只有 `gradle-wrapper.properties`，`compileSdk 35` 的平台也没装）——补齐 JDK 与 `gradle wrapper` 生成的 `gradlew`/`gradle-wrapper.jar`，此后 `scripts/dev/android-build.sh <task>` 即可本地构建。（工具链后来整体升到当前主流版本：Gradle 9.9.1、AGP 9.5.1 + 内建 Kotlin 2.4.21、compileSdk/targetSdk 37；宿主 JDK 直接用 Studio 自带的 JBR 25，Homebrew JDK 只作备用。）第 3 节「高」第 6 条全部修掉：所有编译错误；HPKE 按公钥长度选 KEM（32B X25519 / 65B P-256，与 `proto/crypto.kemForPublicKey` 同规则）；正文 AAD 真正传进 cipher；`refreshDirectory` 在每次上传前调用（失败则用缓存目录）；队列按信封值删除（下标删除会漏传重传）；5xx 与网络错误保留重试、401 续期会话一次、其余 4xx 丢弃并记日志；`UploadWorker` 的 kicker 与 worker 类重名改为 companion object。v2 C：`Transcripts.messageUpload` 经 `Envelope.splitBody`（`SplitMessageEnvelope` 的严格 Kotlin 孪生）取正文，签名覆盖 `H(body)`；v2 D：二维码携带 `c`（§9.1），`pairStatus` 在 §3.4 签名之后用自己的 `c` 常数时间比对 §3.13 MAC，失败即中止、不钉任何状态（轮询端把 `SecurityException` 与瞬时错误分开，验签失败直接停止配对）。顺带修掉一个既有字节错误：§3.4 誊本的 nonce 是 32 个 hex ASCII 字符，原实现放了 16 原始字节——旧代码的配对验签和 MAC 本来就不会匹配。新增 `CryptoVectorsTest`（9 项，对着 `ios/Tests/KeyrefCoreTests/Fixtures/vectors.json`）：pair-register 誊本、pair 誊本空授予前缀、§3.13 MAC（含错误秘密负例）、message-upload `H(body)` 誊本与截断信封负例、双 KEM 确定性 HPKE（`deriveKeyPair(seed)` + `setupBaseS(..., eph)` 复现 circl 的 enc/ct）、AEAD blob 双向、正文 AAD 形状。门禁全绿：`assembleDebug`、`testDebugUnitTest`（9/9）、`lintDebug`（0 errors）。仍未做：真机上的配对 → 密封 → 上传全链路（需要手机与 iPhone 扫码）。

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

- `cli/internal/exec` 的 `TestStageFdFileUnlinksImmediately`：**已修复（issue #4）。** 原断言「在不存在的目录里暂存会失败」在 Linux 上不成立——`stageFdFile` 先走 memfd，根本不碰目录，CI 跑在 `ubuntu-latest`，`main` 的 `ci` 因此一直是红的。现在文件回退拆成 `stageFdFallback` 直接测试，memfd 分支在 `fdstage_linux_test.go` 里单独断言（不依赖目录、载荷完整），macOS 与 Linux 交叉编译均通过。
- e2e 的 `TestPtyReplyFlow`：沙箱没有可用的 pty，`exec --pty` 以退出码 18 结束。因此本次对 pty 路径的改动（启动失败文本脱敏、`ChildExit`、`Failed()` 检查）**编译过但没有运行过**，请在有 pty 的机器上跑一遍 `go test -C cli ./internal/exec` 和这个 e2e。

iOS 在第 1 步已全量编译与测试通过；Android 在第 10 步已编译、通过 vectors 测试与 lint（未在真机上运行）。

## 3. 已确认但尚未修复的问题

按优先级排列。标「→ v2 X」的由协议 v2 批次的对应小节解决（已并入 protocol.md / design.md）。

### 高

1. **decider 把短信明文包给未签名的公钥**（`cli/internal/decider/decider.go` 约 258–264 行）。恶意服务器替换审批行里的 `cli_ephemeral_public_key` 即可读到验证码。→ v2 A
2. **审批决定和 SMS 消息没有发送方认证。** 服务器可以伪造决定和消息。→ v2 B、C
3. **CLI 完全不验 item 行的签名**（`cli/internal/syncing/syncing.go` 约 97–127 行），服务器可以回放旧密文实现策略回滚。iOS 在两个 wrapped key 都为空时也跳过验签（`SyncEngine.swift` 约 157 行）。→ v2 E、F
4. **配对时 owner 公钥由服务器说了算**（`cli/internal/pair/pair.go` 约 179 行；Android `net/ApiClient.kt` 约 131–146 行）。→ v2 D
5. **默认拒绝名单拦不住外泄。** 版本后缀已修，但 `timeout sh -c`、`awk`、复制一份的 bash 等仍然通过。→ v2 H
6. **Android 采集端不可用。** 多处编译错误（`crypto/Transcripts.kt` 对 `ByteArray` 调 `addAll`；`store/SourceState.kt` 引用未定义的 `KEY_DIRECTORY`、缺 `android.util.Base64` 导入）；owner 的 P-256 HPKE 公钥被塞进 X25519 构造器（`crypto/Envelope.kt` 约 80 行）；消息体 AAD 没有传给 cipher（约 74 行）；`refreshDirectory` 无人调用；上传队列按过期的下标删除，会漏传和重传（`sms/UploadWorker.kt`）；5xx 直接丢弃消息。建议先接入 vectors 测试再谈功能。（已随第 10 步全部修复，并接入 vectors 测试。）

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
9. **本地库占了四个包，其中两个叫 store**：`cli/local`、`cli/store`（只有一个 provider 的注册表）、`cli/internal/localvault`、`cli/internal/source`，另有 `cli/internal/store` 是同步缓存。（注册表已删除、缓存包已改名 `cache`——§0 第 9 步；剩下的库边界见 design v0.10 §17.7。）
10. **「一套命令面」是名义上的。** `list` 只有 sync 有，`set` 和 `--reveal` 只有 local 有，`mcp` 只对 sync，`lock` 对 local 无效。本地 source 的主密钥在同一用户的 keyring 里，对同机 agent 没有保护，文档应当直说它是「防意外回显」的工具。（→ design v0.10 §17：local 的 `list`、`mcp --source`、统一的 `get` 形状、§17.6 的直白表述；`lock` 已覆盖 local。）
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
8. **把 protocol-v2.md 并入 protocol.md / design.md**，修正第 4 节列出的文档出入，更新 `CLAUDE.md` 的不变量，然后删除 protocol-v2.md。（各节内容已随第 2–7 步先行并入；本步收尾。）
9. 第 3 节「中」里剩下的条目，以及 `LiveBackend` 下沉、CLI 包结构整理。（CLI 部分与包结构整理已完成——见 §0 第 9 步；审批请求透明性字段也已完成——见 §0 末条；剩余：iOS / server 的其余「中」条目、`LiveBackend` 下沉。）
10. **Android：已完成（第 10 步）。** 构建环境补齐、vectors 测试接入、按 v2 C、D 重写 `Envelope.kt` / `Transcripts.kt` 并修掉第 3 节「高」第 6 条的全部问题——详见 §0 的第 10 步条目。

## 6. 已经定下来的决定

- 协议直接做破坏性修改，不兼容旧客户端。
- 已配对的库 `exec` 默认白名单；本地 source 保持拒绝名单。
- 「存在哪」与「是否每次审批」是两个正交的轴，保留「同步 + 审批」。
- 多 owner 走链式验证，不移出范围。

## 7. lib + CLI review（2026-11-13）

范围：`cli/local`（库）、`cli/cmd/keyref` 与 `cli/internal/exec`、`source`、`localvault`（CLI 的本地路径），目标是「作为库集成」和「agent 在本机直接用 CLI」。基于 `0bb3cec`。server、iOS、Android 不在范围内。

**设计问题** 写进了 design.md v0.10：§17 重写（本地库的加密 meta 与 `list`、`set` 的换行与策略、`--reveal` 的终端确认、密钥环条目的绑定、`mcp --source`、§17.6 local source 挡什么、§17.7 库的边界、§17.8 命令面细则），§7.4 增加两条，§16 改两条、加三条。实现状态与建议顺序在 design §17.9。

**bug** 各有一条 issue，都在 `0bb3cec` 上复现过（#6、#8 是读代码得出的）：

| issue | 内容 |
| --- | --- |
| #2 | `keyref init` 覆盖另一个本地库在密钥环里的主密钥——丢数据 |
| #3 | MCP 的 `exec` 工具丢错误信息：多条路径写进程 stderr 而不是工具结果 |
| #4 | `TestStageFdFileUnlinksImmediately` 在 Linux 上失败，`main` 的 CI 是红的 |
| #5 | `cli` module 在 `go.work` 之外编译不过：`go.mod` 钉的 `proto` 版本过旧 |
| #6 | `sources.json` 非原子写入、无锁 |
| #7 | 只用本地 source 的安装也会生成 `cache.sqlite`；`<command> --help` 退出码是 2 |
| #8 | Ctrl-C 对子进程组发的是 SIGKILL，不是转发信号 |

**整理项**（不是设计，也不是 bug；做 §17.7 的引擎导出时一并处理）：

- 一次 exec 引用了哪些 ref，算了四遍：`runExecCore` 的 `addRef`、`refsOf`、`exec.CollectRefs`、`baseOutcome`；`injectionModes` 与 `baseOutcome` 重复，`splitSpec` 与 `splitEnvSpec` 重复，`placeholdersInArgv` 与 `ArgvPlaceholderRefs` 重复。有的排序、有的不排序，迟早漂移。让 `exec` 包解析一次、其余地方读结果。
- `execOptions` 到 `exec.Request` 是逐字段拷贝；`approvalBaseOptions` 有 12 个参数、`resolveViaApproval` 有 13 个。把一次 sync exec 的上下文（store、identity、client、vault id、目录、审计收件人）收成一个结构。
- `cli/cmd/keyref/main.go` 1400 行，按命令拆文件。
- `exec.go` 里退出码的数字字面量（`10`、`11`、`15`、`18`）与 `exitcode` 常量混用。
- `cli/local/README.md` 末尾写「仓库是私有的、需要 `GOPRIVATE`」，而仓库目前是公开的；二者取其一。
