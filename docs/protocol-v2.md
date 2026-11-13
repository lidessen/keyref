# keyref 协议变更规格（v2）

状态：**A、B、C、D、G 已实现，其余已定方案、未实现**。本文是 2026-11 review 之后对 [protocol.md](protocol.md) 与 [design.md](design.md) 的变更规格。实现时先把对应章节并入 protocol.md / design.md，再改代码。背景、发现的问题和实施顺序见 [handoff.md](handoff.md)。

兼容性：**破坏性变更，不兼容旧客户端**（已确认没有需要兼容的存量部署）。直接原地修改格式，不加版本协商和回退分支。

## 0. 原则与记号

原则：**客户端从服务器消费的每一个对象，都必须带有一个消费方能在 owner 签名目录里找到的设备密钥的签名（或者带有服务器从未见过的密钥算出的 MAC），并由消费方验证。** 服务器始终只是不可信的中继。现状里只有 item、grant、directory 满足这一条；审批请求的临时公钥、审批决定、SMS 消息、配对响应都不满足。

记号：

- `P(kind)` = `"KEYREF1" NUL kind NUL`，即现有的 `beginTranscript`。
- `H(x)` = SHA-256(x)，32 字节原始值。
- id 是现有的 32 字符小写 hex。`u64be` 是 8 字节大端。
- `NUL` 是字段之间的一个 `0x00` 分隔字节，末尾没有 NUL。
- 本文新增和修改的誊本只由定长字段和枚举字符串组成，因此编码是单射的。

Go 是参考实现。改完 `proto/` 之后重新生成 `ios/Tests/KeyrefCoreTests/Fixtures/vectors.json`，并为每个新誊本补向量。

## A. 审批请求签名

**已实现**（proto/wire、server、CLI、decider、iOS `ApprovalFlows.swift`；protocol.md §3.11/§6.19/§6.20；向量见 `ios/Tests/KeyrefCoreTests/Fixtures/vectors.json` 的 `approval_request_transcript`）。

替换现状的「Ed25519 直接签 request_ciphertext 原始字节」（无域分隔，也不覆盖临时公钥、subject 和过期时间）。

誊本 `approval-request`，由发起请求的 CLI 用 Ed25519 签：

```text
P("approval-request") vault_id NUL cli_device_id NUL subject_kind NUL
subject_id NUL u64be(expires_at) NUL cli_ephemeral_public_key(32 raw)
NUL H(request_ciphertext)
```

- `subject_kind` 取 `item` 或 `message`；`subject_id` 是条目或消息 id。
- `cli_ephemeral_public_key`（X25519，32 字节）在 `POST /v1/approvals` 里对两种 subject 都**必填**，落库，并在 `GET /v1/approvals` 的行里对两种 subject 都返回。
- 服务器：用请求字段加会话的 vault id、device id 重建誊本，在调用设备的公钥下验签。
- owner（iOS）与 decider：从行重建誊本，在**签名目录**里取该 CLI 的 Ed25519 公钥验签（设备必须是 `kind = cli`、`status = active`）。owner 另外要求解密后的请求正文里的临时公钥等于行上的 `cli_ephemeral_public_key`。decider 解不开请求正文，这个签名就是它所包裹的临时公钥的唯一认证来源。
- 一次性包裹的 HPKE info 不变（仍绑定 approval id、subject id 和 `H(request_ciphertext)`）。

修掉的问题：decider 把短信明文包给服务器转交的未签名公钥。

## B. 审批决定签名（新增）

**已实现**（proto/wire、server 的 approvals 表新增 `decision_signature` 列、schema v7、CLI `internal/approval`、decider、iOS `LiveBackend.decideApproval`；protocol.md §3.12/§6.21/§6.22；向量见 `approval_decision_transcript` 与 `approval_denied_transcript`）。

誊本 `approval-decision`，由做出决定的设备签（owner：ECDSA P-256；decider：Ed25519）：

```text
P("approval-decision") vault_id NUL approval_id NUL decision_device_id
NUL decision NUL H(request_ciphertext) NUL H(wrap)
```

- `decision` 取 `approved` 或 `denied`。
- `wrap` = `u16be(len(one_time_enc)) ‖ one_time_enc ‖ one_time_wrapped_key`（服务器 store 现有的打包形式）；`denied` 时为空串，`H(wrap)` = SHA-256("")。
- `POST /v1/approvals/{id}/decision` 新增**必填**字段 `decision_signature`。服务器在调用设备的公钥下验签（算法按设备），落库（approvals 表新增一列，按现有 `SchemaVersion` 方式迁移），并在 `GET /v1/approvals/{id}` 返回 `decision_device_id` 时一并返回 `decision_signature`。
- CLI 在状态为 `approved` 时、**解包之前**：在本地保存的 owner 签名目录里查 `decision_device_id`。它必须 `status = active`，并且是 `kind = ios`，或者在 subject 为 message 时是 `kind = decider`。重建誊本并验签。本地查不到该设备时同步一次、重查一次。任何失败：退出码 13，不解包。

修掉的问题：HPKE base 模式没有发送方认证，服务器可以伪造审批决定（对 message subject 可以直接塞入伪造的短信正文）。

## C. SMS 消息签名覆盖消息体，读方验签

**已实现**（proto/wire、`proto/crypto.SplitMessageEnvelope`、server `internal/api/messages.go`、CLI `internal/decider`、iOS `MessageEnvelope.verifyUploadSignature` + `LiveBackend`；protocol.md §3.9/§6.28/§6.29；向量见 `message_upload_transcript`）。

信封布局不变：`wrap_count(1) ‖ wraps… ‖ body`，其中 body = `nonce(12) ‖ ct ‖ tag(16)`。

誊本 `message-upload` 的最后一个字段由整个信封改为消息体的哈希：

```text
P("message-upload") vault_id NUL source_device_id NUL u64be(received_at)
NUL H(body)
```

- wrap 记录有意不签：owner 之后会为 decider 补 wrap（`PUT /v1/messages/{id}/wraps`），而伪造的 wrap 解不出消息密钥。
- 服务器在 `POST /v1/messages`：用严格解析器解析信封（`wrap_count >= 1`、id 长度 32、wrapped key 48 字节、body 非空），畸形信封返回 `invalid_field`；对 body 验签。检查顺序：kind → 形状 → 签名 → 配额。（现状是先扣配额后验签，且不校验形状。）
- `GET /v1/messages` 的行新增 `request_signature`。
- 读方（iOS owner、decider）：在签名目录里查 `source_device_id`（必须是 `kind = source` 且未撤销），用行上的 `received_at` 和从信封切出的 body 重建誊本，**解密之前**验签。验不过的行直接跳过，不展示、不审批、不投递。
- 在 `proto/crypto` 放一个把信封切成 (wraps, body) 的公共函数，各端共用。

修掉的问题：source 的签名只有服务器验，owner 和 decider 无法区分真实短信和服务器伪造的消息。

## D. 配对确认 MAC

**已实现**（proto/wire/pair_confirm.go、CLI `internal/pair`、server `internal/api/pair.go` 只存不验、iOS `PairingClient`/`buildPairConfirmMAC` 与 `LiveBackend.completePairing` 按 `t` 接纳设备；protocol.md §3.13/§6.17/§6.18/§9.1；向量见 `pair_confirm_mac`）。

目的：让被配对的设备能认证 owner，而不是信任服务器返回的 owner 公钥。不需要新增任何界面。

- 配对二维码 / payload 新增参数 `c`：32 字节随机数，标准 base64，由被配对的设备生成，**永不发给服务器**。二维码本身就是 CLI 到手机的带外通道。
- owner 计算：

  ```text
  pairing_mac = HMAC-SHA256(key = c,
      msg = "keyref v1 pair-confirm" NUL kind NUL pair_transcript_bytes)
  ```

  `kind` 是被接纳设备的类型（`cli`、`source`、`decider`），`pair_transcript_bytes` 是现有 §3.4 的 pair 誊本。
- `POST /v1/pair/complete` 新增**必填**字段 `pairing_mac`（32 字节）。服务器不透明地保存，并在 `GET /v1/pair/status` 以 `pairing_mac` 返回。
- 被配对的设备用自己的 `c`、自己的 kind 和自己重建的誊本重算 MAC，常数时间比较；不一致则中止配对——在 pin owner 公钥、写入任何本地状态之前。
- owner 必须遵守二维码里的 `t` 参数（设备类型，缺省为 `cli`）。现状 iOS 忽略 `t` 并写死 `cli`，导致配不出 source / decider。
- MAC 计算放在 `proto` 里，签发方和验证方共用一个函数。

修掉的问题：恶意服务器知道 nonce，可以用自己的密钥「完成配对」；Android 采集端因此会把所有短信封给服务器选的公钥。

## E. item 誊本 v2

```text
P("item") vault_id NUL item_id NUL u64be(revision) NUL tombstone(1 字节：
0x00 活条目，0x01 tombstone) NUL H(meta_ciphertext) NUL
H(secret_ciphertext) NUL H(vault_wrapped_meta_key) NUL
H(vault_wrapped_item_key) NUL writer_device_id
```

- 空字段按 SHA-256("") 计。tombstone 四个字段全空且 tombstone = 0x01，不再与「四个字段全空的活条目」字节相同。活条目和 tombstone 用同一个构造函数。
- `ItemData`（sync、`GET /v1/items`）新增四个**始终存在**的字段：`meta_digest`、`secret_digest`、`vault_wrapped_meta_key_digest`、`vault_wrapped_item_key_digest`（各 32 字节，服务器从落库的行计算）。为某设备裁剪过的行仍保留这四个摘要。
- 验证方（CLI 与 iOS，每一条 item 行，包括 tombstone）：对每个在场（非空）字段要求 `H(field) == digest`；用摘要构造誊本；在写入者的公钥下验签（见 F）。服务器仍从完整的 PUT / DELETE 请求体重建誊本。
- grant 誊本字节不变，但 `hpke_enc` 必须恰好是该 KEM 的封装密钥长度（X25519 为 32，P-256 为 65），`wrapped_key` 恰好 48 字节；在 `GrantData.Validate` 和构造函数里校验。

修掉的问题：变长字段用单个 NUL 分隔导致编码不是单射；tombstone 标志不在签名内；CLI 拿到的是裁剪过的行，无法重建誊本，因此现状完全不验 item 签名。

## F. owner 密钥链（多 owner）

客户端不再只认一把 pin 住的 owner 公钥。

- 信任锚：配对时 pin 的 owner 公钥，以及配对时保存的目录。
- 新目录（revision 严格大于已保存的）被接受，当且仅当它的签名在**当前已保存目录**里某个 `kind = ios`、`status = active` 设备的签名公钥下验证通过。本地没有已保存目录时，只接受 pin 住的 owner 公钥。
- item 或 grant 行被接受，当且仅当它的签名在已保存目录里某个 `kind = ios`、`status = active` 设备的签名公钥下验证通过。item 带有签名者（`writer_device_id`）；grant 没有，逐个尝试 active owner 公钥。
- CLI：验证失败的行跳过（不入库、不使用），stderr 一行警告；验证失败的目录让本次同步报错中止。iOS 继续抛 `SyncError.tampered`，例外是本地不存在的条目的 tombstone，直接忽略。
- 已知限制：服务器只保存最新目录。客户端如果错过了「引入当前签名者」的那一版目录，就无法验证，只能重新配对。恢复接管之后旧设备本来就全部撤销，同样需要重新配对。
- owner 被撤销之后，它签过的 item 不再被接受，所以撤销 owner 或恢复接管时必须把全部条目重新签名（现有的轮换流程会重签，但 `LiveBackend.swift` 里用 `try?` 吞掉了失败，需要改成报错）。

## G. 服务器：设备行由签名目录派生

**已实现**（server + protocol.md §6.3/§6.15），测试见 `server/internal/api/regress_test.go` 与 `server/internal/store/directory_test.go`。

- `PUT /v1/directory`（以及恢复接管）时，该 vault 里**不在新目录中**的设备行一律置为 `revoked`。
- `revoked` 是终态：已保存为 `revoked` 的设备，如果新目录把它列为其他状态，返回 `invalid_field`。
- 计划设备上限按新目录的记录投影计算，被省略的行不再计入。

修掉的问题：签名目录和 `devices` 表是两个真相来源，「省略」不等于撤销，被省略的 owner 设备仍保有除签目录外的全部 owner 权限。

## H. exec：已配对的库默认白名单

- 已配对（sync）source：`allowCommands` 为空的条目不能被 `keyref exec` 使用——退出码 10，提示去 iOS 里设置该条目允许的命令。非空时与现状一样是白名单。
- 本地 source：不变（默认拒绝名单），因为本地 source 本来就有 `get --reveal`。
- 任何文档里都不再把拒绝名单描述成安全边界。它挡的是「手滑」，不是对抗性的 agent：`timeout 5 sh -c …`、`awk`、`find -exec`、`git -c alias.x='!…'` 都能把 env 里的秘密变形输出，脱敏器只认整段秘密值。
- 后续（需要改界面，未定稿）：iOS 创建条目时按类型给出命令预设（`curl`、`gh`、`aws` …）。
- `commandPolicy` 字段目前 `exec` 从不读取。要么删除，要么让它成为本条规则的开关；不要保留一个不起作用的旋钮。

## I. 审批是两个正交的轴

- 「存在哪」（同步 / 仅本机）和「是否每次审批」互相独立。仅本机必然审批；同步条目可以是 standard 也可以是 approval。四种组合里三种合法。
- design.md §6.1 的「弱端点」用法（同步 + 审批）继续成立；§6.6 的「`sensitivity` 是派生属性」作废。
- CLI 需要走审批，当且仅当条目 meta 写着 `sensitivity = approval`，**或者**本设备对它没有有效的 `use` 授予。审批投递什么由行决定：`secret_ciphertext` 为空则决定里带的是秘密值本身，否则是一次性 item key。meta 里的字符串只会收紧，永远不会放松。
- design.md §6.6 写审批后投递「密文本身」，实现和 protocol.md 投递的是明文值，以后者为准并修正 §6.6。
- 后续（需要改界面）：iOS 目前用 `StorageClass(sensitivity:)` 把 approval 映射成仅本机，界面上只有一个轴。

## 未纳入本规格、仍然开放的问题

- `PUT /v1/vault/recovery` 的誊本没有 revision / nonce，旧的签名请求可以被重放，把恢复材料回滚到旧恢复码。需要给誊本加 revision 并在 vaults 表存一列。
- 审计事件（HPKE base，无发送方签名）仍然不可认证，服务器可以增删。
- pair-register 誊本不覆盖 HPKE 公钥；session 誊本不绑定 origin。影响低。
- 授予过期：owner 每次解锁都会静默续期，后台续期密钥（§8.4）生成了但没有端点、没有后台任务。要么实现，要么从目录誊本里拿掉。
- 任何 CLI 都可以对任意 item id 发起审批请求（不要求有授予），可用于骚扰式弹窗；审批界面看不到 `--pass`、env 变量名、fd 模板、cwd 和解析后的可执行文件。
