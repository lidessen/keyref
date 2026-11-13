# keyref 线协议契约

状态：v1.2，对应 design.md v0.8。本文是唯一的线格式依据：并行的 Go 服务器实现者与 Go CLI 实现者都只按本文写字节。design.md 讲「为什么」，本文讲「精确是什么」。两者冲突时，以本文对线格式的拍板为准，并把差异登记在第 12 节。

本文包含 2026-11 协议 v2 破坏性变更批次的全部内容（原变更规格 protocol-v2.md，已逐节并入后删除）：标注「v2 X」的段落属于该批次，不兼容旧客户端（没有存量部署需要兼容）。

日期：2026-11-02（v1.2 修订：随 design v0.8 新增短信验证码采集——`source`/`decider` 设备种类、消息端点与信封、审批 subject 扩展、委托策略誊本、§5.28–§5.32；v1.1 2026-10-27 补推送令牌端点；初版 2026-10-24）。实现语言：Go（design §12.2，v0.4 起 CLI 与服务器同为 Go）。

---

## 1. 全局约定

### 1.1 编码

| 项 | 规则 |
| --- | --- |
| 二进制字段（JSON 内） | 标准 Base64，RFC 4648 **带填充**，`encoding/base64.StdEncoding` |
| id（`vault_id`、`device_id`、`item_id`、`approval_id`、`message_id`、`nonce`） | 16 字节随机数的**小写 hex**，32 个字符，正则 `^[0-9a-f]{32}$` |
| 时间 | Unix 毫秒，JSON number（`int64`） |
| 誊本内整数（`revision`、`expires_at`、`directory_revision`、计数） | **uint64 大端 8 字节**（`binary.BigEndian.PutUint64`） |
| HPKE `info` 与 AAD 分隔 | ASCII unit separator `0x1f`（下文写作 `<US>`） |
| 签名誊本分隔 | NUL `0x00`（下文写作 `<NUL>`） |
| `Authorization` | `Bearer <token>`；token 是 32 字节随机数的 hex（64 字符） |

### 1.2 JSON 规则

- 请求与响应 `Content-Type: application/json; charset=utf-8`。
- 字段名 lower_snake_case。**未知字段一律拒绝**（`400 invalid_field`，design §12.3），避免把客户端误传的明文写进日志。
- 错误响应固定为 `{"error":"<code>"}`，可附结构化字段（如 `challenge`），**永不回显请求字段**（design §11）。
- 请求正文上限先于解析执行：item 路径 256 KiB、审计 4 KiB、审批 8 KiB、消息 16 KiB（decision 96 KiB，§6.21），超限 `413 body_too_large`。

### 1.3 错误码 → HTTP 状态

| 码 | HTTP | 场景 |
| --- | --- | --- |
| `invalid_json` | 400 | 正文不是合法 JSON |
| `invalid_field` | 400 | 字段缺失、类型错、未知字段、hex/base64 不合法、`ref` 类字段越界 |
| `local_item_grant_conflict` | 400 | 仅本机条目（无 `secret_ciphertext`）被建/续 `use` 授予，或带 `use` 授权的条目改为本地（§6.10、§6.12） |
| `invalid_receiver_role` | 400 | 目录 `receiver_role` 非法：非 `0x00` 角色出现在非 ios 设备上，或同一库出现第二条 `0x01` 主接收端（§3.3） |
| `unauthorized` | 401 | 无/坏 token；session 第二步签名不通过；未知设备 |
| `pow_required` | 401 | 托管上创建保险库缺工作量证明（响应附 `challenge`，见 §10.1） |
| `delete_challenge_required` | 401 | 删除保险库第一步（响应附 `challenge`，见 §7.2.5） |
| `forbidden` | 403 | `kind=cli` 调 owner 端点；owner 端点由非 owner 调用 |
| `device_revoked` | 403 | 已撤销设备调用 §8.4 送达语义允许之外的端点 |
| `bad_signature` | 403 | 签名缺失或在该设备当前公钥下验证失败 |
| `vault_frozen` | 403 | 冻结库的写入（读与删除仍允许，design §10.5 第 8 条） |
| `not_found` | 404 | 路径里的 id 不存在 |
| `revision_conflict` | 409 | item/grant 的 revision 不满足「已存值 + 1」或目录 revision 不前进 |
| `cursor_stale` | 409 | sync cursor 落在已清理的日志区间（客户端改用 `cursor=0`） |
| `approval_not_pending` | 409 | 对非 pending 的审批做决定 |
| `pair_expired` | 410 | 配对会话过期或已消费 |
| `body_too_large` | 413 | 超过 §1.2 的正文上限 |
| `rate_limited` | 429 | 超过每分钟配额；审批轮询间隔 < 2 秒 |
| `quota_exceeded` | 429 | 超过每日请求、存储、条目数、待审批数等档位上限 |

超额（`quota_exceeded`）时**永远可用**的操作集合（design §10.5 第 7 条）：读（`sync`、`account`、`items` 读、`grants/self`、`messages`）、删除（item tombstone、grants、目录、整个保险库、消息）、审批决定。

### 1.4 算法标识（数据库列值与 JSON 字符串）

| 列/字段 | 取值 | 映射到 circl / 标准库 |
| --- | --- | --- |
| `hpke_kem` | `"X25519"` \| `"P-256"` | `hpke.KEM_X25519_HKDF_SHA256`（0x20）\| `hpke.KEM_P256_HKDF_SHA256`（0x10） |
| `sign_alg` | `"ed25519"` \| `"ecdsa-p256"` | `crypto/ed25519` \| `crypto/ecdsa` + P-256 |
| HPKE suite | 固定 RFC 9180 Base：DHKEM + HKDF-SHA256 + AES-256-GCM | `hpke.NewSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)` |

公钥字节编码（`hpke_public_key`、`sign_public_key` 列与 JSON 传输一致）：

| 密钥 | 编码 | 长度 |
| --- | --- | --- |
| X25519（HPKE） | 原始公钥 | 32 |
| P-256（HPKE） | SEC1 非压缩点 `0x04‖X‖Y` | 65 |
| Ed25519（签名） | 原始公钥 | 32 |
| ECDSA P-256（签名） | SEC1 非压缩点 | 65 |

签名编码：Ed25519 = 64 字节原生；ECDSA P-256 = **ASN.1 DER**（`ecdsa.SignASN1`/`VerifyASN1`，先 SHA-256 再签）。

### 1.5 密文 blob 布局

| blob | 布局 |
| --- | --- |
| 对称加密（`meta_ciphertext`、`secret_ciphertext`、`recovery_wrap`、`vault_wrapped_*`、审计正文 AES 段） | `nonce(12) ‖ ct ‖ tag(16)`，AES-256-GCM，nonce 随机 |
| HPKE 封装（`hpke_enc`、`one_time_enc`、审计包裹 `enc`） | KEM `enc` 原始字节（X25519 32 字节 / P-256 65 字节） |
| HPKE 密文（`wrapped_key`、`one_time_wrapped_key`、审计包裹 `ct`） | `ct ‖ tag(16)`，AAD 为空（绑定全部在 `info`） |

**誊本是只写的**：签名方按字段顺序拼接，验证方用结构化字段重建再比对，任何实现都**不得**按 `<NUL>` 切分解析誊本——二进制字段（密文、公钥、digest）允许包含 `0x00`。

---

## 2. 模块、依赖与目录

### 2.1 go.work：四模块共用，不做 vendoring

拍板：根 `go.work` 连接四个模块（cli、proto、server 与 tools/vectordump——生成 iOS 跨语言金向量的开发工具，不参与线上字节），共享誊本与密码学代码放独立模块 `proto/`。理由：服务器与 CLI 都要构造/重建誊本并验签（§3），`internal/` 跨模块不可见，复制代码会让两侧誊本漂移；vendoring 冻结依赖、拖慢修补，且 go.work 已是 2026 年多模块仓库的标准做法。Docker 构建以仓库根为 context，`go.work` 在 WORKDIR 内自动生效。

```
// /go.work
go 1.26.0

use (
	./cli
	./proto
	./server
	./tools/vectordump
)
```

模块路径为 `github.com/lidessen/keyref/{proto,server,cli,tools/vectordump}`（已由各 go.mod 落地，见第 13 节假设）。

### 2.2 proto/（共享协议模块）

```
proto/go.mod                // module github.com/lidessen/keyref/proto
proto/wire/wire.go          // 全部请求/响应 JSON 结构体 + 字段校验（仅标准库）
proto/wire/transcript.go    // §3 全部誊本的构造与重建（仅标准库）
proto/wire/entity.go        // §8.2 entity_id 编解码（仅标准库）
proto/crypto/hpke.go        // circl 封装：WrapKey/UnwrapKey（收发两个方向、两种 KEM）
proto/crypto/aead.go        // AES-GCM blob（§1.5）、info/AAD 拼接
proto/crypto/keys.go        // 设备密钥生成、公钥编码（§1.4）
proto/crypto/hkdf.go        // recovery-kek / recovery-sign 派生（§7.2.2）
proto/crypto/testdata/      // 金向量 JSON（§11.3）
```

依赖拆分是硬约束：**`proto/wire` 只 import 标准库**；circl 只进 `proto/crypto`。服务器只 import `proto/wire`（§2.4），因此服务器二进制不携带 HPKE。

### 2.3 cli/

```
cli/go.mod                  // module github.com/lidessen/keyref/cli
cli/cmd/keyref/main.go      // 命令入口：pair session status lock unlock sync list get exec server mcp
cli/internal/approval/      // 审批流 CLI 侧：发起审批请求、轮询、一次性解包（design §8.3）
cli/internal/audit/         // 封箱并上传 exec 审计事件（§6.23）
cli/internal/client/        // 同步 API 的薄 HTTP 客户端
cli/internal/config/        // origin 配置（0700 目录）、KEYREF_SERVER 覆盖
cli/internal/device/        // 设备身份：X25519 HPKE 密钥 + 签名密钥的生成与保管
cli/internal/exec/          // spawn（os/exec + SysProcAttr）、策略与 shebang、注入、脱敏、pty/reply
cli/internal/exitcode/      // design §7.6 的退出码表
cli/internal/itemcrypt/     // CLI 侧解密路径：owner 验签 + grant/meta/secret 解密
cli/internal/keyring/       // SecretStore 接口；go-keyring 实现；e2e 用的目录实现（§11.4）
cli/internal/meta/          // list/get：只解 meta，输出掩码
cli/internal/pair/          // 二维码生成、pair/register、pair/status 轮询、钉死 owner 公钥
cli/internal/qr/            // skip2/go-qrcode 封装；ToSmallString 的 ▀▄█ 半块字符写 stdout
cli/internal/secret/        // memguard 守护缓冲区、秘密 JSON 无字符串解析
cli/internal/session/       // 挑战→令牌、token 复用与续期
cli/internal/cache/         // cache.sqlite（模式 0600，密文缓存 + 已验签 revision）
cli/internal/syncing/       // 把服务器变更应用到本地缓存（cursor=0 引导、撤销检测）
cli/internal/testowner/     // 测试与 e2e 用的软件 P-256 owner（§11.2）
cli/e2e/doc.go              // package e2e；无 build 标签，只有包注释（防 ./... 报 exclude all Go files）
cli/e2e/*_test.go           // 全部带 //go:build e2e（§11）
```

### 2.4 server/

```
server/go.mod               // module github.com/lidessen/keyref/server
server/cmd/keyref-server/main.go   // 默认 serve；子命令 backup、version（§10.3）
server/internal/api/        // 全部 handler、鉴权/限流/正文上限中间件、错误码
server/internal/store/      // modernc.org/sqlite、§6.3 schema 迁移、changes 追加
server/internal/quotas/     // 档位表、全局预算、frozen、usage_daily
server/internal/pow/        // 工作量证明签发与校验（§10.1）
server/internal/httpserver/ // net/http、autocert、healthz
server/Dockerfile
```

**服务器不需要 HPKE**（已核实，design §10.1「哑存储加一点点鉴权」）：它只存 BLOB、验签名（Ed25519 / ECDSA P-256 / 恢复 Ed25519，全部标准库）、递游标。所以：

```
// server/go.mod 的 require（示意）
require (
	github.com/lidessen/keyref/proto v0.x.x   // 只用 proto/wire
	modernc.org/sqlite v1.61.0
	golang.org/x/crypto v0.58.0               // acme/autocert
)
```

```
// cli/go.mod 的 require（示意）
require (
	github.com/awnumar/memguard v0.23.0
	github.com/cloudflare/circl v1.6.5
	github.com/lidessen/keyref/proto v0.x.x
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/crypto v0.58.0               // hkdf
)
```

两个模块都 `CGO_ENABLED=0` 可构建（§4 已逐个核实）。

---

## 3. 誊本（签名的精确字节格式）

以下 `<NUL>` = 单字节 `0x00`；`u64be(x)` = 8 字节大端；hex 字段是 ASCII 小写 hex 字节串；其余字段按原文原始字节。所有誊本以 ASCII `KEYREF1` 开头。除特别说明，结尾**没有**尾随 `<NUL>`。

### 3.1 item 誊本（design §9.1，protocol v2 E）

```text
"KEYREF1" <NUL> "item" <NUL> vault_id(hex) <NUL> item_id(hex) <NUL>
u64be(revision) <NUL> tombstone(1 字节) <NUL> H(meta_ciphertext) <NUL>
H(secret_ciphertext) <NUL> H(vault_wrapped_meta_key) <NUL>
H(vault_wrapped_item_key) <NUL> writer_device_id(hex)
```

- 签名者：owner（v2 F：`writer_device_id` 所指、目录里 `kind = ios`、`status = active` 的设备；ECDSA P-256，ASN.1 DER）。
- `H(x)` = SHA-256(x)，空字段按 `H("")` 计，恒为 32 字节。
- `tombstone` 一个原始字节（紧跟 `u64be(revision)` 之后的字段，后面的 `<NUL>` 照常）：`0x00` 活条目，`0x01` tombstone。tombstone 的四个密文字段必须全空，因此不再与「四个字段全空的活条目」字节相同；两种行用同一个构造函数。
- 验证（CLI 与 iOS，每一条 item 行，包括 tombstone）：对每个在场的（非空）字段要求 `H(field) == digest`；用 `ItemData` 的四个摘要字段构造上面的誊本并验签。为 CLI 裁剪过的行（§8.3）仍带四个摘要，签名可验而密文不可见。服务器仍从 PUT / DELETE 请求体的完整字段重建誊本。
- `vault_wrapped_*` = AES-256-GCM(VMK) blob（§1.5），AAD = `keyref v1 <US> vault-meta-key <US> <vault_id> <US> <item_id>` 与 `... vault-item-key ...`（US = `0x1f`）。

### 3.2 grant 誊本

```text
"KEYREF1" <NUL> "grant" <NUL> vault_id(hex) <NUL> device_id(hex) <NUL> item_id(hex) <NUL>
kind("view"|"use") <NUL> u64be(revision) <NUL> u64be(expires_at, 0=永不过期) <NUL>
hpke_enc <NUL> wrapped_key
```

- 签名者：owner。删除授权的誊本同样格式：`expires_at = 0`、`hpke_enc` 与 `wrapped_key` 为零长度。
- `hpke_enc`/`wrapped_key` 是 HPKE(X25519, recipient=CLI) 对 32 字节 meta key（view）或 item key（use）的封装，info 见 §3.7，AAD 空。
- 在场（非空）的 `hpke_enc` 必须恰好是该 KEM 的封装长度（X25519 为 32，P-256 为 65），`wrapped_key` 恰好 48 字节（v2 E，避免变长尾字段被任意字节伪造）。

### 3.3 directory 誊本

```text
"KEYREF1" <NUL> "directory" <NUL> vault_id(hex) <NUL> u64be(directory_revision) <NUL>
<设备记录按 device_id 的 hex 字节序升序排列，记录之间以单个 <NUL> 连接，末尾无 <NUL>>

每个设备记录：
device_id(hex) <NUL> kind("ios"|"cli"|"source"|"decider") <NUL> status("pending"|"active"|"revoked") <NUL>
hpke_kem("X25519"|"P-256") <NUL> hpke_public_key <NUL> sign_alg("ed25519"|"ecdsa-p256") <NUL>
sign_public_key <NUL> renewal_sign_public_key <NUL> grants_digest(32 字节原始 SHA-256) receiver_role(1 字节)
```

- 签名者：owner（多 owner 时任一在目录内的 owner）。`renewal_sign_public_key` 无则为零长度。
- **`receiver_role`**（v1.2 新增，design §14.4）：紧跟 `grants_digest` 之后的一个原始字节，**不带分隔符**。取值：`0x00` 无角色 / `0x01` 主接收端 / `0x02` 收件箱。记录之间仍只有一个 `<NUL>`，所以两设备的字节目次是：`记录一 … grants_digest(32) receiver_role(1)`、`<NUL>`、`记录二 … grants_digest(32) receiver_role(1)`（末条记录后无 `<NUL>`）。校验：非 `0x00` 的角色只允许出现在 `kind = ios` 的设备上；每个 vault 至多一条 `0x01`（超限 → `invalid_receiver_role`）。`0x02` 本轮保留给后面的安卓收件箱设备，MVP 不下发。
- **`grants_digest`** = SHA-256( 该设备当前全部 grant 誊本按 `(item_id hex 升序, kind 字节序升序)` 排序后顺序拼接 )。注意：`kind` 按字符串字节序，即 `"use"` 排在 `"view"` 之前。`source` 与 `decider` 设备（design v0.8 §14）永远没有 grants，其 `grants_digest` = SHA-256(空串)，即 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。

### 3.4 pair 誊本（配对完成，owner 签）

```text
"KEYREF1" <NUL> "pair" <NUL> vault_id(hex) <NUL> owner_sign_public_key <NUL>
nonce(hex) <NUL> device_id(hex) <NUL> hpke_kem <NUL> hpke_public_key <NUL>
sign_alg <NUL> sign_public_key <NUL> label(utf-8) <NUL> u64be(grant_count) <NUL>
<grant 誊本按 (item_id, kind) 排序顺序拼接>
```

### 3.5 pair-register 誊本（CLI Ed25519 签）

```text
"KEYREF1" <NUL> "pair-register" <NUL> nonce(16 字节原始) <NUL> proposed_name(utf-8)
```

### 3.6 session / vault-delete / vault-recovery 誊本

```text
session:      "KEYREF1" <NUL> "session" <NUL> device_id(hex) <NUL> challenge(32 字节原始)
vault-delete: "KEYREF1" <NUL> "vault-delete" <NUL> vault_id(hex) <NUL> challenge(32 字节原始)
vault-recovery: "KEYREF1" <NUL> "vault-recovery" <NUL> vault_id(hex) <NUL>
               recovery_wrap <NUL> recovery_kdf_json(utf-8) <NUL> recovery_sign_pub
```

`session` 由申请设备用自己的签名私钥签（Ed25519 或 ECDSA P-256，随设备）。`vault-delete`、`vault-recovery` 由 owner 签。

### 3.7 HPKE `info` 与 AAD 模板（`<US>` = `0x1f`）

```text
info 基底: "keyref v1" <US> <purpose> <US> <vault_id hex> <US> <recipient_device_id hex>
purpose ∈ { vmk, meta-key, item-key, one-time-item-key, audit-event-key, approval-request,
            source-message, one-time-message-key }
```

| 用途 | 完整 info / AAD |
| --- | --- |
| view 授权包裹 meta key | 基底，purpose=`meta-key` |
| use 授权包裹 item key | 基底，purpose=`item-key` |
| 一次性 item key（§7.1.4） | 基底 purpose=`one-time-item-key`，再接 `<US> item_id(hex) <US> approval_id(hex) <US> SHA-256(request_ciphertext 原始字节)`（第 12 节 D4：把 design §8.3 要求绑定的 `item_id` 并进 §9.1 的基底） |
| 一次性消息密钥（§6.28 消费） | 基底 purpose=`one-time-message-key`，再接 `<US> message_id(hex) <US> approval_id(hex) <US> SHA-256(request_ciphertext 原始字节)` |
| 审计事件密钥包裹 owner | 基底，purpose=`audit-event-key` |
| 消息密钥包裹 owner/决策器 | 基底，purpose=`source-message`（recipient = 该包裹的目标设备，§3.9） |
| 审批请求 HPKE 给 owner | 基底，purpose=`approval-request`（recipient = owner 设备） |
| VMK 包给 owner 设备 | 基底，purpose=`vmk` |
| 条目密文 AAD | `keyref v1 <US> secret <US> <vault_id> <US> <item_id>`（meta 换成 `meta`；**不含 revision**，design §9.1） |
| `vault_wrapped_*` AAD | `keyref v1 <US> vault-meta-key|vault-item-key <US> <vault_id> <US> <item_id>` |
| `recovery_wrap` AAD | `keyref v1 <US> recovery <US> <vault_id>` |
| 审计正文 AES 段 AAD | `keyref v1 <US> audit <US> <vault_id> <US> <device_id>(上报设备)` |
| 消息正文 AES 段 AAD | `keyref v1 <US> message <US> <vault_id> <US> <source_device_id>(上报设备)`——镜像审计信封绑定上报设备而非服务器生成的 id：source 在上传前就要构建信封，那时 message_id 尚不存在（D15） |

### 3.8 恢复码与派生（design §8.5）

- 恢复码载荷 = `vault_id(16 原始字节) ‖ 种子(32 字节 CSPRNG)`，整体 Crockford Base32 分组编码展示；解析即得两段。
- HKDF-SHA256：`prk = hkdf.Extract(sha256.New, ikm=种子, salt=nil)`；`recovery-kek = Expand(prk, "recovery-kek", 32)`；`recovery-sign` 的 Ed25519 种子 = `Expand(prk, "recovery-sign", 32)`。两条派生域分离、相互独立。
- `recovery_wrap` = AES-256-GCM(`recovery-kek`, VMK)，blob 与 AAD 见 §1.5/§3.7。
- `recovery_kdf_json` 固定为：`{"v":1,"kdf":"hkdf-sha256","salt":"","kek_info":"recovery-kek","sign_info":"recovery-sign"}`。以后加 Argon2id 口令副本时 `kdf` 换 `"argon2id"` 并增 `m/t/p/salt` 字段，服务器只透传不解释。

### 3.9 message-upload 誊本与消息信封（design v0.8 §14.3）

**上传誊本**（source 设备 Ed25519 签，服务器在落库前验证；protocol v2 C）：

```text
"KEYREF1" <NUL> "message-upload" <NUL> vault_id(hex) <NUL> source_device_id(hex) <NUL>
u64be(received_at, 设备自报的短信到达时间) <NUL> SHA-256(body)
```

末字段是信封**正文 blob**（下文的 `nonce ‖ ct ‖ tag`）的摘要，不是整个信封：正文按下面的信封格式切分得到（严格切分器，`proto/crypto.SplitMessageEnvelope`）。**包裹记录有意不签名**——owner 之后要补写决策器包裹（§6.30），若签名覆盖包裹则补写会使签名失效；伪造包裹也解不出消息密钥（HPKE 只对记录里钉死的目标设备有效）。誊本因此是定长的，与信封大小无关。

**验签方**：服务器在上传时验证；owner（iOS 收件箱 / 审批页）与决策器在**解密任何包裹之前**都要按 owner 签名目录中 `kind = source` 且 active 的条目重建誊本并验签——服务器不是信任锚，不验的行直接跳过，不展示、不审批、不投递。

**消息信封**（复用 D12 审计信封的构造，增加显式目标标识——多接收方类别（owner + 决策器）必须钉死对应关系）：

```text
u8 wrap_count ‖ 每个接收者记录（按 device_id 的 hex 字节序升序，记录间无分隔）:
    u16be(device_id_len=32) ‖ device_id(hex ascii, 32 字节) ‖
    u16be(enc_len) ‖ enc(KEM 封装，X25519 32B / P-256 65B) ‖
    wrapped(48B: HPKE 密文 = ct(32 字节消息密钥) ‖ tag(16)；与 §3.7 的其余包裹同为 `enc ‖ ct`，不另带 nonce——HPKE 自己派生 nonce)
‖ 消息正文 blob: nonce(12) ‖ ct ‖ tag(16)，AES-256-GCM(消息密钥, 明文 JSON)
```

每条包裹的 HPKE `info` = §3.7 基底，purpose=`source-message`，recipient = 该记录的 `device_id`；正文 blob 的 AAD = `keyref v1 <US> message <US> <vault_id> <US> <source_device_id>`（上报设备——source 在上传前构建信封，服务器生成的 `message_id` 尚不存在，故镜像审计信封 D12 绑定上报设备）。明文 JSON（≤ 4 KiB）：

```json
{ "v": 1, "sender": "10086", "body": "【XX银行】您的验证码 482913，5 分钟内有效。",
  "sim": "备用卡1", "received_at": 1790000000000 }
```

**决策器补投**（design §14.8）：决策器配对或委托开启后，owner 对**已落库且未过期**的消息计算 `HPKE(source-message, recipient=decider)` 包裹并通过 `PUT /v1/messages/:message_id/wraps` 补写（§6.30）——服务器不改写正文 blob，只追加目标记录；`device_id` 重复追加 → `409 revision_conflict`（复用码，语义=已存在）。

### 3.10 delegation 誊本（design v0.8 §14.8）

```text
"KEYREF1" <NUL> "delegation" <NUL> vault_id(hex) <NUL> u64be(delegation_revision) <NUL>
policy_json(utf-8)
```

- 签名者：owner（任一在目录内且 active 的 owner 密钥，Ed25519 或 ECDSA 随设备）。
- `policy_json` 是**签名的明文**（服务器可见其字节但只验签、不解析——这是委托功能新增的唯一明文面，已记入 design §6.4）：

```json
{ "v": 1, "senders": ["10086", "95533"], "max_age_min": 5,
  "per_cli_hourly": 10, "per_cli_daily": 50, "cli_devices": ["<device_id hex>"] }
```

- 空委托（撤回）= `policy_json` 为 `{"v":1}`：全部字段缺省 ⇒ 无 sender 白名单 ⇒ 决策器无可自动批准的对象。
- 决策器把 `delegation_revision` 与最新策略一起拉取（§6.31）；策略字节与签名必须先验后用（owner 公钥已钉死）。

### 3.11 approval-request 誊本（CLI Ed25519 签，protocol v2 A）

```text
"KEYREF1" <NUL> "approval-request" <NUL> vault_id(hex) <NUL> cli_device_id(hex) <NUL>
subject_kind <NUL> subject_id(hex) <NUL> u64be(expires_at) <NUL>
cli_ephemeral_public_key(32 原始字节) <NUL> H(request_ciphertext)
```

- 签名者：发起请求的 CLI（Ed25519）。
- `subject_kind` 取 `item` 或 `message`；`subject_id` 是条目 id 或消息 id。
- `expires_at` 是请求里的毫秒时间戳，服务器**原样落库**（不重算）。
- `cli_ephemeral_public_key`（X25519，32 字节）对**两种 subject 都必填**（§6.19）。
- `H(x)` = SHA-256(x)，32 字节原始值。末尾没有 NUL。
- 服务器：用请求字段加会话的 vault id、device id 重建誊本，在调用设备的公钥下验签（§6.19）。
- owner（iOS）与决策器：从行重建誊本，在**签名目录**里取该 CLI 的 Ed25519 公钥验签（设备必须 `kind = cli`、`status = active`）。owner 另外要求解密后的请求正文里的临时公钥等于行上的 `cli_ephemeral_public_key`。**决策器不解密请求正文，这个签名就是它所包裹的临时公钥的唯一认证来源。**
- 它取代的是「Ed25519 直接签 `request_ciphertext` 原始字节」——旧签名没有域分隔，也不覆盖临时公钥、subject 和过期时间。

### 3.12 approval-decision 誊本（owner ECDSA P-256 / 决策器 Ed25519 签，protocol v2 B）

```text
"KEYREF1" <NUL> "approval-decision" <NUL> vault_id(hex) <NUL> approval_id(hex) <NUL>
decision_device_id(hex) <NUL> decision <NUL> H(request_ciphertext) <NUL> H(wrap)
```

- 签名者：做出决定的设备——owner（ECDSA P-256）或被委托的决策器（Ed25519）。
- `decision` 取 `approved` 或 `denied`。
- `wrap` = `u16be(len(one_time_enc)) ‖ one_time_enc ‖ one_time_wrapped_key`（服务器落库的打包形式，§6.21）；`denied` 时为空串，`H(wrap)` = SHA-256("")。
- 服务器：在调用设备的公钥下验签，落库（approvals 表新增一列，按 `SchemaVersion` 迁移），并在 §6.22 返回。
- CLI 在状态为 `approved` 时、**解包之前**验签：在本地保存的 owner 签名目录里查 `decision_device_id`——必须 `status = active`，并且是 `kind = ios`，或在 subject 为 message 时是 `kind = decider`；重建誊本并验签。本地查不到该设备时同步一次、重查一次。**任何失败：退出码 13，不解包。**
- 理由：HPKE base 模式没有发送方认证，没有这个签名，服务器可以凭空造一个决定（对 message subject 可以直接塞进伪造的短信正文）。

### 3.13 配对确认 MAC（被配对设备验，protocol v2 D）

```text
pairing_mac = HMAC-SHA256(key = c,
    msg = "keyref v1 pair-confirm" <NUL> kind <NUL> pair 誊本字节)
```

- `c`：32 字节随机数，由被配对的设备（`cli` / `source` / `decider`）生成，标准 base64 放进二维码的 `c` 参数（§9.1），**永不发给服务器**——二维码是它到手机的唯一带外通道。
- `kind`：被接纳设备的类型，与 §6.17 的 `device.kind` 一致。
- `pair 誊本字节`：§3.4 的完整誊本字节串（含末尾拼接的 grant 誊本）。
- owner 在 `pair/complete` 时计算并提交（§6.17 必填字段 `pairing_mac`）；服务器不透明保存、经 §6.18 原样返回。
- 被配对设备用自己的 `c`、自己的 kind 和自己重建的誊本重算 MAC，**常数时间**比较；不一致就中止配对——在钉 owner 公钥、写入任何本地状态之前。
- 理由：§3.4 的签名只证明「这份誊本自洽」。服务器知道登记的设备公钥与 nonce，可以自造一把 owner key、自签一份自洽誊本，把「完成配对」冒充成另一个 owner——采集端会因此把短信封给服务器选的公钥。`c` 只在二维码里，服务器拿不到，MAC 是它伪造不了的唯一凭证。
- 签发方与验证方共用同一个实现（Go `proto/wire/pair_confirm.go`、Swift `KeyrefCore/Wire/Transcript.swift`）；`vectors.json` 的 `pair_confirm_mac` 是跨语言闸门。

---

## 4. 库可行性结论（2026-10-24 实测）

全部在本机 `go version go1.27.3 darwin/arm64` 上验证。`go.mod` 现状（v1.1 核对）：`cli` 与 `server` 写 `go 1.26.0`，`proto` 与 `tools/vectordump` 写 `go 1.25.0`（circl v1.6.5 的下限）；根 `go.work` 写 `go 1.26.0`。

| 库 | 拍板版本 | 核实命令 | 结果 |
| --- | --- | --- |---|
| `modernc.org/sqlite` | v1.61.0 | `go list -m -versions`；随后以 `CGO_ENABLED=0 go run` 实测 open/WAL/BLOB 往返/`VACUUM INTO` | ✅ 内嵌 SQLite 3.54.1，纯 Go，`VACUUM INTO` 在线备份可用（backup 子命令据此） |
| `golang.org/x/crypto`（`hkdf`、`acme/autocert`） | v0.58.0 | `go build golang.org/x/crypto/acme/autocert` 等 | ✅ BUILD-OK |
| `github.com/cloudflare/circl/hpke` | v1.6.5 | 拷贝模块后 `go test ./hpke/ -count=1`（含 RFC 9180 官方向量 `testdata/vectors_rfc9180_*.json.gz`） | ✅ `ok github.com/cloudflare/circl/hpke 0.516s`；**X25519（0x20）与 P-256（0x10）两种 KEM 都可用**（冒烟程序往返成功，enc 长度分别为 32 / 65 字节） |
| 标准库 `crypto`（ed25519、ecdsa P-256 ASN.1、AES-256-GCM）+ `net/http` | go1.27.3 | 同一冒烟程序 | ✅ 全部往返/验签通过 |
| `github.com/zalando/go-keyring` | v0.2.8 | darwin 编译 + 读源码 | ✅ macOS 走 `/usr/bin/security` 子进程、Linux 走 godbus（纯 Go），**两侧都不需要 CGO** |
| `github.com/awnumar/memguard` | v0.23.0 | `go build` | ✅ BUILD-OK；`NewBuffer`/`NewBufferFromBytes`/`WipeBytes`/`Purge` 覆盖 §12.2 守护分配需求 |
| `github.com/skip2/go-qrcode` | v0.0.0-20200617195104-da1b6568686e | 读源码 | ✅ `ToSmallString(bool)` 用 `▀▄█` 半块字符渲染，可直接写 stdout；**注意：无 tag 发布、2020 年后未更新**，按伪版本钉死；如需更换，替代 `mdp/qrterminal`（接口不同，改动仅限 `cli/internal/qr`） |

服务器侧不需要 HPKE / circl / keyring / memguard / qrcode——已按 design §10.1 与 §11 的校验清单核对：服务器只做签名验证与密文透传。

---

## 5. 端点总表

基址 `<origin>/v1`。除下表「鉴权」列写「无」的六个端点（`POST /v1/vaults`、`GET /v1/vaults/:vault_id/recovery`、`POST /v1/recovery/directory`、`POST /v1/pair/register`、`GET /v1/pair/status`、`GET /v1/healthz`；其中创建、恢复与配对走 IP 限流）外，一律 `Authorization: Bearer <token>`。`POST /v1/session` 用挑战签名代替 bearer。

| # | 方法与路径 | 鉴权 | 调用者 |
| --- | --- | --- | --- |
| 5.1 | `POST /v1/vaults` | 无（PoW + IP 限流，仅托管） | 新 iOS 设备 |
| 5.2 | `GET /v1/vaults/:vault_id/recovery` | 无（限流） | 任何人 |
| 5.3 | `POST /v1/recovery/directory` | 无（限流） | 恢复码持有者 |
| 5.4 | `PUT /v1/vault/recovery` | owner | iOS owner |
| 5.5 | `DELETE /v1/vaults/:vault_id` | owner（两步挑战） | iOS owner |
| 5.6 | `GET /v1/healthz` | 无 | 拨测 |
| 5.7 | `POST /v1/session` | 挑战签名 | 已登记设备 |
| 5.8 | `GET /v1/sync?cursor=` | bearer | 已登录设备 |
| 5.9 | `GET /v1/items/:item_id` | bearer | 已登录设备 |
| 5.10 | `PUT /v1/items/:item_id` | bearer + owner | iOS owner |
| 5.11 | `DELETE /v1/items/:item_id` | bearer + owner | iOS owner |
| 5.12 | `PUT /v1/grants` | bearer + owner | iOS owner |
| 5.13 | `DELETE /v1/grants` | bearer + owner | iOS owner |
| 5.14 | `GET /v1/grants/self` | bearer | CLI 设备 |
| 5.15 | `PUT /v1/directory` | bearer + owner | iOS owner |
| 5.16 | `POST /v1/pair/register` | 无（每分钟限流） | 配对中的 CLI |
| 5.17 | `POST /v1/pair/complete` | bearer + owner | iOS owner |
| 5.18 | `GET /v1/pair/status?nonce=` | 无 | 配对中的 CLI |
| 5.19 | `POST /v1/approvals` | bearer | CLI |
| 5.20 | `GET /v1/approvals?status=pending` | bearer + owner | iOS owner |
| 5.21 | `POST /v1/approvals/:approval_id/decision` | bearer + owner | iOS owner |
| 5.22 | `GET /v1/approvals/:approval_id` | bearer | 发起 CLI（轮询） |
| 5.23 | `POST /v1/audit` | bearer | 已登录设备 |
| 5.24 | `GET /v1/audit?cursor=` | bearer + owner | iOS owner |
| 5.25 | `GET /v1/account` | bearer + owner | iOS owner |
| 5.26 | `POST /v1/billing/apple` | bearer + owner | iOS owner（仅托管；自托管 404） |
| 5.27 | `PUT /v1/devices/push-token` | bearer + owner | iOS owner（APNs 令牌登记） |
| 5.28 | `POST /v1/messages` | bearer | source 设备（上传验证码） |
| 5.29 | `GET /v1/messages?since=` | bearer | iOS owner 或决策器 |
| 5.30 | `PUT /v1/messages/:message_id/wraps` | bearer + owner | iOS owner（决策器补投） |
| 5.31 | `DELETE /v1/messages/:message_id` | bearer + owner | iOS owner |
| 5.32 | `PUT` / `GET /v1/delegation` | bearer（PUT + owner） | iOS owner 写；全部设备读 |

通用校验（每个端点都做）：设备属于该 vault 且 `status = active`（§8.4 送达语义的例外除外）；`kind = cli` 调 5.10/5.11/5.12/5.13/5.15/5.4/5.5/5.27 → `403 forbidden`；`kind = source` 只能调 5.28、会话续期与 5.8（仅目录）；`kind = decider` 只能调 5.29、5.32 读、5.20（仅 message subject）与 5.21（subject 必须为 `message:` 前缀）；签名字段在该设备当前公钥下验证；正文上限 §1.2。

## 6. 端点明细

### 6.1 `POST /v1/vaults` — 创建保险库

托管部署（`KEYREF_ENFORCE_QUOTAS=1`）先走 §10.1 PoW：不带 `pow` 字段首次请求 → `401 {"error":"pow_required","challenge":"<b64 32B>","expires_at":1790000000000}`；带解答重试。

请求：

```json
{
  "vault_id": "5f0c…(32 hex)",
  "device": {
    "device_id": "…(32 hex)", "kind": "ios",
    "hpke_kem": "P-256", "hpke_public_key": "<b64 65B>",
    "sign_alg": "ecdsa-p256", "sign_public_key": "<b64 65B>",
    "label": "iPhone", "renewal_sign_public_key": "<b64 32B ed25519 公钥>"
  },
  "recovery_wrap": "<b64 nonce‖ct‖tag>",
  "recovery_kdf_json": "{\"v\":1,\"kdf\":\"hkdf-sha256\",…}",
  "recovery_sign_pub": "<b64 32B>",
  "directory_revision": 1,
  "directory_signed": "<b64：§3.3 誊本原文>",
  "signature": "<b64 ECDSA ASN.1，签 directory 誊本>",
  "pow": { "challenge": "<b64，服务器签发>", "nonce": "<b64 8B u64be>" }
}
```

响应 `201 {"vault_id":"…"}`。随后设备用 §6.7 换会话。托管写 `plan=free`，自托管 `plan=unlimited`；客户端传的 `plan` 一律忽略。错误：`invalid_field`、`pow_required`、`rate_limited`（IP 每 /32 或 /64 每天 3 个）、`quota_exceeded`（全局预算触顶拒新库）。

### 6.2 `GET /v1/vaults/:vault_id/recovery` — 拉恢复材料

无鉴权、按 IP 与按 vault 限流。响应：

```json
{ "vault_id": "…", "recovery_wrap": "<b64>", "recovery_kdf_json": "{…}",
  "recovery_sign_pub": "<b64>",
  "directory_revision": 7,
  "directory_signed": "<b64 誊本>", "directory_signature": "<b64>" }
```

### 6.3 `POST /v1/recovery/directory` — 恢复接管

请求（两个签名覆盖**同一份 §3.3 directory 誊本**字节：恢复签名权威 + 新 owner 密钥，design §8.5「共同签署」）：

```json
{
  "vault_id": "…",
  "directory_revision": 8,
  "directory_signed": "<b64：接管后的新目录誊本>",
  "recovery_signature": "<b64 Ed25519，用恢复码派生私钥>",
  "owner_signature": "<b64 ECDSA ASN.1，新 owner>"
}
```

服务器用存储的 `recovery_sign_pub` 验 `recovery_signature`、用誊本内新 owner 公钥自洽验证 `owner_signature`，落库并追加 `directory:` 变更；旧设备会话立即失效。接管目录同样按 §6.15 的三条规则生效：没列出的设备一律置为 `revoked`，列出 `revoked` 设备的其他状态返回 `400 invalid_field`。**服务器不检查「旧设备是否都写成了 revoked」**——它只按目录应用；把旧设备写成 revoked 是构造接管目录的客户端（iOS）的责任。响应即新 owner 会话（形状同 §6.7 第二步）：

```json
{ "token": "<64 hex>", "expires_at": 1790000000000,
  "origin": "https://sync.example", "plan": "free",
  "limits": { "items": 20, "devices_ios": 1, "devices_cli": 1,
              "devices_source": 1, "devices_decider": 1, "messages_pending": 20,
              "storage_bytes": 1048576,
              "audit_retention_days": 7, "audit_max_events": 100,
              "requests_per_day": 500, "requests_per_minute": 30 } }
```

### 6.4 `PUT /v1/vault/recovery` — 替换恢复材料（owner 签）

请求 `{"recovery_wrap":…,"recovery_kdf_json":…,"recovery_sign_pub":…,"signature":"<b64 §3.6 vault-recovery 誊本>"}` → `204`。错误：`bad_signature`、`forbidden`（CLI）。

### 6.5 `DELETE /v1/vaults/:vault_id` — 两步删除

第一步：DELETE 不带正文 → `401 {"error":"delete_challenge_required","challenge":"<b64 32B>","expires_at":…}`（挑战 60 秒、单次）。
第二步：DELETE `{"challenge":"<b64>","signature":"<b64 owner 签 §3.6 vault-delete 誊本>"}` → `204`，级联清空全部行。错误：`bad_signature`、`unauthorized`（挑战过期）。

### 6.6 `GET /v1/healthz` — 见 §10.2。

### 6.7 `POST /v1/session` — 挑战换令牌（两步同路径）

第一步 `{"device_id":"…"}` → `200 {"challenge":"<b64 32B>","expires_at":…}`（60 秒、单次）。
第二步 `{"device_id":"…","challenge":"<b64 原样返回>","signature":"<b64 设备签名私钥签 §3.6 session 誊本>"}` →：

```json
{ "token": "<64 hex>", "expires_at": 1790000000000,
  "origin": "https://sync.example", "plan": "unlimited", "limits": { …同 §6.3… } }
```

令牌 12 小时有效，续期即重新走两步。数据库只存 `token_hash = hex(SHA-256(token 原始 32 字节))`。错误：`unauthorized`、`device_revoked`（revoked 设备不发新令牌）。（`/v1/session` 本身没有限流——挑战与令牌都不占配额；这是已知残余，见 design §15。）

### 6.8 `GET /v1/sync?cursor=<int>` — 增量同步（§8 详述）

### 6.9 `GET /v1/items/:item_id` — 按需单条

响应行 = §8.3 的 item `data` 对象，按调用者身份过滤（owner 全量；CLI 有 view 授予即给 `meta_ciphertext` 与 `secret_ciphertext`——审批条目只有 view 授予，也要能拿到密文在批准后解开；`vault_wrapped_*` 只给 owner）。四个 `*_digest` 字段始终在场，按落库的行计算（v2 E）。错误：`not_found`、`forbidden`（CLI 无 view 授予）。

### 6.10 `PUT /v1/items/:item_id` — 上传新 revision（owner）

```json
{
  "revision": 4, "tombstone": false,
  "meta_ciphertext": "<b64>", "secret_ciphertext": "<b64>",
  "vault_wrapped_meta_key": "<b64>", "vault_wrapped_item_key": "<b64>",
  "writer_device_id": "<hex>",
  "signature": "<b64 ECDSA，签 §3.1 誊本>"
}
```

服务器要求 `revision == 已存值 + 1`，并从未裁剪的请求体重建 §3.1 v2 誊本验签，否则 `409 revision_conflict` / `403 bad_signature`。响应 `200 {"revision":4,"updated_at":1790000000000}`。条目更新追加一条 `item:` 变更；**不**自动追加合成 grant 变更（grant 写入时才有合成 item 变更，design §6.3），CLI 靠本条 item 变更刷新本地行。错误信息不得回显密文字段。

**仅本机条目**（design v0.7 §6.6）：`secret_ciphertext` 与 `vault_wrapped_item_key` 省略（或为零长度），行内只落 meta——密文只在 owner 手机本地。仅本机条目不得拥有 `use` 授予：`PUT /v1/grants` 对该条目建/续 `use` → `400 local_item_grant_conflict`；带 `use` 授权的条目改为本地 → 同错误。

### 6.11 `DELETE /v1/items/:item_id` — tombstone（owner）

请求 `{"revision":5,"signature":"<b64 §3.1 v2 誊本，tombstone 标志字节 0x01，四个密文字段为零长度>"}` → `204`。服务器置 tombstone、**删除该条全部 grants**、逐设备追加 `grant:` 删除变更与 `item:` 变更（design §6.3）。

### 6.12 `PUT /v1/grants` — 写入/更新授予（owner）

```json
{ "grants": [ { "device_id":"…","item_id":"…","kind":"use",
    "hpke_enc":"<b64>","wrapped_key":"<b64>","expires_at":1790000000000,
    "revision":3,"signature":"<b64 §3.2 誊本>" } ] }
```

每行 revision 须严格大于已存值（推荐 +1）。服务器为每个 grant 追加合成 `item:<item_id>` 变更（design §6.3）。响应 `200 {"applied":1}`。

### 6.13 `DELETE /v1/grants`（owner）

`{"device_id":"…","item_id":"…","kind":"use","revision":4,"signature":"<b64 §3.2 删除形态誊本>"}` → `204`；追加对该设备可见的 `grant:` 变更。

### 6.14 `GET /v1/grants/self`（CLI 对账）

```json
{ "grants": [ { …§3.2 行的全部字段… } ],
  "grants_digest": "<b64 32B，客户端自行重算比对目录>",
  "directory_revision": 7 }
```

digest 与目录不符时 CLI 停用授予并提示（design §9.1/§10.6）。

### 6.15 `PUT /v1/directory`（owner）

`{"directory_revision":8,"directory_signed":"<b64 §3.3 誊本>","signature":"<b64>"}` → `200 {"directory_revision":8}`。要求 revision 严格递增；签名用**上一版目录内**的 owner 公钥验证。撤销设备后其会话立即按 §8.4 送达语义收缩。

誊本是该库里**设备行的唯一真相来源**：

- 目录里没列出的设备行，在同一次写入里一律置为 `revoked`（「省略即撤销」）。
- `revoked` 是终态：已存为 `revoked` 的设备，新目录如果把它的状态写成别的值，返回 `400 invalid_field`，整次写入回滚，revision 不被消耗。重新配对会生成新的 `device_id` 和密钥。
- 计划设备上限按新目录投影计算：目录里 `active` 的记录数，被省略的行一律不计入。

### 6.16 `POST /v1/pair/register`（CLI，无鉴权）

```json
{ "nonce": "<hex 32>", "hpke_kem": "X25519", "hpke_public_key": "<b64 32B>",
  "sign_alg": "ed25519", "sign_public_key": "<b64 32B>",
  "proposed_name": "build-agent-1", "signature": "<b64 Ed25519，签 §3.5 誊本>" }
```

→ `201 {"expires_at":…}`。服务器存 `nonce_hash = hex(SHA-256(nonce 原始 16 字节))`，行 10 分钟有效、一次性；每分钟每 IP 限流。

### 6.17 `POST /v1/pair/complete`（owner）

```json
{ "nonce": "<hex>",
  "device": { "device_id":"…","kind":"cli","hpke_kem":"X25519",
              "hpke_public_key":"<b64>","sign_alg":"ed25519","sign_public_key":"<b64>",
              "label":"build-agent-1" },
  "grants": [ { "item_id":"…","kind":"view","hpke_enc":"…","wrapped_key":"…",
                "expires_at":…,"revision":1,"signature":"…" } ],
  "signature": "<b64 owner 签 §3.4 pair 誊本>",
  "pairing_mac": "<b64 32B，§3.13 配对确认 MAC>" }
```

→ `204`。`pairing_mac` 必填；服务器只检查 32 字节长度，原样存进配对会话、经 §6.18 返回（它无从验算，`c` 不经过服务器）。服务器核对 nonce 行未消费、设备公钥与登记一致、owner 签名通过，写 `devices`（status=active）与 `grants`，追加变更；`pair_sessions.consumed_at` 置位。错误：`invalid_field`（`pairing_mac` 缺失或不是 32 字节）、`pair_expired`、`bad_signature`。

### 6.18 `GET /v1/pair/status?nonce=<hex>`（CLI 轮询）

`200 {"status":"pending"}` 或：

```json
{ "status": "complete", "vault_id": "…", "device_id": "…",
  "owner_sign_public_key": "<b64 65B ECDSA 公钥>",
  "pairing_signature": "<b64 §3.4 誊本的 owner 签名>",
  "pairing_mac": "<b64 32B，§6.17 提交的那份>",
  "directory_revision": 8, "directory_signed": "<b64>", "directory_signature": "<b64>",
  "grants": [ { …该设备的初始授予… } ] }
```

CLI 先验 `pairing_signature`，再用自己的 `c` 重算并常数时间比对 `pairing_mac`（§3.13）——两者都通过才把 `owner_sign_public_key` 钉死进本地配置；此后只接受这把 key（或其签名目录接纳的后续 owner key）签的目录与授予。MAC 不匹配视为配对失败、不写入任何本地状态。错误：`pair_expired`（过期或不存在——同码，不区分）。

### 6.19 `POST /v1/approvals`（CLI）

```json
{ "item_id": "…", "request_ciphertext": "<b64 enc‖ct，HPKE 给 owner>",
  "request_signature": "<b64 Ed25519，签 §3.11 誊本>",
  "cli_ephemeral_public_key": "<b64 32B>",
  "expires_at": 1790000000000 }
```

`request_signature` 覆盖的是 **§3.11 誊本**（含 subject、过期时间、一次性公钥与密文摘要），不再是 `request_ciphertext` 的原始字节。服务器用请求字段加会话的 vault id、device id 重建誊本，在调用设备的公钥下验签；验不过 → `403 bad_signature`，不落库。

`cli_ephemeral_public_key`（请求内一次性 X25519 公钥的 32 字节原始值）**对两种 subject 都必填**，落库，并在 §6.20 的行里返回：owner 用它和密文内的那把做交叉核对，决策器靠 §3.11 签名确认它可信。

**消息消费形态**（design v0.8 §14.5）：`item_id` 省略，改传 `message_id`（32 hex，指向一条 `status = active` 的消息）。明文 JSON 的 `item_id` 字段换为 `message_id`，其余不变。同一 `message_id` 同时最多一个未终结审批：存在 pending 时 → `409 approval_not_pending`。

→ `201 {"approval_id":"…","expires_at":…}`。`expires_at − now ≤ 120000`（CLI `--timeout`）。正文 ≤ 8 KiB、每库 pending ≤ 10，超出 `413` / `429 quota_exceeded`。`request_ciphertext` = `enc(32B 一次性 X25519) ‖ ct‖tag`；明文 JSON：

```json
{ "v": 1, "cli_device_id": "…", "item_id": "…", "argv": ["curl", "https://…"],
  "refs": ["openai-prod"], "injection": "env",
  "hosts": ["api.openai.com"], "ephemeral_kem": "X25519",
  "ephemeral_public_key": "<b64 32B>", "created_at": 1790000000000,
  "cwd": "/Users/me/project", "executable": "/usr/bin/curl",
  "executable_real": "/usr/bin/curl", "executable_layers": ["curl"],
  "pass_names": [], "env_names": ["OPENAI_API_KEY"],
  "fd_targets": [], "fd_template": "" }
```

**执行上下文字段**（2026-11 评审）：argv 原文看不出来的部分随请求一起交给审批人——`cwd`（子进程的工作目录）、`executable`（keyref 实际 spawn 的绝对路径：argv0 经 PATH 解析后、符号链接解析前的那个文件）、`executable_real`（符号链接与 shebang 一路解析后内核真正运行的程序）、`executable_layers`（argv0 与每个 shebang 解释器的小写 basename 依次排列；命令策略逐层检查的就是这条链）、`pass_names`（`--pass` 从环境转发的变量名）、`env_names`（`--env` 注入秘密的变量名）、`fd_targets`（`--fd` 载荷写入的子进程 fd 编号）、`fd_template`（`--fd-template` 原文）。八个字段**总是出现**，未使用时为空字符串或空数组。它们只含名字、路径和模板，**绝不含秘密值**；又因为它们位于 HPKE 密文之内、§3.11 签名覆盖密文摘要，服务器无法篡改。iOS 审批页把它们与命令原文同屏展示（ios-ui.md）。

### 6.20 `GET /v1/approvals?status=pending`（owner；决策器仅见 message subject）

`{"approvals":[{"approval_id":"…","cli_device_id":"…","item_id":"…","message_id":"…(消息类才有)","cli_ephemeral_public_key":"…(两种 subject 都有)","request_ciphertext":"…","request_signature":"…","created_at":…,"expires_at":…}]}`。iOS 解开后**先验 CLI 签名**（对 §3.11 誊本，设备须在签名目录里且 `kind=cli`、`status=active`），再核对正文里的临时公钥与行上的一致，然后才展示；决策器不解开 request_ciphertext，按 §3.10 的委托策略与明文元数据评估，但**必须先验 §3.11 签名**——行上的 `cli_ephemeral_public_key` 只有验过签名才可信。

### 6.21 `POST /v1/approvals/:approval_id/decision`（owner 或决策器）

同意：`{"decision":"approved","one_time_enc":"<b64>","one_time_wrapped_key":"<b64 ct‖tag>","decision_signature":"<b64 §3.12 誊本的签名>"}`。
包裹 = HPKE(X25519, recipient=请求的临时公钥, info=§3.7 一次性模板, AAD 空)；服务器置 `expires_at = now + 60000`。拒绝：`{"decision":"denied","decision_signature":"<b64>"}`。→ `204`。错误：`invalid_field`（缺 `decision_signature` 或签名验不过）、`approval_not_pending`、`forbidden`（决策器对非 message subject 的审批做决定——服务器强制，design §14.8）。服务器把**签署这次决定的设备 id**（owner `kind=ios` 或决策器 `kind=decider`）和**这次决定的签名**写进审批行，同意与拒绝都记（schema v6 / v7，design v0.8 §14.5/§14.8），由 §6.22 轮询回传、CLI 转写进审计事件。

`decision_signature` **必填**（同意与拒绝都要）：它是决定设备对 §3.12 誊本的签名，服务器在调用设备的公钥下验签（算法按设备：owner ECDSA P-256，决策器 Ed25519）。没有它，HPKE base 模式就没有发送方认证——服务器可以凭空造一个决定。

**载荷三种**（design v0.7 §6.6、v0.8 §14.5）：同步条目照旧包 32 字节 item key；**仅本机条目**（`items.secret_ciphertext` 为 NULL，design §6.6）包该条目的 secret **值本身**——owner 解开本地包裹后的明文字节（UTF-8 的 value 字符串，≤64 KiB；不是 §3.7 的 secret JSON 包装，也不是密文）。CLI 的 unwrap 结果直接作为注入值。**消息消费**（design v0.8 §14.5）包**该消息的明文 JSON**（§3.9 的 `{"v":1,"sender":…,"body":…,"sim":…,"received_at":…}` 原始字节，≤4 KiB）——消息密钥不出 owner/决策器域，CLI 解开即得正文。decision 端点正文上限 **96 KiB**（审批请求仍 8 KiB）。CLI 按本地缓存中该条目是否缺 `secret_ciphertext`、审批请求是否带 `message_id` 区分三种投递。仅本机条目不得拥有 `use` 授权（服务器互斥校验，错误码 `local_item_grant_conflict`）。

### 6.22 `GET /v1/approvals/:approval_id`（发起 CLI 轮询）

`{"approval_id":"…","status":"pending"|"denied"|"expired"|"consumed"}`；首次轮询到 `approved` 时**原子**返回包裹并置 `consumed`、清包裹字节：

```json
{ "approval_id": "…", "status": "approved",
  "one_time_enc": "<b64>", "one_time_wrapped_key": "<b64>", "expires_at": 1790000000060,
  "decision_device_id": "…(32 hex，可选)", "decision_signature": "<b64(可选)>" }
```

**可选字段 `decision_device_id`**（32 hex）：签署该次 decision 的设备——owner（`kind=ios`）或被委托的决策器（`kind=decider`，design v0.8 §14.5/§14.8）。服务器只在 decision 被接受时写入（§6.21），因此 `pending` 行与从未做出决定的行（如 `expired`）**省略**该字段。

**可选字段 `decision_signature`**：与 `decision_device_id` 同时出现，是那次决定对 §3.12 誊本的签名。CLI 在 `approved` 时**先验签再解包**：在本地保存的签名目录里查 `decision_device_id`（须 `status=active`，且 `kind=ios`；message subject 时可以是 `kind=decider`），重建 §3.12 誊本并验签。查不到该设备时同步一次、重查一次。验不过 → 退出码 13，不解包。

轮询间隔 < 2 秒 → `429 rate_limited`；轮询**不计**每日请求配额（design §8.3）。这个端点做自己的鉴权（不走 `authorize`，否则会计入配额）：非 active 设备（含 revoked）→ `401 unauthorized`，**不是** `403 device_revoked`——发起轮询的 CLI 在等待自己的审批时被撤销，得到的就是 401。

### 6.23 `POST /v1/audit`（已登录设备）

```json
{ "ciphertext": "<b64 审计信封：u8 wrap_count ‖ 每.owner{ u16be enc_len ‖ enc ‖ 48B 包裹的事件密钥 } ‖ nonce‖ct‖tag（AES-GCM(事件密钥) 正文）>" }
```

MVP `wrap_count=1`（单 owner；Phase 2 多 owner 时按 owner device_id 升序追加包裹，信封格式不变）。事件密钥 32 字节随机；包裹 info = §3.7 `audit-event-key`。明文 JSON 字段见 design §7.7（无秘密值）：`time`、`device_id`、`refs`、`injection`、`argv`、`allow_argv`、`policy_result`、`child_exit`、`redactions`，加上两个可选键——`approval_result`（走过审批时的结论）与 **`decision_device_id`**（32 hex，签署那次审批决定的设备：owner `kind=ios` 或决策器 `kind=decider`，design v0.8 §14.5/§14.8）。`decision_device_id` 由 CLI 从 §6.22 同名字段回填，没有审批决定的尝试省略它；`sms:<message_id>` 这类被消费对象已经在 `refs` 里，不另设消息 id 字段。→ `201 {"seq":42}`。正文 ≤ 4 KiB。审计与待审批密文计入存储口径（design §10.5）。

### 6.24 `GET /v1/audit?cursor=<int>`（owner）

`{"events":[{"seq":42,"device_id":"…","created_at":…,"ciphertext":"…"}],"cursor":50,"has_more":false}`，每页 ≤ 200，cursor 为该 vault 的 `audit_events.seq`。

### 6.25 `GET /v1/account`（owner）

```json
{ "plan": "free", "plan_expires_at": null,
  "limits": { "items":20,"devices_ios":1,"devices_cli":1,"storage_bytes":1048576,
              "audit_retention_days":7,"audit_max_events":100,
              "requests_per_day":500,"requests_per_minute":30 },
  "usage": { "items":3,"devices_active":2,"storage_bytes":18432,
             "audit_events":12,"requests_today":45 } }
```

自托管不强制配额时 `plan="unlimited"`、`limits` 各字段为 `null`。

### 6.26 `POST /v1/billing/apple`（owner，仅托管）

`{"transaction_id":"…"}` → `200 {"plan":"plus","plan_expires_at":…}`；自托管 `404 not_found`。服务器自行调 App Store Server API，不回显收据。

### 6.27 `PUT /v1/devices/push-token` — 登记 APNs 推送令牌（owner）

```json
{ "token": "<hex、偶数长度、32–200 字符（APNs 当前 64）>", "env": "sandbox" | "production" }
```

→ `204`。令牌写到**调用者自己的**设备行（owner 即 `kind=ios`；`kind=cli` → `403 forbidden`），重复登记覆盖旧值；`env` 只校验取值、不落库。错误：`unauthorized`、`forbidden`、`invalid_field`（`env` 非 `sandbox|production`、token 非 hex 或长度越界）。登记只存令牌；新审批落库后，服务器向各 owner 设备已登记的 token **尽力推送**（best-effort，失败只记日志；APNs 回 410 即清除该 token，design §8.3）。未配置 APNs 凭据的部署照常接受登记，只是不推送。新消息落库后走同一推送面：正文固定为「收到新的验证码」，**不带 sender 与任何短信内容**（design §14.4，锁屏是半公开表面）。

### 6.28 `POST /v1/messages` — 上传验证码（source 设备）

```json
{ "envelope": "<b64 §3.9 信封>", "request_signature": "<b64 Ed25519，签 §3.9 message-upload 誊本>",
  "received_at": 1790000000000 }
```

→ `201 {"message_id":"…","expires_at":…}`，`message_id` 由服务器生成，`expires_at = 服务器 now + 24h`（固定 TTL，design §14.3；客户端自报的过期时间不存在）。服务器校验顺序（protocol v2 C）：`kind = source` → 请求体上限（envelope ≤ 16 KiB，解码时）→ 信封形状（按 §3.9 严格切分出正文）→ 誊本验签（vault、source_device_id、received_at、`SHA-256(body)`，对该设备当前 Ed25519 公钥）→ 该设备 active 消息数 < 档位上限（托管）→ 该设备当日上传 < 100（托管）。配额只在**验签通过之后**计费：被拒的上传不占额度。错误：`forbidden`（非 source）、`invalid_field`（信封切不出正文）、`bad_signature`、`body_too_large`、`quota_exceeded`。落库后向 owner 设备的已登记 token 尽力推送（§6.27 的消息推送面）。

### 6.29 `GET /v1/messages?since=<int>`（owner 或决策器）

`since` 是十进制的 `created_at` 单调游标（0 = 全量）。响应：

```json
{ "messages": [ { "message_id": "…", "source_device_id": "…", "status": "active|consumed",
    "envelope": "<b64>", "request_signature": "<b64 §3.9 上传签名>", "received_at": 1790000000000,
    "created_at": 1790000000000, "expires_at": 1790000000000 } ],
  "cursor": 1790000001234, "has_more": false }
```

只返回 `expires_at > now` 的行，按 `created_at` 升序，每页 ≤ 200，`cursor` = 本页最大 `created_at`。**不进 §8 的 changes 日志**（90 天滚动日志不被 24 小时消息污染，design §14.3）；拉取时顺带删除已过期的行（与审计清理同性质）。`received_at` 是设备自报值，仅作展示参考；排序、游标与「最大年龄」策略一律用服务器 `created_at`。每行回传 `request_signature`（protocol v2 C）：owner 与决策器按 owner 签名目录重建 §3.9 誊本、验签之后才解密——服务器会代替所有设备验签，但服务器不是信任锚，不验的行直接跳过。

### 6.30 `PUT /v1/messages/:message_id/wraps` — 决策器补投（owner）

```json
{ "wraps": [ { "device_id": "<decider device_id hex>", "hpke_enc": "<b64>", "wrapped_key": "<b64>" } ] }
```

→ `204`。owner（iOS）在决策器配对或委托开启后，把**未过期**消息的消息密钥按 §3.9 信封记录格式补包给决策器。服务器按信封格式解析、按 `device_id` 升序重排后重写 envelope；目标已存在 → `409 revision_conflict`；消息已过期/不存在 → `404`。服务器不解任何包裹。

### 6.31 `DELETE /v1/messages/:message_id` 与 `PUT` / `GET /v1/delegation`

- `DELETE /v1/messages/:message_id`（owner）→ `204`：立即删除（收件箱手动删除，design §14.4）；不存在 → `404`。
- `PUT /v1/delegation`（owner）：`{"delegation_revision":3,"delegation_signed":"<b64 §3.10 誊本>","signature":"<b64>"}` → `204`。要求 `delegation_revision` 严格大于已存值，签名用**当前目录内 active 的 owner 公钥**验证（与 §6.15 目录验证同规）。
- `GET /v1/delegation`（任意 active 设备）：`{"delegation_revision":3,"delegation_signed":"<b64>","signature":"<b64>"}`；未委托时 `{"delegation_revision":0,"delegation_signed":null,"signature":null}`。**`signature` 必须回传**：决策器要「先验后用」，而服务器不是信任锚——只存字节不给签名，等于让决策器信服务器的一面之词（2026-11-02 修正，服务器原本验完即丢）。owner 公钥已在配对时钉死（§9.2）。

---

## 7. 关键流程串起来

### 7.1 审批一次性包裹（design §8.3）

1. CLI 生成一次性 X25519（用后即弃），构造 §6.19 明文，HPKE 给 owner（info=§3.7 `approval-request`），Ed25519 签 **§3.11 誊本**（含 subject、过期时间、一次性公钥、密文摘要），`POST /v1/approvals`。
2. 服务器重建誊本并验 CLI 签名（设备 active、在目录内）→ 不过 `403 bad_signature` 才落库。
3. iOS 拉取 → 解开 → 验 CLI 签名（对 §3.11 誊本）+ 核对临时公钥 → Face ID → `POST decision` 附 HPKE(recipient=临时公钥, info=§3.7 one-time 模板) 的 item key 包裹 + 对 §3.12 誊本的签名。
4. CLI 每 2 秒轮询 `GET /v1/approvals/:id`，取走包裹（原子 consumed），**先验决定签名（§3.12）再解包**，解开 item key，`exec`，结束即 zeroize（memguard）。

### 7.2 会话挑战（design §8.2）

§6.7 两步。令牌盗用的后果边界、`token_hash` 存储已在 design §8.2 固定。

### 7.3 恢复接管（design §8.5）

解析恢复码 → `GET /v1/vaults/:id/recovery` → 本地 HKDF 派生、AEAD tag 判对错 → 新 owner 密钥 + 恢复签名私钥**共同签**同一份新目录誊本 → `POST /v1/recovery/directory` → 拿新 owner 会话 → `cursor=0` 引导（§8.1）→ 旧设备会话失效 → 重新配对 CLI 并按 §8.4 默认动作轮换曾被旧设备用过的 item key。

---

## 8. sync 线格式

### 8.1 请求与响应

`GET /v1/sync?cursor=<int>`（cursor 为十进制整数，`0` 表示从零引导）：

```json
{ "cursor": 1051, "has_more": false,
  "changes": [ { "seq": 1051, "entity": "item", "entity_id": "item:0a1b…(hex)",
                 "created_at": 1790000000000, "data": { …见 8.3… } } ] }
```

- 每页 ≤ 100 条，按 `seq` 升序；还有更多时 `has_more=true`，客户端带返回的 cursor 续拉。
- `cursor=0`：服务器把该设备**当前可见现状**（当前 revision 的 items、当前 grants、当前目录、相关审批状态）作为一批合成变更返回，新 cursor 直接跳到日志末尾——不重放历史（design §10.6）。
- cursor 小于 changes 日志仍保留的最小 `seq`（90 天滚动清理）→ `409 {"error":"cursor_stale"}`，客户端重置 0 重新引导。

### 8.2 `entity` 与 `entity_id`（design §6.3，全部字段为 hex，`:` 不出现在值内）

| entity | entity_id | 触发 |
| --- | --- | --- |
| `item` | `item:<item_id>` | 条目创建/更新/tombstone；grant 写入时的合成变更 |
| `grant` | `grant:<device_id>:<item_id>:<kind>` | 授予写入/更新/删除 |
| `device` | `device:<device_id>` | 设备行变化（配对生效、撤销） |
| `directory` | `directory:<vault_id>` | 新目录誊本落库 |
| `approval` | `approval:<approval_id>` | 与该设备相关的审批状态变化（状态摘要，不含密文） |

### 8.3 `data` 形状（按调用者过滤）

- item（owner 全量；CLI：`meta_ciphertext` 需 view、`secret_ciphertext` 需 use、`vault_wrapped_*` 不给 CLI；四个 `*_digest` 字段**始终在场**，按落库的行计算，v2 E）：
  `{ "vault_id":"…","item_id":"…","revision":4,"tombstone":false,"meta_ciphertext":"…","secret_ciphertext":"…","vault_wrapped_meta_key":"…","vault_wrapped_item_key":"…","meta_digest":"…","secret_digest":"…","vault_wrapped_meta_key_digest":"…","vault_wrapped_item_key_digest":"…","writer_device_id":"…","signature":"…","updated_at":… }`
- grant：`{ "device_id":"…","item_id":"…","kind":"use","hpke_enc":"…","wrapped_key":"…","expires_at":…,"revision":3,"signature":"…" }`；删除行为 `{ "device_id":"…","item_id":"…","kind":"use","deleted":true,"revision":4 }`。
- device：`{ "device_id":"…","kind":"cli","status":"revoked","label":"…","created_at":…,"revoked_at":… }`。
- directory：`{ "directory_revision":8,"directory_signed":"<b64>","directory_signature":"<b64>" }`。
- approval：`{ "approval_id":"…","status":"consumed" }`。

可见性（design §10.6）：active CLI 见自己的 grants、指向的 items、目录、相关审批；active owner 见全部 items/grants/目录/审批；**revoked 设备**只目录、tombstone 与指向自己的 grant 删除——其余端点一律 `403 device_revoked`，唯一例外是 §6.22 的审批轮询（自己的鉴权，非 active → `401 unauthorized`）。客户端在解密前验签（v2 F 的 owner 密钥链：item 按 `writer_device_id` 选 key，grant 逐个试 active owner key，新目录按已保存目录里的 active owner key；没有已保存目录时只认 pin 住的 key）。CLI 验不过的行跳过并在 stderr 打一行警告，验不过的目录中止本次同步；iOS 抛 `SyncError.tampered`（本地不存在的条目的 tombstone 直接忽略），并保留旧数据。

---

## 9. 配对二维码与 CLI 展示

### 9.1 二维码负载（design §8.1）

```text
keyref://pair?v=1&k=<b64 X25519 hpke_public_key>&s=<b64 ed25519 sign_public_key>&n=<hex nonce 32>&name=<percent-encoded utf-8, ≤32 字节>&u=<percent-encoded origin, https>[&t=<cli|source|decider>]&c=<b64 32B pairing secret>
```

- `k`、`s`、`c` 为标准 Base64 后按 RFC 3986 percent-encode 进 query（`+`、`=`、`/` 必须转义）；`n` 是 hex，无需转义；`name`、`u` 是普通 percent-encoding。iOS 必须先 percent-decode 再 base64 解码。
- `t` 是 v1.2 新增的可选参数，声明请求配对的设备种类；缺省为 `cli`（旧二维码兼容）。iOS 扫到 `t=source` 时确认页写明「只能上传短信」，`t=decider` 时写明「将看到全部短信明文」（design §14.2、§14.8）；非 owner 扫到的 `t` 值以 owner 在 `pair/complete` 里提交的 `device.kind` 为准——owner 必须按 `t` 来接纳设备，并把同一个 kind 写进目录行和配对确认 MAC（§3.13，protocol v2 D）。
- `c` 是 v2 D 新增的**必填**参数：32 字节随机数，由被配对的设备生成，只出现在二维码里，**永不发给服务器**。owner 用它算 §3.13 的 `pairing_mac`；缺 `c` 或长度不是 32 字节的二维码应当被拒绝。
- `nonce` = CLI 生成的 16 字节随机数，即 §6.16/§3.5 的 nonce；10 分钟有效。
- 终端同时以文字打印 origin 与指纹：指纹 = `SHA-256(s 原始字节)` 前 8 字节的 hex，按 4 位分组大写显示 `A1B2-C3D4-E5F6-7890`，供扫不出来时人工核对。

### 9.2 流程对端点

CLI：`keyref pair` 生成密钥（私钥入密钥环）与 32 字节配对秘密 `c` → 打印二维码 + 指纹 → `POST /v1/pair/register` → 每 2 秒 `GET /v1/pair/status`，拿到完成后先验 §3.4 签名、再验 §3.13 MAC。iOS：扫码 → 核对指纹/名字/origin（origin 不同须人确认后手机才改自己的服务器 URL）→ 勾选条目（默认空集）→ `POST /v1/pair/complete`（带 §3.13 `pairing_mac`）。授予集合为空直到人勾选（design §15）。

---

## 10. 托管专属与运维面

### 10.1 工作量证明（仅 `KEYREF_ENFORCE_QUOTAS=1` 时校验；自托管跳过）

- 签发：`POST /v1/vaults` 缺 `pow` → `401 pow_required` + `challenge`（32 随机字节，b64；有效期 1 小时，单挑战可多次尝试求解但不换库）。
- 求解：找 u64 `nonce` 使 `SHA-256(challenge ‖ vault_id 的 16 原始字节 ‖ u64be(nonce))` 的**前 21 个二进制位全为 0**。提交时 `pow.nonce` 为 u64be 8 字节的 b64。
- 服务器验证成本 = 一次哈希；求解期望 ≈ 2^21 次（design §10.5 第 9 条）。

### 10.2 `GET /v1/healthz`

```json
{
  "status": "ok",                       // ok | degraded（db 不可写 / 磁盘≥50% / 预算≥70% 任一）
  "version": "1.0.0", "commit": "…", "started_at": 1790000000000,
  "db_writable": true,
  "tls": { "mode": "acme",              // acme | plain（无域名调试）
           "status": "ok" },            // 恒 ok：证书状态不在 healthz 上报，ACME 续期看日志
  "quotas": { "enforced": true, "degraded": false },
  "reasons": []                          // degraded 时列字符串码："db_not_writable"、"disk_usage"、"budget_usage"
}
```

未登录可访问；不含任何 vault 维度数据。降级只汇总全局水位（数据库可写、磁盘、托管预算），配额档位的用量数值不在健康检查里展开。

### 10.3 `keyref-server` 子命令与配置

| 命令/变量 | 行为 |
| --- | --- |
| `keyref-server [serve]` | 默认启动 HTTP 服务。`--listen <addr>` 或 `KEYREF_LISTEN`；有 `KEYREF_DOMAIN` 时 443/80 + autocert（证书在 `KEYREF_DATA`，剩余寿命 1/3 起自动续期，状态进 healthz）；无域名时**纯 HTTP**监听 `--listen`（默认 `127.0.0.1:8080`，仅供开发与 e2e，design §10.4） |
| `keyref-server backup --out <file>` | `VACUUM INTO` 在线一致性备份（modernc sqlite 3.54.1 已实测支持）；目标已存在则报错退出非 0；成功打印字节数。**不要**直接复制热 `.db` |
| `keyref-server version` | 打印 semver 与 commit，退出 0 |
| `KEYREF_DATA` | 数据目录（默认 `/data`） |
| `KEYREF_DOMAIN` / `KEYREF_ACME_EMAIL` | 打开内置 ACME |
| `KEYREF_ENFORCE_QUOTAS` | `1` 才启用档位/PoW/全局预算；自托管不设，`plan=unlimited`；客户端请求不可改变它 |

---

## 11. e2e 测试主人方案（拍板）

### 11.1 结构

`cli/e2e/`：`doc.go`（**无** build 标签，仅包注释，保证 `go build ./...` / `go vet ./...` 不报「exclude all Go files」）；其余文件全部 `//go:build e2e`。运行：`cd cli && go test -tags e2e ./e2e`（go.work 使其能引用 proto 与 server 模块）。

### 11.2 软件 owner（替代 iOS）

全部用 Go 实现，放 `cli/e2e/owner_test.go`：

- 签名：`ecdsa.GenerateKey(elliptic.P256())` + `SignASN1`（`sign_alg=ecdsa-p256`）。
- HPKE 接收：`hpke.KEM_P256_HKDF_SHA256.Scheme().GenerateKeyPair()`（`hpke_kem=P-256`；Secure Enclave 互通留给 design §9.2 的跨语言向量任务，e2e 不依赖隔区）。
- HPKE 发送（授予/审批）：`hpke.KEM_X25519_HKDF_SHA256`，`proto/crypto` 的 WrapKey——与 CLI 同一份代码。
- VMK/条目密钥/密文/誊本：全部调 `proto/wire` + `proto/crypto`，**不允许 e2e 自造第二套格式**。

### 11.3 关键步骤（happy path 一条主测试 + 失败分支）

1. `TestMain`：`go build -o <tmp>/keyref-server github.com/lidessen/keyref/server/cmd/keyref-server`；预留空闲端口；以 `--listen 127.0.0.1:<port>`、`KEYREF_DATA=<tmp>`、不设 `KEYREF_ENFORCE_QUOTAS` 启动（纯 HTTP）；等 healthz 就绪。
2. owner 建库：`POST /v1/vaults`（目录誊本 revision=1）→ `POST /v1/session` 两步。
3. 建条目：随机 meta/item key；AES-GCM（§1.5，AAD=§3.7）；`vault_wrapped_*` 用 VMK；签 §3.1；`PUT /v1/items/:id`。
4. CLI 侧：`go build ./cmd/keyref`，用 `KEYREF_SERVER=http://127.0.0.1:<port>` + 临时 HOME + **文件版 keyring**（§11.4）跑 `keyref pair`（二维码文本与 §9.1 负载一致性在此断言，用 `--print-payload` 类调试输出或直接测 `internal/pair` 的负载构造函数）。
5. owner `POST /v1/pair/complete`（含 view+use 授予，info=§3.7）；CLI `keyref sync` 拉引导批。
6. `keyref list` / `get`：断言 stdout/stderr 不含夹具明文及其 base64/hex（design §12.2 验收）。
7. `keyref exec --env K=openai-prod -- /usr/bin/printenv`-类夹具（用允许的 argv0）：断言子进程拿到秘密、CLI 回传已脱敏。
8. 审批路径：建 `approval` 条目（只有 view 授予）→ CLI `exec` 发审批 → owner 验 CLI 签名、构造一次性包裹（info 绑定 approval_id/item_id/请求摘要）→ CLI 轮询取包裹 → 执行 → 包裹取出后再次轮询为 `consumed`。
9. 失败分支：revision 回退（409）、撤销后 sync 只见目录与 grant 删除（403 device_revoked）、`cursor_stale`（把 changes 表旧行删掉再拉旧 cursor）、`echo`/`sh`/`#!/bin/sh` 脚本被拒（退出码 10）、审批 <2s 轮询 429。

### 11.4 密钥环替身

`cli/internal/keyring` 定义 `type SecretStore interface { Set(service, user, secret string) error; Get(…) (string, error); Delete(…) error }`；生产用 `zalando/go-keyring`，e2e 注入 0700 目录文件实现。CI 无 Keychain/Secret Service 也能跑全套。CLI 源码通过接口取私钥，不直接 import go-keyring 到不可替换的位置。

### 11.5 向量来源

- HPKE 层：RFC 9180 官方向量由 circl 上游覆盖（本次已实测其 `go test ./hpke/` 通过，含 `testdata/vectors_rfc9180_*.json.gz`），e2e 不重复。
- 协议层：`proto/crypto/testdata/vectors.json` 金向量（固定种子密钥 + 固定输入 → 期望的誊本字节、AAD、info、签名、digest），由 `proto` 的单元测试消费；e2e 与两侧实现都以通过这组向量为前提。Swift/P-256 隔区互通向量仍是 design §9.2 的独立任务，不在本契约内。

---

## 12. 相对 design.md 的拍板与补齐（差异登记）

| # | 事项 | 拍板 | 依据 |
| --- | --- | --- | --- |
| D1 | 共享代码方式 | 根 `go.work` + 独立 `proto` 模块（`wire` 仅标准库、`crypto` 带 circl），不做 vendoring；服务器只 import `proto/wire` | design §12.2「协议代码两侧共用」；§2 本文 |
| D2 | 服务器是否需要 HPKE | **不需要**。只验签（Ed25519/ECDSA/恢复 Ed25519，标准库）与透传 BLOB | design §10.1、§11 校验清单，逐项核对 |
| D3 | 誊本可解析性 | 誊本只写不读；验证=重建比对；禁止 NUL 切分解析（二进制字段可含 `0x00`） | design §9.1 未言明，本文补齐 |
| D4 | 一次性包裹 info | 在 §9.1 基底后接 `item_id <US> approval_id <US> SHA-256(request_ciphertext)`——把 §8.3 要求绑定的 `item_id` 并入 §9.1 只列 `approval_id` 与摘要的基底，两节 reconciled | design §8.3 vs §9.1 |
| D5 | grant 誊本 `expires_at` | 钉为 u64be（0=无过期）；design 只写了 `<expires_at>` | §3.2 |
| D6 | directory 设备排序与分隔 | 按 `device_id` hex 字节序升序；记录间单个 `<NUL>`，末尾无；`grants_digest` 按 `(item_id, kind 字节序)` 排序（`use` < `view`） | design §9.1 未言明 |
| D7 | 审批签名对象 | CLI Ed25519 签 `request_ciphertext` 原始字节；iOS 解开后对同字节复验 | design §8.3「签名覆盖整个密文」 |
| D8 | sync 增加 `approval` entity | `approval:<approval_id>`，data 只含状态摘要；审批正文仍走专用端点 | design §10.6「与自己相关的审批」需载体 |
| D9 | PoW 线流程 | `401 pow_required + challenge` 重试同端点；解 = SHA-256 前导 21 个 0 位，绑定 challenge/vault_id/nonce | design §10.5 第 9 条只定了量 |
| D10 | 删除保险库两步 | 同端点：无签名 → `401 delete_challenge_required + challenge`；带 §3.6 签名重发 → 204 | design §11「先领挑战，再签名确认」 |
| D11 | 会话挑战两步同路径 | `POST /v1/session`：无签名字段→发挑战；带 `signature`→发令牌 | design §8.2、端点表 |
| D12 | 审计密文信封 | `u8 wrap_count ‖ 每 owner { u16be enc_len ‖ enc ‖ 48B } ‖ AES blob`，MVP count=1，多 owner 平滑扩展 | design §7.7 只描述了构造 |
| D13 | 恢复接管双签 | `recovery_signature` 与 `owner_signature` 都签 §3.3 目录誊本原文；响直接发新 owner 会话 | design §8.5「共同签署一份接管誊本」 |
| D14 | pair/status 与 register 无鉴权 | nonce 即凭证（16 字节随机，仅出现在二维码）；按 IP/每分钟限流 | CLI 配对前无会话，design §8.1 |
| D15 | 消息信封带显式目标 | `u16be id_len ‖ device_id ‖ u16be enc_len ‖ enc ‖ wrapped(48B)` 记录式信封（按 device_id 升序），不复用审计 D12 的隐式排序——消息的接收方有两类（owner + 决策器），必须钉死对应关系。`wrapped` 是普通 HPKE 包裹（`enc ‖ ct`，32 字节消息密钥 → 48 字节密文），与 §3.7 其他包裹同构；2026-11-02 修正：原文写作 60B 并把 §1.5 的 AES 段格式误套到 HPKE 段，任何 HPKE 实现（circl、CryptoKit）都产不出该长度 | design v0.8 §14.3「信封里每个包裹带目标 device_id」 |
| D16 | 审批 subject 的线格式 | 请求体沿用 `item_id` 字段并新增可选 `message_id`（互斥）；服务器落库为 `subject` 列（`item:<id>` / `message:<id>`）。不改名为 subject 是为了 v1.1 客户端字节兼容 | design v0.8 §14.5「`item_id` 扩展为 `subject`」 |
| D17 | 决策器补投走独立端点 | 决策器配对/委托开启前的旧消息，由 owner 通过 `PUT /v1/messages/:id/wraps` 补包（服务器只追加记录）；补投之前决策器解不开旧消息，24h TTL 自愈 | design v0.8 §14.3 自愈缺口需要显式载体 |
| D18 | 消息消费的 decision 载荷 | 包**消息明文 JSON 原始字节**（§3.9），不是消息密钥——消息密钥不出 owner/决策器域，CLI 无 `messages` 读权限 | design v0.8 §14.5 经三视角评审修正（评审 P0：密钥管道断裂） |
| D19 | 谁批的进审计 | 审批行新增 `decision_device_id` 列（schema v6），decision 被接受时记下签署设备（owner `kind=ios` 或决策器 `kind=decider`）；§6.22 轮询响应与 CLI 审计事件明文各加一个**可选**同名键（`omitempty`，pending/未决行省略）。纯增量，v1.1 客户端忽略未知键 | design v0.8 §14.5「消费审计的明文含 decision 来源设备」、§14.8「审批单与审计里记录 decision 的 device_id」 |

## 13. 假设

1. **模块路径** `github.com/lidessen/keyref/{proto,server,cli,tools/vectordump}`：初版由镜像名 `ghcr.io/lidessen/keyref-server`（design §10.4）推断，现已由各 go.mod 落地确认。
2. `docs/protocol.md` 此前不存在（`docs/` 只有 `design.md` 与 `README.md`），没有早先 Rust 版本需要改写；本文全新撰写，无 Rust 残句。
3. Go 最低 1.25（circl v1.6.5 的 `go.mod` 要求 `go 1.25.0`）；仓库实际声明：`go.work` 与 `cli`/`server` 为 `go 1.26.0`，`proto`/`tools/vectordump` 为 `go 1.25.0`。本契约全部核实命令在 go1.27.3 darwin/arm64 上执行。
4. CLI 命令面（`pair session status lock unlock sync list get exec server mcp`，与 `cli/cmd/keyref/main.go` 的 dispatch 一致）与退出码（10–18）按 design §7.6/§12.2 原样执行，本文不重复定义；`--pty`/`--reply` 已随审批路径实现（§6.19–§6.21、§7.1），不再是接口预留。
5. 官方托管 origin 仍是占位 `https://sync.example`（design §14.12）；编译进 CLI 的默认 origin 在域名敲定后只改一处常量。
6. `keyref-server` 在无 `KEYREF_DOMAIN` 时监听纯 HTTP 的行为（§10.3）是本文为实现「本地调试听 127.0.0.1」（design §10.4）与 e2e 拍板的具体化。
