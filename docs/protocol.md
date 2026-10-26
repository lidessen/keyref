# keyref 线协议契约

状态：v1.0，对应 design.md v0.4。本文是唯一的线格式依据：并行的 Go 服务器实现者与 Go CLI 实现者都只按本文写字节。design.md 讲「为什么」，本文讲「精确是什么」。两者冲突时，以本文对线格式的拍板为准，并把差异登记在第 12 节。

日期：2026-10-24。实现语言：Go（design §12.2，v0.4 起 CLI 与服务器同为 Go）。

---

## 1. 全局约定

### 1.1 编码

| 项 | 规则 |
| --- | --- |
| 二进制字段（JSON 内） | 标准 Base64，RFC 4648 **带填充**，`encoding/base64.StdEncoding` |
| id（`vault_id`、`device_id`、`item_id`、`approval_id`、`nonce`） | 16 字节随机数的**小写 hex**，32 个字符，正则 `^[0-9a-f]{32}$` |
| 时间 | Unix 毫秒，JSON number（`int64`） |
| 誊本内整数（`revision`、`expires_at`、`directory_revision`、计数） | **uint64 大端 8 字节**（`binary.BigEndian.PutUint64`） |
| HPKE `info` 与 AAD 分隔 | ASCII unit separator `0x1f`（下文写作 `<US>`） |
| 签名誊本分隔 | NUL `0x00`（下文写作 `<NUL>`） |
| `Authorization` | `Bearer <token>`；token 是 32 字节随机数的 hex（64 字符） |

### 1.2 JSON 规则

- 请求与响应 `Content-Type: application/json; charset=utf-8`。
- 字段名 lower_snake_case。**未知字段一律拒绝**（`400 invalid_field`，design §12.3），避免把客户端误传的明文写进日志。
- 错误响应固定为 `{"error":"<code>"}`，可附结构化字段（如 `challenge`），**永不回显请求字段**（design §11）。
- 请求正文上限先于解析执行：item 路径 256 KiB、审计 4 KiB、审批 8 KiB，超限 `413 body_too_large`。

### 1.3 错误码 → HTTP 状态

| 码 | HTTP | 场景 |
| --- | --- | --- |
| `invalid_json` | 400 | 正文不是合法 JSON |
| `invalid_field` | 400 | 字段缺失、类型错、未知字段、hex/base64 不合法、`ref` 类字段越界 |
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

超额（`quota_exceeded`）时**永远可用**的操作集合（design §10.5 第 7 条）：读（`sync`、`account`、`items` 读、`grants/self`）、删除（item tombstone、grants、目录、整个保险库）、审批决定。

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

### 2.1 go.work：三模块共用，不做 vendoring

拍板：根 `go.work` 连接三个模块，共享誊本与密码学代码放独立模块 `proto/`。理由：服务器与 CLI 都要构造/重建誊本并验签（§3），`internal/` 跨模块不可见，复制代码会让两侧誊本漂移；vendoring 冻结依赖、拖慢修补，且 go.work 已是 2026 年多模块仓库的标准做法。Docker 构建以仓库根为 context，`go.work` 在 WORKDIR 内自动生效。

```
// /go.work
go 1.25

use (
	./proto
	./server
	./cli
)
```

模块路径假定为 `github.com/lidessen/keyref/{proto,server,cli}`（镜像名 `ghcr.io/lidessen/keyref-server` 推断，见第 13 节假设）。

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
cli/cmd/keyref/main.go      // 命令入口：pair status lock unlock sync list get exec server
cli/internal/config/        // origin 配置（0700 目录）、KEYREF_SERVER 覆盖
cli/internal/keyring/       // SecretStore 接口；go-keyring 实现；e2e 用的目录实现（§11.4）
cli/internal/store/         // cache.sqlite（模式 0600，密文缓存 + 已验签 revision）
cli/internal/session/       // 挑战→令牌、token 复用与续期
cli/internal/sync/          // 拉取、验签、cursor=0 引导、grants_digest 对账、撤销检测
cli/internal/meta/          // list/get：只解 meta，输出掩码
cli/internal/pair/          // 二维码生成、pair/register、pair/status 轮询、钉死 owner 公钥
cli/internal/exec/          // spawn（os/exec + SysProcAttr）、策略与 shebang、注入、脱敏、审计
cli/internal/qr/            // skip2/go-qrcode 封装；ToSmallString 的 ▀▄█ 半块字符写 stdout
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

### 3.1 item 誊本（design §9.1，逐字实现）

```text
"KEYREF1" <NUL> "item" <NUL> vault_id(hex) <NUL> item_id(hex) <NUL>
u64be(revision) <NUL> meta_ciphertext <NUL> secret_ciphertext <NUL>
vault_wrapped_meta_key <NUL> vault_wrapped_item_key <NUL> writer_device_id(hex)
```

- 签名者：owner（ECDSA P-256，ASN.1 DER）。tombstone 行的四个密文字段是**零长度字节串**，其余规则不变。
- `vault_wrapped_*` = AES-256-GCM(VMK) blob（§1.5），AAD = `keyref v1 <US> vault-meta-key <US> <vault_id> <US> <item_id>` 与 `... vault-item-key ...`（US = `0x1f`）。

### 3.2 grant 誊本

```text
"KEYREF1" <NUL> "grant" <NUL> vault_id(hex) <NUL> device_id(hex) <NUL> item_id(hex) <NUL>
kind("view"|"use") <NUL> u64be(revision) <NUL> u64be(expires_at, 0=永不过期) <NUL>
hpke_enc <NUL> wrapped_key
```

- 签名者：owner。删除授权的誊本同样格式：`expires_at = 0`、`hpke_enc` 与 `wrapped_key` 为零长度。
- `hpke_enc`/`wrapped_key` 是 HPKE(X25519, recipient=CLI) 对 32 字节 meta key（view）或 item key（use）的封装，info 见 §3.7，AAD 空。

### 3.3 directory 誊本

```text
"KEYREF1" <NUL> "directory" <NUL> vault_id(hex) <NUL> u64be(directory_revision) <NUL>
<设备记录按 device_id 的 hex 字节序升序排列，记录之间以单个 <NUL> 连接，末尾无 <NUL>>

每个设备记录：
device_id(hex) <NUL> kind("ios"|"cli") <NUL> status("pending"|"active"|"revoked") <NUL>
hpke_kem("X25519"|"P-256") <NUL> hpke_public_key <NUL> sign_alg("ed25519"|"ecdsa-p256") <NUL>
sign_public_key <NUL> renewal_sign_public_key <NUL> grants_digest(32 字节原始 SHA-256)
```

- 签名者：owner（多 owner 时任一在目录内的 owner）。`renewal_sign_public_key` 无则为零长度。
- **`grants_digest`** = SHA-256( 该设备当前全部 grant 誊本按 `(item_id hex 升序, kind 字节序升序)` 排序后顺序拼接 )。注意：`kind` 按字符串字节序，即 `"use"` 排在 `"view"` 之前。

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
purpose ∈ { vmk, meta-key, item-key, one-time-item-key, audit-event-key, approval-request }
```

| 用途 | 完整 info / AAD |
| --- | --- |
| view 授权包裹 meta key | 基底，purpose=`meta-key` |
| use 授权包裹 item key | 基底，purpose=`item-key` |
| 一次性 item key（§7.1.4） | 基底 purpose=`one-time-item-key`，再接 `<US> item_id(hex) <US> approval_id(hex) <US> SHA-256(request_ciphertext 原始字节)`（第 12 节 D4：把 design §8.3 要求绑定的 `item_id` 并进 §9.1 的基底） |
| 审计事件密钥包裹 owner | 基底，purpose=`audit-event-key` |
| 审批请求 HPKE 给 owner | 基底，purpose=`approval-request`（recipient = owner 设备） |
| VMK 包给 owner 设备 | 基底，purpose=`vmk` |
| 条目密文 AAD | `keyref v1 <US> secret <US> <vault_id> <US> <item_id>`（meta 换成 `meta`；**不含 revision**，design §9.1） |
| `vault_wrapped_*` AAD | `keyref v1 <US> vault-meta-key|vault-item-key <US> <vault_id> <US> <item_id>` |
| `recovery_wrap` AAD | `keyref v1 <US> recovery <US> <vault_id>` |
| 审计正文 AES 段 AAD | `keyref v1 <US> audit <US> <vault_id> <US> <device_id>(上报设备)` |

### 3.8 恢复码与派生（design §8.5）

- 恢复码载荷 = `vault_id(16 原始字节) ‖ 种子(32 字节 CSPRNG)`，整体 Crockford Base32 分组编码展示；解析即得两段。
- HKDF-SHA256：`prk = hkdf.Extract(sha256.New, ikm=种子, salt=nil)`；`recovery-kek = Expand(prk, "recovery-kek", 32)`；`recovery-sign` 的 Ed25519 种子 = `Expand(prk, "recovery-sign", 32)`。两条派生域分离、相互独立。
- `recovery_wrap` = AES-256-GCM(`recovery-kek`, VMK)，blob 与 AAD 见 §1.5/§3.7。
- `recovery_kdf_json` 固定为：`{"v":1,"kdf":"hkdf-sha256","salt":"","kek_info":"recovery-kek","sign_info":"recovery-sign"}`。以后加 Argon2id 口令副本时 `kdf` 换 `"argon2id"` 并增 `m/t/p/salt` 字段，服务器只透传不解释。

---

## 4. 库可行性结论（2026-10-24 实测）

全部在本机 `go version go1.27.3 darwin/arm64` 上验证；`go.mod` 统一写 `go 1.25`。

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

通用校验（每个端点都做）：设备属于该 vault 且 `status = active`（§8.4 送达语义的例外除外）；`kind = cli` 调 5.10/5.11/5.12/5.13/5.15/5.4/5.5 → `403 forbidden`；签名字段在该设备当前公钥下验证；正文上限 §1.2。

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
  "directory_signed": "<b64：旧设备全部 revoked、新 owner active 的新目录誊本>",
  "recovery_signature": "<b64 Ed25519，用恢复码派生私钥>",
  "owner_signature": "<b64 ECDSA ASN.1，新 owner>"
}
```

服务器用存储的 `recovery_sign_pub` 验 `recovery_signature`、用誊本内新 owner 公钥自洽验证 `owner_signature`，落库并追加 `directory:` 变更；旧设备会话立即失效。响应即新 owner 会话（形状同 §6.7 第二步）：

```json
{ "token": "<64 hex>", "expires_at": 1790000000000,
  "origin": "https://sync.example", "plan": "free",
  "limits": { "items": 20, "devices_ios": 1, "devices_cli": 1, "storage_bytes": 1048576,
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

令牌 12 小时有效，续期即重新走两步。数据库只存 `token_hash = hex(SHA-256(token 原始 32 字节))`。错误：`unauthorized`、`device_revoked`（revoked 设备不发新令牌）、`rate_limited`。

### 6.8 `GET /v1/sync?cursor=<int>` — 增量同步（§8 详述）

### 6.9 `GET /v1/items/:item_id` — 按需单条

响应行 = §8.3 的 item `data` 对象，按调用者身份过滤（owner 全量；CLI 有 view 授予给 `meta_ciphertext`，有 use 授予再给 `secret_ciphertext`；`vault_wrapped_*` 只给 owner）。错误：`not_found`、`forbidden`（CLI 无 view 授予）。

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

服务器要求 `revision == 已存值 + 1` 且签名通过，否则 `409 revision_conflict` / `403 bad_signature`。响应 `200 {"revision":4,"updated_at":1790000000000}`。条目更新追加一条 `item:` 变更；**不**自动追加合成 grant 变更（grant 写入时才有合成 item 变更，design §6.3），CLI 靠本条 item 变更刷新本地行。错误信息不得回显密文字段。

**仅本机条目**（design v0.7 §6.6）：`secret_ciphertext` 与 `vault_wrapped_item_key` 省略（或为零长度），行内只落 meta——密文只在 owner 手机本地。仅本机条目不得拥有 `use` 授予：`PUT /v1/grants` 对该条目建/续 `use` → `400 local_item_grant_conflict`；带 `use` 授权的条目改为本地 → 同错误。

### 6.11 `DELETE /v1/items/:item_id` — tombstone（owner）

请求 `{"revision":5,"signature":"<b64 §3.1 誊本，密文字段为零长度>"}` → `204`。服务器置 tombstone、**删除该条全部 grants**、逐设备追加 `grant:` 删除变更与 `item:` 变更（design §6.3）。

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
  "signature": "<b64 owner 签 §3.4 pair 誊本>" }
```

→ `204`。服务器核对 nonce 行未消费、设备公钥与登记一致、owner 签名通过，写 `devices`（status=active）与 `grants`，追加变更；`pair_sessions.consumed_at` 置位。错误：`pair_expired`、`bad_signature`。

### 6.18 `GET /v1/pair/status?nonce=<hex>`（CLI 轮询）

`200 {"status":"pending"}` 或：

```json
{ "status": "complete", "vault_id": "…", "device_id": "…",
  "owner_sign_public_key": "<b64 65B ECDSA 公钥>",
  "pairing_signature": "<b64 §3.4 誊本的 owner 签名>",
  "directory_revision": 8, "directory_signed": "<b64>", "directory_signature": "<b64>",
  "grants": [ { …该设备的初始授予… } ] }
```

CLI 验 `pairing_signature` 后把 `owner_sign_public_key` 钉死进本地配置；此后只接受这把 key（或其签名目录接纳的后续 owner key）签的目录与授予。错误：`pair_expired`（过期或不存在——同码，不区分）。

### 6.19 `POST /v1/approvals`（CLI）

```json
{ "item_id": "…", "request_ciphertext": "<b64 enc‖ct，HPKE 给 owner>",
  "request_signature": "<b64 Ed25519，签 request_ciphertext 原始字节>",
  "expires_at": 1790000000000 }
```

→ `201 {"approval_id":"…","expires_at":…}`。`expires_at − now ≤ 120000`（CLI `--timeout`）。正文 ≤ 8 KiB、每库 pending ≤ 10，超出 `413` / `429 quota_exceeded`。`request_ciphertext` = `enc(32B 一次性 X25519) ‖ ct‖tag`；明文 JSON：

```json
{ "v": 1, "cli_device_id": "…", "item_id": "…", "argv": ["curl", "https://…"],
  "refs": ["openai-prod"], "injection": "env",
  "hosts": ["api.openai.com"], "ephemeral_kem": "X25519",
  "ephemeral_public_key": "<b64 32B>", "created_at": 1790000000000 }
```

### 6.20 `GET /v1/approvals?status=pending`（owner）

`{"approvals":[{"approval_id":"…","cli_device_id":"…","item_id":"…","request_ciphertext":"…","request_signature":"…","created_at":…,"expires_at":…}]}`。iOS 解开后**先验 CLI 签名**（对密文），再展示。

### 6.21 `POST /v1/approvals/:approval_id/decision`（owner）

同意：`{"decision":"approved","one_time_enc":"<b64>","one_time_wrapped_key":"<b64 ct‖tag>"}`。
包裹 = HPKE(X25519, recipient=请求里的 `ephemeral_public_key`, info=§3.7 一次性模板, AAD 空)；服务器置 `expires_at = now + 60000`。拒绝：`{"decision":"denied"}`。→ `204`。错误：`approval_not_pending`、`bad_signature`（缺 CLI 签名的旧行）。

**载荷两种**（design v0.7 §6.6）：同步条目照旧包 32 字节 item key；**仅本机条目**（`items.secret_ciphertext` 为 NULL，design §6.6）包该条目的 secret **密文字节**（明文的既有 wire 密文，≤64 KiB）。decision 端点正文上限相应为 **96 KiB**（审批请求仍 8 KiB）。CLI 按本地缓存中该条目是否缺 `secret_ciphertext` 区分两种投递。仅本机条目不得拥有 `use` 授权（服务器互斥校验，错误码 `local_item_grant_conflict`）。

### 6.22 `GET /v1/approvals/:approval_id`（发起 CLI 轮询）

`{"approval_id":"…","status":"pending"|"denied"|"expired"|"consumed"}`；首次轮询到 `approved` 时**原子**返回包裹并置 `consumed`、清包裹字节：

```json
{ "approval_id": "…", "status": "approved",
  "one_time_enc": "<b64>", "one_time_wrapped_key": "<b64>", "expires_at": 1790000000060 }
```

轮询间隔 < 2 秒 → `429 rate_limited`；轮询**不计**每日请求配额（design §8.3）。

### 6.23 `POST /v1/audit`（已登录设备）

```json
{ "ciphertext": "<b64 审计信封：u8 wrap_count ‖ 每.owner{ u16be enc_len ‖ enc ‖ 48B 包裹的事件密钥 } ‖ nonce‖ct‖tag（AES-GCM(事件密钥) 正文）>" }
```

MVP `wrap_count=1`（单 owner；Phase 2 多 owner 时按 owner device_id 升序追加包裹，信封格式不变）。事件密钥 32 字节随机；包裹 info = §3.7 `audit-event-key`。明文 JSON 字段见 design §7.7（无秘密值）。→ `201 {"seq":42}`。正文 ≤ 4 KiB。审计与待审批密文计入存储口径（design §10.5）。

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

---

## 7. 关键流程串起来

### 7.1 审批一次性包裹（design §8.3）

1. CLI 生成一次性 X25519（用后即弃），构造 §6.19 明文，HPKE 给 owner（info=§3.7 `approval-request`），Ed25519 签密文字节，`POST /v1/approvals`。
2. 服务器验 CLI 签名（设备 active、在目录内）→ 不过 `403 bad_signature` 才落库。
3. iOS 拉取 → 解开 → 验 CLI 签名 → Face ID → `POST decision` 附 HPKE(recipient=临时公钥, info=§3.7 one-time 模板) 的 item key 包裹。
4. CLI 每 2 秒轮询 `GET /v1/approvals/:id`，取走包裹（原子 consumed），解开 item key，`exec`，结束即 zeroize（memguard）。

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

- item（owner 全量；CLI：`meta_ciphertext` 需 view、`secret_ciphertext` 需 use、`vault_wrapped_*` 不给 CLI）：
  `{ "vault_id":"…","item_id":"…","revision":4,"tombstone":false,"meta_ciphertext":"…","secret_ciphertext":"…","vault_wrapped_meta_key":"…","vault_wrapped_item_key":"…","writer_device_id":"…","signature":"…","updated_at":… }`
- grant：`{ "device_id":"…","item_id":"…","kind":"use","hpke_enc":"…","wrapped_key":"…","expires_at":…,"revision":3,"signature":"…" }`；删除行为 `{ "device_id":"…","item_id":"…","kind":"use","deleted":true,"revision":4 }`。
- device：`{ "device_id":"…","kind":"cli","status":"revoked","label":"…","created_at":…,"revoked_at":… }`。
- directory：`{ "directory_revision":8,"directory_signed":"<b64>","directory_signature":"<b64>" }`。
- approval：`{ "approval_id":"…","status":"consumed" }`。

可见性（design §10.6）：active CLI 见自己的 grants、指向的 items、目录、相关审批；active owner 见全部 items/grants/目录/审批；**revoked 设备**只目录、tombstone 与指向自己的 grant 删除——其余端点一律 `403 device_revoked`。客户端在解密前验签；验签失败停止应用本批并保留旧数据。

---

## 9. 配对二维码与 CLI 展示

### 9.1 二维码负载（design §8.1）

```text
keyref://pair?v=1&k=<b64 X25519 hpke_public_key>&s=<b64 ed25519 sign_public_key>&n=<hex nonce 32>&name=<percent-encoded utf-8, ≤32 字节>&u=<percent-encoded origin, https>
```

- `k`、`s` 为标准 Base64 后按 RFC 3986 percent-encode 进 query（`+`、`=`、`/` 必须转义）；`n` 是 hex，无需转义；`name`、`u` 是普通 percent-encoding。iOS 必须先 percent-decode 再 base64 解码。
- `nonce` = CLI 生成的 16 字节随机数，即 §6.16/§3.5 的 nonce；10 分钟有效。
- 终端同时以文字打印 origin 与指纹：指纹 = `SHA-256(s 原始字节)` 前 8 字节的 hex，按 4 位分组大写显示 `A1B2-C3D4-E5F6-7890`，供扫不出来时人工核对。

### 9.2 流程对端点

CLI：`keyref pair` 生成密钥（私钥入密钥环）→ 打印二维码 + 指纹 → `POST /v1/pair/register` → 每 2 秒 `GET /v1/pair/status`。iOS：扫码 → 核对指纹/名字/origin（origin 不同须人确认后手机才改自己的服务器 URL）→ 勾选条目（默认空集）→ `POST /v1/pair/complete`。授予集合为空直到人勾选（design §15）。

---

## 10. 托管专属与运维面

### 10.1 工作量证明（仅 `KEYREF_ENFORCE_QUOTAS=1` 时校验；自托管跳过）

- 签发：`POST /v1/vaults` 缺 `pow` → `401 pow_required` + `challenge`（32 随机字节，b64；有效期 1 小时，单挑战可多次尝试求解但不换库）。
- 求解：找 u64 `nonce` 使 `SHA-256(challenge ‖ vault_id 的 16 原始字节 ‖ u64be(nonce))` 的**前 21 个二进制位全为 0**。提交时 `pow.nonce` 为 u64be 8 字节的 b64。
- 服务器验证成本 = 一次哈希；求解期望 ≈ 2^21 次（design §10.5 第 9 条）。

### 10.2 `GET /v1/healthz`

```json
{
  "status": "ok",                       // ok | degraded（db 不可写 / tls 异常 / 预算≥70% / 磁盘≥50% 任一）
  "version": "1.0.0", "commit": "…", "started_at": 1790000000000,
  "db_writable": true,
  "tls": { "mode": "acme",              // acme | plain（无域名调试）| disabled
           "status": "ok",              // ok | expiring | renewal_failing
           "not_after": 1799999999999 },
  "quotas": { "enforced": true, "degraded": false,
              "free_storage":     { "used_bytes": 0,     "cap_bytes": 2147483648 },
              "free_daily_requests": { "used": 0,        "cap": 1000000 } },
  "reasons": []                          // degraded 时列字符串码，如 "disk_usage"、"budget_usage"
}
```

未登录可访问；不含任何 vault 维度数据。

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

## 13. 假设

1. **模块路径** `github.com/lidessen/keyref/{proto,server,cli}`：从镜像名 `ghcr.io/lidessen/keyref-server`（design §10.4）推断，仓库尚未有 go.mod，未经仓库所有者确认。改名是全局替换。
2. `docs/protocol.md` 此前不存在（`docs/` 只有 `design.md` 与 `README.md`），没有早先 Rust 版本需要改写；本文全新撰写，无 Rust 残句。
3. Go 最低 1.25（circl v1.6.5 的 `go.mod` 要求 `go 1.25.0`）；本契约全部核实命令在 go1.27.3 darwin/arm64 上执行。
4. CLI 命令面（`pair status lock unlock sync list get exec server`）与退出码（10–18）按 design §7.6/§12.2 原样执行，本文不重复定义；`--pty`/`--reply` 为 Phase 2 接口预留。
5. 官方托管 origin 仍是占位 `https://sync.example`（design §14.12）；编译进 CLI 的默认 origin 在域名敲定后只改一处常量。
6. `keyref-server` 在无 `KEYREF_DOMAIN` 时监听纯 HTTP 的行为（§10.3）是本文为实现「本地调试听 127.0.0.1」（design §10.4）与 e2e 拍板的具体化。
