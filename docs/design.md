# keyref 设计文档

状态：草案 v0.1。本文是规格，不是实现记录。仓库里的 `ios/`、`cli/`、`server/` 还没有代码。

日期：2026-10-20。

本文用中文写。命令、字段、算法、路径和代码标识保持英文，例如 `keyref exec`、`VMK`、`{{keyref:openai-prod}}`。

## 决策摘要

这些决定是后面几节的结论，放在前面方便对照。标成「待确认」的条目在文末「开放问题」里，不阻塞把文档当成默认规格来读。

| 主题 | 决定 |
| --- | --- |
| 产品边界 | 人用 iOS 管理秘密。Agent 只用 CLI。CLI 的输出里没有明文 |
| 编辑权 | MVP 里只有 iOS owner 能创建、修改、删除、轮换。CLI 只读 |
| 引用 | 每个条目有稳定的 `ref`（例如 `openai-prod`）。占位符是 `{{keyref:REF}}`，URI 形式 `keyref://REF` 与之等价 |
| 注入 | 优先 `--env`、stdin、额外 fd / 打开后即删除的临时文件。进程参数注入必须显式 `--allow-argv` |
| 执行 | CLI 直接 `posix_spawn` / `execve`，不经过 shell。`echo`、`env`、`sh` 等默认拒绝 |
| 敏感条目 | `sensitivity = approval` 的条目不给 CLI 长期条目密钥。每次 `exec` 由手机批准后下发一次性包裹 |
| 元数据 | 名称、描述、`ref`、策略、秘密值全部加密。服务器只看见 id、版本、密文、设备授权图 |
| 密码学 | AES-256-GCM 做数据加密；HPKE（RFC 9180）做密钥包裹；Secure Enclave 用 P-256；CLI 用 X25519 + Ed25519；恢复口令用 Argon2id |
| 存储 | Cloudflare Workers + D1。个人与早期使用大约 $0–5/月。不用 KV 当数据源，MVP 不用 R2 |
| 技术栈 | iOS：Swift / SwiftUI。CLI：Rust。服务器：TypeScript on Workers |
| 身份 | MVP 没有邮箱账号。保险库由第一台 iPhone 创建，恢复靠高熵恢复密钥 |
| 待确认 | 默认要不要每次审批、MVP 要不要沙箱、要不要 MCP、Windows、团队共享、自托管是否为硬需求 |

## 1. 背景

把 API key 交给 AI agent 时，常见做法是写进环境变量、项目配置或对话。模型随后能在上下文里看见明文，也可能把明文写进日志、工单、另一个文件，或在下一步命令里打印出来。

keyref 把两件事分开：

1. **使用**：被授权的命令可以拿到秘密（否则密钥没有意义）。
2. **看见**：规划命令的 agent 只接触 `ref`、名称、描述和掩码。工具返回给模型的字节流里，秘密已经被替换掉。

人的管理界面在 iOS 上。手机持有主密钥，并用 Face ID 控制主密钥的解包。CLI 是跑在 agent 那台机器上的经纪人：它能解自己被授权的条目，但协议上没有「把明文打出来」这条命令。

这不是另一套 1Password `op run`。`op run` 信任即将执行的命令。keyref 信任的是人在手机上设过的策略，以及「agent 的工具面只有 keyref」这条集成约束。命令本身是模型写的，默认不可信。

## 2. 目标与非目标

### 2.1 目标

- 人可以创建、查看、修改、删除、轮换 API key、token、密码和笔记。
- 每个条目有人类可读的名称、描述，以及保险库内唯一的稳定 `ref`。
- iOS 用 Face ID 解锁，主密钥材料的包裹密钥在 Secure Enclave 里。
- 人可以在手机上批准或撤销一台 CLI 设备，并选择这台设备能使用哪些条目。
- Agent 可以 `list` / `get` 看到掩码，不能看到明文。
- Agent 可以用 `exec` 跑自己本来要跑的命令，把 `ref` 放在秘密原来的位置。
- `exec` 会脱敏子进程的 stdout 和 stderr，包括常见编码。
- 交互式程序可以走 pty，密码可以从 keyref 写进子进程的输入，而不是写进 agent 的上下文。
- 同步服务器在端到端加密之外只保存密文。
- 每一次 `exec` 都有审计记录，且审计正文对服务器是密文。

### 2.2 非目标

- 不把「主机已被同一用户完全控制」做成可防的场景。调试器、内存转储、恶意动态链接器不在保护范围内。见第 4 节。
- MVP 不做团队保险库、多主人同时编辑、浏览器扩展、Android、Windows。
- MVP 不托管 SSH 私钥文件、大附件或 OTP 种子。条目值是有长度上限的字符串（64 KiB 以内）。
- 不做服务端全文搜索。名称是加密的，搜索在已解锁的客户端本地进行。
- 不替换公司现有的 KMS。keyref 管的是「人自己的、要交给 agent 用的」那一类秘密。
- 不保证恶意但已被人批准的命令不会把秘密发到网络上。命令若真的需要秘密，它就有能力把秘密传走。策略和审批用来把这个决定留给手机前的人。

## 3. 角色

| 角色 | 是谁 | 持有什么 |
| --- | --- | --- |
| Owner | 使用 iOS 应用的人 | Secure Enclave 密钥、解锁后的 VMK、全部条目 |
| Agent | 写命令的模型，以及调用工具的 harness | `ref`、掩码、已脱敏的命令输出 |
| CLI 设备 | 装在 agent 机器上的 `keyref` 进程 | 自己的 X25519 / Ed25519 私钥；被授权条目的密钥 |
| 同步服务 | Workers + D1 | 密文、设备公钥、授权关系、会话令牌哈希 |
| 子进程 | `exec` 真正启动的程序，例如 `curl` | 这一次被注入的秘密 |

Owner 设备是 `kind = ios`。Agent 设备是 `kind = cli`。只有 owner 设备会拿到 VMK 的包裹。

## 4. 威胁模型

### 4.1 要挡住的对手

| ID | 对手 | 我们要的结果 |
| --- | --- | --- |
| A1 | 网络窃听者 | TLS 之外仍然只能看到密文。窃听同步流量得不到秘密 |
| A2 | 被入侵的同步服务运营方，或被迫交出数据库的人 | 有全部密文、授权图、时间戳，没有密钥就解不开。不能伪造 owner 的签名来通过诚实客户端的校验 |
| A3 | 会写命令的 agent，工具结果会回到模型上下文 | `list` / `get` / `exec` 的回传里没有明文，也没有明文的常见编码 |
| A4 | 试图用 `exec` 做外泄的 agent：`echo`、`env`、`base64`、启动 shell、把值写进文件再读 | 默认策略拒绝这些命令。秘密不进 shell 历史。默认不进进程参数 |
| A5 | 偷到上锁 iPhone 的人 | 没有 Face ID / 密码就解不开 Secure Enclave 里的包裹 |
| A6 | 偷到服务器备份、但没有手机也没有恢复密钥的人 | 与 A2 相同 |
| A7 | 把用户骗去扫别人的配对二维码 | 配对码要在手机和终端两边对得上；授予范围默认是空的，要人逐条勾选 |

### 4.2 明确不承诺挡住的情况

这些不是「以后再修的 bug」，而是这个架构接受的边界。产品文案和集成文档都要写清楚。

| ID | 情况 | 原因 |
| --- | --- | --- |
| B1 | 跑 CLI 的主机被完全控制：root、调试器、`ptrace`、内存转储、`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` 打进 `keyref` 自己 | 注入秘密的进程自己能读到秘密。没有任何用户态经纪人能在这个前提下保密 |
| B2 | Agent 的 harness 除了 `keyref` 之外还有一个通用 shell，并且可以和 `exec` 同时观察这台机器 | 同一用户可以读 `/proc/<pid>/environ`、`ps e`、子进程写出来的文件。脱敏只覆盖 keyref 自己转发的那条输出 |
| B3 | 人在手机上批准了一个会把秘密发走的命令，或条目策略允许了这个命令和主机 | 被授权的程序本来就要使用秘密 |
| B4 | 攻击者拿着已解锁的手机，或能通过当时的 Face ID | 这就是主人 |
| B5 | 恢复密钥已经泄露 | 恢复密钥等价于 VMK 的副本 |
| B6 | 已经解开过条目密钥的 CLI 副本，在撤销之后继续使用本地缓存，并且二进制被改掉、不再遵守过期时间 | 撤销要配合轮换条目密钥。只删服务器上的授权，挡不住已经拷走的密钥 |
| B7 | 操作系统或 Secure Enclave 自身被攻破 | 超出应用层设计 |
| B8 | 秘密很短，或被拆成几段分别打印，脱敏无法靠整串匹配发现 | 靠拒绝 shell 和解释器来缩小这个口子，不靠脱敏器万能 |

### 4.3 集成要求

这条要求和密码学同样重要：

> Agent 的工具白名单里只放 `keyref`（以后可以是 `keyref mcp`）。不要再给同一个 agent 一个原始 shell，也不要把 `ps`、环境变量转储或 core dump 喂回模型。

做不到这一点时，keyref 仍然能避免秘密进入「keyref 这个工具的返回值」，但不能阻止模型用另一个工具去读进程环境。第 7 节的沙箱是 Phase 3 的补强，不是 Phase 1 的前提。

### 4.4 失败时的方向

解不开、策略不通过、审批超时、脱敏器出错：命令不启动，或者已经启动的子进程被杀掉，并且 **不把原始输出交给调用方**。错误信息里可以有 `ref`，不能有秘密的任何片段。

## 5. 架构

```mermaid
flowchart TB
  subgraph phone [iOS]
    App[Keyref App]
    SE[Secure Enclave P-256]
    App --- SE
  end

  subgraph host [Agent 所在的机器]
    Agent[AI Agent]
    CLI[keyref CLI]
    Child[子进程]
    Agent -->|只调用 keyref| CLI
    CLI -->|注入秘密并脱敏输出| Child
  end

  API[Sync API on Workers]
  DB[(D1 密文与授权)]

  App -->|写入密文、授予、审批| API
  CLI -->|同步、审批轮询、审计| API
  API --- DB
```

人在手机上编辑条目。应用用 VMK 包裹每条的密钥，用条目密钥加密内容，用 Secure Enclave 签名。密文上传到同步服务。

CLI 配对之后，只同步自己被授予的条目。它在本地解开这些密钥，执行命令，把审计事件加密给 owner 的公钥再上传。

审批路径不走持久授权。CLI 把「将要执行的命令」（仍然是 `ref`，不是秘密）加密给 iPhone。人在手机上同意之后，iOS 用 CLI 的公钥做一次一次性 HPKE 包裹。CLI 取回、使用、从内存清掉。服务器看不到包裹里的密钥。

```mermaid
sequenceDiagram
  autonumber
  participant Agent
  participant CLI as keyref CLI
  participant API as Sync API
  participant Phone as iOS
  participant Child as 子进程

  Agent->>CLI: exec --env OPENAI_API_KEY=openai-prod -- curl ...
  CLI->>CLI: 解析 ref，核对本地策略
  alt 条目要求 approval
    CLI->>API: 发给 owner 的加密审批请求
    Phone->>API: 打开应用时拉到待处理请求
    Phone->>Phone: Face ID，展示命令与 ref
    Phone->>API: 一次性 HPKE 包裹
    CLI->>API: 取回包裹并解开
  end
  CLI->>Child: posix_spawn，秘密只进入 env 或 fd
  Child-->>CLI: stdout 与 stderr
  CLI->>CLI: 脱敏
  CLI-->>Agent: 脱敏后的输出和退出码
  CLI->>API: 加密审计事件
```

MVP 的在线方式是短请求。CLI 在等待审批时每 1–2 秒轮询一次，而不是占住一个 Worker 做长连接。手机在 Phase 2 用 APNs 获知新请求；Phase 1 可以在应用打开时轮询。Workers 的计费按请求和 CPU，不用为了审批去上 WebSocket 或 Durable Objects。

## 6. 数据模型

### 6.1 条目在加密之前的样子

一条逻辑条目拆成两份明文，用两把不同的密钥加密。这样「可以看见名称」和「可以使用秘密」能分开授予。

Meta（由 meta key 加密）：

```json
{
  "v": 1,
  "ref": "openai-prod",
  "name": "OpenAI 生产密钥",
  "description": "文档代理用来调用模型",
  "type": "api_key",
  "masked": "sk-****abcd",
  "injectable": true,
  "policy": {
    "sensitivity": "standard",
    "commandPolicy": "deny-shells",
    "allowCommands": [],
    "allowedHosts": ["api.openai.com"],
    "allowArgv": false
  }
}
```

Secret（由 item key 加密）：

```json
{
  "v": 1,
  "value": "sk-example",
  "username": "",
  "notes": "",
  "fields": {}
}
```

`type` 取 `api_key`、`token`、`password`、`note`、`generic`。

- `note` 的 `injectable` 默认是 `false`。CLI 拒绝把笔记注入命令，直到人在手机上打开。
- `password` 和 `note` 的 `masked` 永远是 `***`。口令通常更短，末几位本身就能用。
- `api_key` 和 `token` 按最长前缀匹配：`github_pat_`、`sk-proj-`、`sk-ant-`、`glpat-`、`xoxb-`、`xoxp-`、`xoxa-`、`ghp_`、`gho_`、`sk-`、`AKIA`。总长度至少比前缀多 8 个字符时，`masked` 保留前缀和末四位，例如 `sk-****abcd`。否则是 `***`。
- `masked` 由 iOS 在保存时算好，放进 meta。`list` 和 `get` 只解 meta，不碰 secret。这样 `approval` 条目（CLI 只有 view 授权）也能显示 `sk-****abcd`，同时 `list` 这条更容易写错的路径上根本没有明文。
- 代价是：任何拿到 view 授权的 agent 都能看见 API key 的前缀和末四位。这是有意接受的小泄露。若要关掉，把 `masked` 固定成 `***` 即可，协议不用改。

`ref` 的语法：`^[a-z][a-z0-9-]{0,62}[a-z0-9]$`，或者单字符 `[a-z]`。在一个保险库里唯一。MVP 里创建之后不可改。改名会悄悄打断已经写进脚本和对话里的引用，所以留到以后单独立项，并要求人显式确认。

`sensitivity`：

| 值 | CLI 平时拿到的密钥 | `exec` 时 |
| --- | --- | --- |
| `standard` | meta key 和 item key 的长期包裹 | 配对完成且策略通过即可运行，不必每次按手机 |
| `approval` | 只有 meta key | 每次执行向手机要一次性 item key |

无人值守的 agent 用 `standard`。生产密钥、邮箱密码、云账号根密钥建议用 `approval`。默认值见开放问题；设计里的推荐默认是 `standard` 加上 `deny-shells`，避免产品第一天就无法无人使用。

### 6.2 标识

- `vault_id`、`device_id`、`item_id`、`approval_id`：16 字节随机数，编码为小写 hex。不用自增整数，避免把创建顺序以外的业务含义编码进去（创建顺序本来就会被时间戳暴露）。
- `ref` 是给人看的稳定名字，不是主键。它在密文里。
- 服务器上的 `revision` 是该条目的单调整数，从 1 开始，由 owner 签名覆盖。客户端拒绝比本地已见版本更小的 revision。

### 6.3 服务器上看见的表

D1 就是 SQLite。下面的形状同时是将来自托管时的 schema。时间用 Unix 毫秒。二进制列存原始字节。

```sql
CREATE TABLE vaults (
  vault_id            TEXT PRIMARY KEY,
  created_at          INTEGER NOT NULL,
  recovery_wrap       BLOB,
  recovery_kdf_json   TEXT,
  directory_revision  INTEGER NOT NULL,
  directory_signed    BLOB NOT NULL
);

CREATE TABLE devices (
  device_id       TEXT PRIMARY KEY,
  vault_id        TEXT NOT NULL,
  kind            TEXT NOT NULL, -- ios | cli
  status          TEXT NOT NULL, -- pending | active | revoked
  hpke_kem        TEXT NOT NULL, -- P-256 | X25519
  hpke_public_key BLOB NOT NULL,
  sign_alg        TEXT NOT NULL, -- ecdsa-p256 | ed25519
  sign_public_key BLOB NOT NULL,
  label           TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  revoked_at      INTEGER
);

CREATE TABLE items (
  vault_id                 TEXT NOT NULL,
  item_id                  TEXT NOT NULL,
  revision                 INTEGER NOT NULL,
  tombstone                INTEGER NOT NULL,
  meta_ciphertext          BLOB,
  secret_ciphertext        BLOB,
  vault_wrapped_meta_key   BLOB,
  vault_wrapped_item_key   BLOB,
  writer_device_id         TEXT NOT NULL,
  signature                BLOB NOT NULL,
  updated_at               INTEGER NOT NULL,
  PRIMARY KEY (vault_id, item_id)
);

CREATE TABLE grants (
  vault_id    TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  item_id     TEXT NOT NULL,
  kind        TEXT NOT NULL, -- view | use
  hpke_enc    BLOB NOT NULL,
  wrapped_key BLOB NOT NULL,
  expires_at  INTEGER,
  signature   BLOB NOT NULL,
  PRIMARY KEY (vault_id, device_id, item_id, kind)
);

CREATE TABLE approvals (
  approval_id          TEXT PRIMARY KEY,
  vault_id             TEXT NOT NULL,
  cli_device_id        TEXT NOT NULL,
  item_id              TEXT NOT NULL,
  request_ciphertext   BLOB NOT NULL,
  status               TEXT NOT NULL, -- pending | approved | denied | expired | consumed
  one_time_wrap        BLOB,
  expires_at           INTEGER NOT NULL,
  created_at           INTEGER NOT NULL
);

CREATE TABLE audit_events (
  vault_id    TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  device_id   TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  ciphertext  BLOB NOT NULL,
  PRIMARY KEY (vault_id, seq)
);

CREATE TABLE changes (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  vault_id   TEXT NOT NULL,
  entity     TEXT NOT NULL,
  entity_id  TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE pair_sessions (
  nonce_hash  TEXT PRIMARY KEY,
  hpke_public_key BLOB NOT NULL,
  sign_public_key BLOB NOT NULL,
  proposed_name   TEXT NOT NULL,
  expires_at      INTEGER NOT NULL,
  consumed_at     INTEGER
);
```

`vault_wrapped_*` 是用 VMK 包起来的 meta key / item key，给 owner 的其他设备用。它们是密文，服务器解不开。新 iPhone 只要拿到 VMK（恢复密钥或旧手机配对），就能解开全部条目。

`grants.kind = view` 包裹的是 meta key。`kind = use` 包裹的是 item key。`approval` 条目只有 `view`，没有长期的 `use`。

`directory_signed` 是 owner 签过名的当前有效设备名单和 `directory_revision`。客户端用它判断撤销是否生效。诚实的服务器只负责递送这份签名。

索引至少要有：`changes(vault_id, seq)`、`grants(vault_id, device_id)`、`devices(vault_id, status)`。D1 按扫描行数计费，这些查询都必须打在索引上。

### 6.4 明文元数据与密文的边界

服务器可以看见，因为没有这些就无法路由：

- `vault_id`、`device_id`、`item_id`、`revision`、tombstone 标记
- 设备种类、状态、公钥、算法标识
- 哪台设备被授予了哪个 `item_id`（授权图）
- 审批单的状态和过期时间
- 密文长度、服务器收到的时间
- 设备的 `label`（来自配对时 CLI 自报的名字，最多 32 字节，owner 可以改）。它是明文，方便在另一台设备的列表里显示「哪一台」。想隐藏机器名字时再把它挪进加密目录，MVP 不这么做

服务器看不见：

- `ref`、名称、描述、`type`、策略细节
- 秘密值、用户名、笔记
- 审批请求里的命令行（整段加密给 iPhone）
- 审计事件正文
- VMK、meta key、item key 的明文

授权图会泄露「这台 CLI 能碰 12 个条目」。这是为了让服务器可以只下发该设备的行，而不是把整个保险库的密文都给每一台 CLI。这个泄露是接受的。条目内容仍然是密文。

### 6.5 客户端本地状态

CLI 目录权限 `0700`：

| 位置 | 内容 |
| --- | --- |
| 操作系统密钥环 | CLI 的 X25519 私钥、Ed25519 私钥 |
| `cache.sqlite` 模式 `0600` | 服务器来的密文、revision、已验证的签名。不是明文 |
| 进程内存 | 解开的 meta key / item key。`mlock` 尽力锁页，退出和 `lock` 时 `zeroize` |
| 不落盘 | 解开后的秘密值、子进程环境块、fd 模板渲染结果 |

缓存里的对象本来就是端到端密文，所以不再做第二层加密。同机其他 Unix 用户靠目录权限挡住。同一用户的恶意程序能读到密文，这落在 B1/B2。

会话：密钥环里的设备私钥在机器登录态里可用。解开的 item key 在内存里默认保留 8 小时，超时后用密钥环里的私钥对本地缓存的包裹重新解开，不必再扫一次二维码。`keyref lock` 立刻清内存。`standard` 条目因此可以无人值守。`approval` 条目没有可重解的本地 item key。解开 item key 不等于把 secret 明文放进内存：明文只在单次 `exec` 的注入和脱敏期间存在，这次执行结束就清掉。

离线：缓存里已有的 `use` 授权可以离线 `exec`。过期时间由诚实的 CLI 执行。需要新的一次性密钥时必须在线。

## 7. 引用语法与 exec

### 7.1 人写在命令里的形式

canonical 占位符：

```text
{{keyref:openai-prod}}
```

等价的 URI，便于写进只接受 URL 的配置说明里：

```text
keyref://openai-prod
```

不支持在占位符里做编码变换（没有 `{{keyref:openai-prod | base64}}`）。变换是外泄通道，也让脱敏更难。

三种调用方式，按推荐顺序：

```bash
# 1. 环境变量。参数里没有秘密。适合自己读 env 的程序。
keyref exec --env OPENAI_API_KEY=openai-prod -- \
  openai api models.list

# 2. 额外的文件描述符。适合 curl 这种不会自己读 env 的程序。
keyref exec \
  --fd 3=openai-prod \
  --fd-template 'header "Authorization: Bearer {{keyref}}"' -- \
  curl --config /dev/fd/3 https://api.openai.com/v1/models

# 3. 标准输入就是秘密，然后关闭 stdin。
keyref exec --stdin github-pat -- \
  gh auth login --with-token
```

`--` 后面是 argv，原样交给子进程。keyref 不启动 `sh -c`。因此 argv 里的 `$OPENAI_API_KEY` **不会**被 shell 展开。需要秘密出现在参数里时，必须写成占位符并加上 `--allow-argv`：

```bash
keyref exec --allow-argv -- \
  mytool --token '{{keyref:openai-prod}}'
```

这个模式会在审计里标成 argv 注入。`ps` 和 macOS 的 Activity Monitor 能看到参数。文档和 CLI 的 stderr 提示都要说明这件事。stderr 提示本身不能打出秘密。

`--fd-template` 只允许一个记号 `{{keyref}}`，表示该 fd 绑定的那一条秘密。模板由 keyref 在内存里渲染，写入 fd。子进程的 argv 里只有 `/dev/fd/3` 这样的路径。

fd 的落地方式：

1. 优先 `memfd` 或 `O_TMPFILE`。
2. 否则在 `0700` 目录里 `open(O_CREAT|O_EXCL, 0600)`，写入后立刻 `unlink`，再把仍然打开的 fd 传给子进程。路径消失，`/tmp` 里不会留下一个给后续命令读的文件名。
3. macOS 用 `/dev/fd/N`。实现时要在目标系统上确认 `posix_spawn` 的 file action 能把这个 fd 交给子进程。

stdin 的默认行为是：写入秘密，需要的话补一个换行，然后关闭写端。不把 agent 的 stdin 拼在秘密后面。需要先写秘密再转发调用方 stdin 时，用单独的 `--stdin-then-proxy`，并且审计里记录这个选择。

pty：

```bash
keyref exec --pty \
  --reply 'Password:=wifi-home' -- \
  some-login-tool
```

keyref 掌握 pty 主端。子进程的输出先过脱敏器，再交给 agent。`--reply` 的正则若匹配到**已脱敏前**的输出，keyref 把对应秘密写进 pty 输入，就像有人在键盘上输入。正则由 agent 提供，恶意程序可以打印 `Password:` 来触发写入。因此 `--reply` 只允许用在该条目的 `allowCommands` 明确包含这个 argv0 的时候，并且条目建议设为 `approval`。Phase 1 可以先不做 `--pty` / `--reply`，把接口定在这里。

### 7.2 启动子进程时的环境

子进程不继承 CLI 的全部环境。keyref 构造一份新环境：

- 保留一份短名单：`PATH`、`HOME`、`USER`、`LOGNAME`、`LANG`、`LC_ALL`、`TERM`、`TMPDIR`
- 丢掉 `LD_PRELOAD`、`LD_LIBRARY_PATH`、`DYLD_INSERT_LIBRARIES`、`DYLD_LIBRARY_PATH` 以及其他 `DYLD_*` / `LD_*`
- 加上本次 `--env` 指定的变量

同时设置 `RLIMIT_CORE = 0`。在 Linux 上于子进程里尝试 `PR_SET_DUMPABLE = 0`，并在实现时验证 `execve` 之后标志是否还在。不要在文档里把它写成已经封死 `/proc/<pid>/environ`。同一用户的 `procfs` 可读性是 B2，靠集成约束和以后的沙箱处理。

### 7.3 默认拒绝的命令

`commandPolicy = deny-shells` 时，argv0 的 basename（大小写不敏感）落在下面的集合里就拒绝执行：

```text
sh bash zsh dash fish ksh csh tcsh busybox
env printenv
echo printf
cat tee dd od xxd hexdump base64 base32
openssl
python python2 python3 node nodejs deno bun perl ruby php lua
osascript socat
```

拒绝时退出码 `10`，说明是策略拒绝，并提示要在 iOS 里修改该条目的 `allowCommands`。错误文本里不回显秘密。

`allowCommands` 非空时，它变成白名单：argv0 必须命中其中一项。白名单里的名字可以覆盖上面的默认拒绝。覆盖默认拒绝时，iOS 保存前提示风险。解释器一旦被允许，模型就可以用它把秘密切片打印，脱敏器会失明。所以对 `python`、`node`、`sh` 的显式允许应该和 `sensitivity = approval` 一起用。

`allowedHosts` 为空表示 MVP **不做**主机检查。不要把空列表解释成「禁止所有网络」。非空时，CLI 扫描 argv 里的 `http://` 和 `https://`，主机名必须与列表完全一致（不接受后缀匹配，`api.openai.com.evil.example` 不能通过 `api.openai.com`）。这是尽力而为：

- IP 字面量、DNS 重绑定、HTTP 重定向、程序自己拼出来的 URL，静态扫描都看不见
- `curl` 默认跟随重定向，允许的主机可以把秘密 302 到别处

真正能约束出口的是 Phase 3 的沙箱加本地代理。在那之前，UI 上把主机列表叫「参数检查」，不要叫「网络隔离」。

### 7.4 脱敏

脱敏发生在 CLI 把子进程输出转交给调用方之前，覆盖 stdout、stderr 和 pty 输出。

对每一个本次注入过的秘密值（长度至少 8；更短的值仍然尝试匹配，但短值误伤和漏检都更严重，创建密码时 UI 可以警告过短）：

- 原始字节
- Base64 与 Base64 去掉填充
- Base64url 与去掉填充
- 小写 hex、大写 hex
- RFC 3986 percent-encoding
- 跨 read 缓冲区的切分：保留 `len(secret) * 2` 量级的重叠窗口，具体常数在实现里按最长编码（hex 是 2 倍）来定

替换文本是固定的 ASCII：

```text
<redacted:openai-prod>
```

不用会让终端或 JSON 解析更麻烦的符号。替换文本本身如果偶然出现在正常输出里，可能被再次看到，这可以接受。

脱敏器内部出错时，杀掉子进程，丢弃已经读到的缓冲区，向调用方返回退出码 `14` 和一条不含输出片段的错误。不要「尽量输出」。

不做的事情，避免给人错误的安全感：

- 不检测任意切片、反转、ROT13、插空格
- 不检测秘密被写进子进程打开的文件
- 不检测子进程发出的网络流量

这些缺口用拒绝解释器、审批和 Phase 3 沙箱来收，不靠输出过滤器。

### 7.5 泄漏路径

| 路径 | MVP 的处理 |
| --- | --- |
| 模型上下文 / 工具返回值 | `list` 与 `get` 没有 value 字段。`exec` 输出先脱敏 |
| Shell 历史 | 不经过 shell。人自己敲的 `keyref exec ...` 历史里只有 `ref` |
| `ps` 的 argv | 默认不把秘密放进 argv。`--allow-argv` 明确接受这个泄露 |
| `/proc/<pid>/environ`、macOS `ps e` | 与 argv 相比，环境变量不会被系统里所有用户在进程列表里看到，但同一用户可以读。这是 B2。文档把 env 排在 argv 前面，是因为暴露面更窄，不是因为 agent 读不到 |
| 临时文件 | 0600、目录 0700、写入后 unlink |
| 子进程把秘密写到磁盘，后续命令再读 | 默认拒绝 `cat` / shell。若 harness 另有 shell，则属于 B2 |
| `exec -- echo {{keyref:x}}` 或 `exec -- env` | 默认拒绝 |
| CLI 日志、崩溃转储 | 不记录解开的值。关闭 core dump。密钥缓冲区 zeroize |
| 交换分区 | 对密钥页 `mlock`，失败只记调试计数，不把秘密写进日志 |
| 审批界面被模型骗 | 手机上展示的是 argv 原文、`ref`、条目名称、注入方式。人看到的是 `curl https://evil.example`，不是一个已经被替换成密钥的字符串 |
| 服务器篡改密文或回滚 | owner 签名 + 客户端保存的最高 revision。服务器可以拒绝服务，不能让诚实客户端接受伪造条目 |
| 撤销后离线使用 | 见 B6。撤销 UI 的默认动作是轮换受影响条目的 item key |

### 7.6 退出码

| 码 | 含义 |
| --- | --- |
| 子进程自身的码 | 策略已通过并且脱敏完成 |
| 10 | 策略拒绝，子进程没有启动 |
| 11 | 未知 `ref`，或此设备没有 view 授权 |
| 12 | 本地会话锁着，密钥环里没有可用的设备私钥 |
| 13 | 审批被拒绝或超时 |
| 14 | 脱敏失败，原始输出已丢弃 |

`keyref get` 在没有这条 `ref` 时也用 `11`。

### 7.7 审计

每一次尝试都记一条，包括被拒绝的尝试。正文加密给当前 owner 设备的 HPKE 公钥（多台 iPhone 时，随机一个事件密钥，分别 HPKE 给每台 owner）。CLI 自己不保留可解密的副本。

事件明文里有：时间、`device_id`、`ref` 列表、注入方式、argv（占位符形式，不是替换后的秘密）、是否 `--allow-argv`、策略结果、审批结果、子进程退出码、脱敏替换次数。没有秘密值。

服务器只看见 `vault_id`、`seq`、`device_id`、时间和密文。iOS 解密后按时间展示。保留期的默认建议是 30 天在 D1，更久的归档放到 Phase 3 的 R2。这是费用上的选择，见第 10 节。

## 8. 配对、会话与审批

### 8.1 配对

CLI 没有摄像头，所以二维码由 CLI 显示，iPhone 来扫。

1. `keyref pair` 在本地生成 X25519（HPKE）和 Ed25519（签名）密钥，私钥写入密钥环。
2. 终端打印二维码，内容是 `keyref://pair?v=1&k=...&s=...&n=...&name=...`。体积控制在约 120 字节量级，方便低分辨率终端二维码。同时打印 CLI 签名公钥的指纹：SHA-256 的前 8 字节，显示为 `A1B2-C3D4-E5F6-7890`。
3. CLI 用私钥签 nonce，向服务器登记一个 10 分钟有效的 `pair_sessions` 行，并开始轮询。
4. iOS 扫描后展示指纹、对方自报的名字，以及**默认不勾选**的条目列表。人点名要授予的条目，再用 Face ID 确认。
5. iOS 用 Secure Enclave 签名配对誊本：`nonce`、双方公钥、`vault_id`、新 `device_id`、授予列表。
6. 服务器核对 nonce 未使用、CLI 的登记公钥与签名一致，然后写入 `devices` 和 `grants`。
7. CLI 取回结果，验证 iOS 的签名，把 iOS 签名公钥钉死在本地配置里。之后所有授予和设备目录更新都必须由这把已钉死的 owner 密钥，或目录里后来增加并被它签名接纳的 owner 密钥签署。

恶意服务器没有 Secure Enclave 的签名，不能自己完成配对。用户仍须核对两边的指纹，避免自己扫到旁边屏幕上的二维码。授予默认是空集，扫码成功不会自动交出所有密钥。

配对不建立邮箱账号。`vault_id` 是随机的，保存在 iPhone 的 Keychain 里（`ThisDeviceOnly`）。

### 8.2 会话令牌

设备用签名私钥签服务器挑战，换一个随机 bearer token，有效期 12 小时，可重新签名续期。D1 里只存 `SHA-256(token)`。

这个令牌被偷走的后果是：攻击者能替这台设备拉取 **它已被授予的密文**、提交审计、发起审批。攻击者解不开密文，除非同时拿走到 CLI 的私钥。所以令牌和密钥环是两层。CLI 发现本地设备被目录撤销后，删除本地包裹和缓存。

### 8.3 审批

`approval` 条目的一次执行：

1. CLI 生成一次性 X25519 密钥（可以复用设备长期密钥；更稳妥的是每条审批一把临时密钥，用完丢掉私钥）。推荐临时密钥，缩小手机误批之后的窗口。
2. 请求正文（argv、`ref`、注入模式、主机名、临时公钥）HPKE 给 owner。
3. iOS 展示解密后的命令。Face ID 通过后，用临时公钥包裹这一条的 item key，`expires_at` 为 60 秒，`status = approved`。
4. CLI 取走包裹。服务器把该行标成 `consumed` 并清掉包裹字节。
5. CLI 在这一次 `exec` 结束后 zeroize item key。

超时默认 2 分钟，然后 CLI 以退出码 `13` 结束。人拒绝同样是 `13`。

Phase 1 如果还没有推送，iOS 在前台轮询 `GET /v1/approvals?status=pending`。这够用来打通协议。Phase 2 再接 APNs。APNs 需要 Apple Developer Program，费用和账号是开放问题里的一项。

### 8.4 授予的有效期与撤销

`use` 授予默认 30 天到期。iOS 在设备仍处于有效目录里、并且手机解锁联网时，于到期前重新包裹并顺延。手机连续 30 天没有回来续期的话，诚实的 CLI 会停用这些授予。诚实的 CLI 在 `expires_at` 之后停止使用本地 item key，即使它错过了撤销同步。被改过的 CLI 会忽略这个时间，所以过期不能代替轮换。

iOS 上撤销一台 CLI 的默认动作：

1. 签一份新的设备目录，该设备 `status = revoked`。
2. 删除它的 grants。
3. **轮换**它曾经拥有 `use` 授权的每条 item key：新密钥、用新密钥重加密 secret、重新包裹给剩余设备。meta 若没有泄露可以不轮换。
4. 被撤设备下次同步收到 tombstone 和新目录。已经拷走旧 item key 的攻击者解不开新的 secret 密文。

「只撤销、不轮换」放在二级确认后面，用于确认设备只是停用、密钥并没有离开那台机器的时候。UI 要写明 B6。

VMK 轮换是稀有操作：重新包裹全部 meta key 和 item key，条目密文可以不动。怀疑恢复密钥泄露时必须轮换 VMK，并作废旧的 `recovery_wrap`。

## 9. 密码学

### 9.1 原则

只组合公开算法，不发明新的原语。实现时用各自平台上维护中的库（Apple CryptoKit / swift-crypto、Rust 的 `hpke` 与 `aes-gcm`）。

| 用途 | 算法 |
| --- | --- |
| 条目 meta、secret、审计正文、审批正文 | AES-256-GCM，12 字节随机 nonce |
| 把密钥包给另一台设备 | RFC 9180 HPKE base mode |
| 包给 iOS Secure Enclave | `DHKEM(P-256, HKDF-SHA256)` + `HKDF-SHA256` + `AES-256-GCM` |
| 包给 CLI | `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `AES-256-GCM` |
| iOS 签名 | P-256 ECDSA，密钥在 Secure Enclave |
| CLI 签名 | Ed25519 |
| 从高熵恢复密钥派生 | HKDF-SHA256 |
| 可选的人类口令 | Argon2id |

选用 AES-256-GCM 而不是 XChaCha20-Poly1305，是因为 CryptoKit、WebCrypto、Go、Rust 都自带它，MVP 不必在 iOS 上再链一份 libsodium。nonce 风险在这个数据规模上不成立：一把 item key 加密一个版本的 secret，一把 VMK 为每个条目包裹两把密钥。随机 96 位 nonce 在远低于 2^32 次加密时碰撞可以忽略。约定：任何一把密钥的加密次数接近 2^32 之前就轮换。keyref 的条目尺寸到不了这个量级。若以后做大文件流式加密，那些对象再改用 XChaCha20-Poly1305，不回头改条目格式。

HPKE 的 `info` 做域分离，UTF-8 字符串，字段用 ASCII unit separator（`0x1f`）连接：

```text
keyref v1 <US> <purpose> <US> <vault_id> <US> <recipient_device_id>
```

`purpose` 取 `vmk`、`meta-key`、`item-key`、`one-time-item-key`、`audit-event-key`、`approval-request`。

条目密文的 AAD 用同一套分隔，避免拼接歧义：

```text
keyref v1 <US> secret <US> <vault_id> <US> <item_id> <US> <revision>
```

meta 密文把 `secret` 换成 `meta`。签名覆盖的誊本是字节串而不是 JSON，避开 JSON 规范化：

```text
KEYREF1 <NUL> item <NUL> <vault_id> <NUL> <item_id> <NUL>
<revision uint64 be> <NUL> <meta ciphertext> <NUL> <secret ciphertext> <NUL>
<vault_wrapped_meta_key> <NUL> <vault_wrapped_item_key> <NUL> <writer_device_id>
```

客户端在解密之前验签。服务器也可以验签，用来丢弃垃圾请求。客户端不能因为「服务器说验过了」就跳过自己的验证。

### 9.2 密钥层次

```mermaid
flowchart TB
  SE["Secure Enclave P-256 协定密钥"]
  Sign["Secure Enclave P-256 签名密钥"]
  VMK["VMK 256 bit，只在解锁后的 iOS 内存里"]
  Rec["恢复密钥 256 bit"]
  MetaK["meta key"]
  ItemK["item key"]
  MetaCT["meta 密文：ref、名称、描述、策略"]
  SecCT["secret 密文：value"]
  CLIkey["CLI X25519"]

  SE -->|HPKE purpose=vmk| VMK
  Rec -->|AES-256-GCM| VMK
  VMK -->|包裹| MetaK
  VMK -->|包裹| ItemK
  MetaK --> MetaCT
  ItemK --> SecCT
  Sign -->|给密文和设备目录签名| MetaCT
  MetaK -->|HPKE view 授权| CLIkey
  ItemK -->|HPKE use 授权，approval 条目没有这条长期边| CLIkey
```

VMK 不到 CLI，也不到服务器。CLI 被妥协时，损失限于已经授予它的 `use` 条目，不是整个保险库。

Secure Enclave 只能生成和使用 NIST P-256，不能生成 X25519，也不能把已有的私钥导入隔区。所以 owner 的包裹和签名走 P-256。CLI 没有隔区，用软件里的 X25519 和 Ed25519，私钥放在操作系统密钥环。

HPKE 与 Secure Enclave 的衔接是实现期风险最高的一处：RFC 9180 的 DHKEM 私钥运算要和 `SecureEnclave.P256.KeyAgreement` 的 ECDH 结果对齐，再按 RFC 做 LabeledExtract / LabeledExpand。Phase 1 的第一项密码学任务是提交跨语言测试向量：Rust 包给 P-256 公钥的 VMK，Swift 用隔区私钥解开，以及反方向的条目密钥包裹。

若隔区私钥无法严格走完 DHKEM，退路是：Keychain 里存一把软件 P-256 私钥，访问控制设为「需要设备密码，且生物识别，`ThisDeviceOnly`」。Face ID 仍然在每次解 VMK 时出现。退路比隔区弱的地方是：解锁之后，被攻破的操作系统内核有机会导出这把软件私钥。退路必须在文档和代码里显式标注，不能静默替换。

### 9.3 创建保险库

1. 生成 VMK（32 字节，系统 CSPRNG）。
2. 生成 Secure Enclave 协定密钥和签名密钥，访问控制 `.biometryCurrentSet`（或等价的「当前生物特征集合」），并要求设备密码。
3. 用协定公钥 HPKE 包裹 VMK，密文放在本机 Keychain，`ThisDeviceOnly`，不进 iCloud 备份。隔区私钥本身也不能离开这台设备。
4. 生成 256 bit 恢复密钥，显示一次。编码用 Crockford Base32，分组，避免 0/O、1/I。用户抄到纸上或放进另一个已经信任的保险库。
5. `recovery_wrap = AES-256-GCM(HKDF(recovery_key), VMK)`，这份密文可以上传。服务器没有恢复密钥。不在服务器存恢复密钥的哈希，验证靠 AEAD tag。
6. 可选：再用一个 Argon2id 口令包一份 VMK。默认参数 `m = 64 MiB`、`t = 3`、`p = 1`、输出 32 字节、盐 16 字节。这是偶尔用于恢复的参数，不是每次解锁都跑的 KDF。实现时对照当时的 OWASP Password Storage Cheat Sheet，不得低于它的下限。解锁日常路径是生物识别，不是这个口令。

丢掉手机又丢掉恢复密钥，数据就没有了。UI 在创建结束前要求人确认已经记下恢复密钥。不做「客服帮你重置」，那会要求服务器能解密。

### 9.4 第二台 iPhone

两条路，MVP 可以只做恢复密钥这一条，旧手机配对放到 Phase 2：

- 在新手机输入恢复密钥，下载 `recovery_wrap` 和全部条目密文，解开 VMK，然后在新隔区里重新包裹一份 VMK。
- 或者旧手机扫新手机的二维码，Face ID 之后把 VMK HPKE 给新手机的 P-256 公钥。

两台 owner 都进入签名过的设备目录。条目写入仍然由任一 owner 发起；MVP 不解决两台手机同时离线编辑。冲突策略：revision 更大的签名版本获胜；revision 相同但密文不同则 iOS 把两边都显示出来让人处理。服务器不合并明文。

### 9.5 本地解锁

iOS 每次从后台进入前台，应用内存里没有 VMK 时，要求 Face ID，让隔区完成 ECDH，解开 VMK。自动锁定间隔建议默认 1 分钟进后台即锁定，具体秒数可以做成设置。VMK 和解开的条目只活在内存里。

CLI 侧没有 Face ID。`standard` 条目的无人值守依赖本机密钥环。这是有意的产品选择：要求每条命令都按手机，agent 就没法在人离开时工作。风险被限制在「这台已经被配对、并且被授予了这些 standard 条目的机器」。

## 10. 存储与同步

### 10.1 服务要做什么

同步服务是一个哑存储加一点点鉴权：

- 认出设备（签名挑战，发会话令牌）
- 按 vault 存密文，按设备过滤 grants
- 提供单调的变更游标
- 暂存审批请求和一次性包裹
- 拒绝明显非法的写入（CLI 改条目、已撤销设备、超大 body、revision 回退）

它不实现搜索、不实现分享链接、不实现「用邮箱找回」。

### 10.2 方案比较

价格按 2026-10-20 能查到的公开标价。标价会变，开工前再对一次。下面的用量是设计假设，不是预测。

假设一条密文加包裹大约 2 KB。一个人 50 到 100 条。一次 `exec` 产生一条审计。CLI 在真正执行命令或 `sync` 时才访问网络，空闲时不轮询。

| | Cloudflare Workers + D1 | Supabase（托管 Postgres） | 小 VPS + SQLite + Litestream | iCloud CloudKit |
| --- | --- | --- | --- | --- |
| 早期费用 | Free 为 $0。正式跑建议 Workers Paid，底价 $5/月 | Free 为 $0，但是项目闲置约 7 天会被暂停。Pro 从 $25/月起 | 小规格实例大约每月数美元，外加对象存储的备份费用 | 同步流量本身通常不再单独计价，但要 Apple Developer 年费才能正经分发和推送 |
| 秘密数据的费用敏感点 | 请求数、D1 行读写、超过 5 GB 之后的存储 | 磁盘、出站流量、计算规格。按行读写不计费 | 磁盘和备份。出站取决于厂商 | 不适合拿来估算「每条秘密多少钱」 |
| 运维 | 没有机器要补丁。需要理解 Workers / D1 的配额 | 平台代管，但要处理暂停、计算规格和备份策略 | 系统补丁、磁盘、TLS、进程守护、恢复演练都在自己身上 | Apple 代管，CLI 几乎接不进去 |
| 和端到端加密的匹配 | 好。Worker 只转发字节 | 好，但平台的 Auth、RLS、生成的 REST 会引诱人把名称做成明文列 | 好。完全自己控制 | 一般。CloudKit 有自己的账号和分享模型，还要再加一层加密 |
| CLI / Linux | 普通 HTTPS | 普通 HTTPS | 普通 HTTPS | 没有可用的 Linux 一等客户端 |
| 一致性 | D1 是 SQLite，写入之后读得到 | Postgres | SQLite | 最终一致，冲突模型是 CloudKit 的 |
| 以后搬走 | schema 就是 SQLite，可以搬到自托管 | 要改成另一套 SQL 方言和托管方式 | 已经是终点形态 | 数据模型和权限模型都绑在 Apple 上 |

Workers 的公开额度（同一天的文档）：

- Free：10 万请求/天，每次调用 10 ms CPU。D1 为每天 500 万行读、10 万行写、一共 5 GB。
- Paid：$5/月起，包含 1000 万请求/月，超出部分 $0.30 / 百万；CPU 时间另有包含额度。D1 包含每月 250 亿行读和 5000 万行写，存储 5 GB 之后 $0.75 / GB-月。
- R2：存储 $0.015 / GB-月，出站流量不收费。Class A 操作 $4.50 / 百万。免费额度是 10 GB-月、100 万次 Class A、1000 万次 Class B。MVP 不把热路径放在 R2 上。

Supabase 公开价：Free 含 500 MB 数据库，闲置约一周会暂停，最多两个活跃项目。Pro 从 $25/月起，含一个 Micro 计算实例的额度。密码同步服务不能接受「一周没人用就被暂停」。

CloudKit 适合「只有 Apple 设备」的同步。keyref 的 CLI 要跑在 agent 用的 Linux 上，CloudKit 不是这条链路的合格传输层。以后可以做「仅 iOS 设备之间的可选副本」，但不能当系统记录。

自托管 SQLite + Litestream（复制到 R2 或别的对象存储）在技术上很贴这个数据模型，费用也可以压到每月数美元。它输在运维：一个人维护的密码服务，补丁和恢复演练比租金贵。API 保持为普通的 HTTPS JSON，schema 保持为 SQLite，就是为了让这条路在真的需要内网部署时还走得通。

不用 Workers KV 当源：授权和游标需要事务和查询，KV 是最终一致的键值。不用 Durable Objects：审批用轮询就够，没有必要为了长连接引入另一套状态和计费。

### 10.3 推荐

**用 Cloudflare Workers + D1。** R2 只在以后归档审计或存放大附件时加入。

理由：

- 秘密很小，D1 的一行放得下。按行计费对「小行、有索引的读」是可预期的。
- 没有空闲暂停这种对密码库不可接受的行为。
- 出站流量不按 GB 收费，同步客户端分布在各地时账单不会被流量主导。
- SQL schema 和自托管 SQLite 相同，不把数据模型锁死在 Cloudflare。
- 应用层代码不调用任何 Cloudflare 专有的加密功能。Worker 里没有密钥。

费用量级，按「每次使用才同步、审计一条 1 KB、30 天留在 D1」估算：

| 规模 | 用量的量级 | 月费 |
| --- | --- | --- |
| 开发与个人，1–10 人 | 远低于 10 万请求/天，存储是 MB | $0，Free 足够开发 |
| 早期正式使用，约 100 个日活 | 大约 1 万请求/天，D1 写入以审计为主，低于每天 10 万行 | $0 到 $5。建议直接开 Paid，避开 Free 的 10 ms CPU 和每日封顶 |
| 约 1,000 个日活 | 每天数万请求；审计写入仍在 Free 的每日写上限附近或以下 | 按 $5 规划 |
| 约 10,000 个日活 | 大约 900 万请求/月，落在 Paid 包含的 1000 万以内。D1 读写也在包含额度里。30 天审计大约数 GB，有机会碰到 5 GB 之后的 $0.75 / GB-月 | 大约 $5–15 |

10,000 日活若把审计无期限留在 D1，存储会慢慢超过包含额度，这是账单里第一个该看的数。先做 30 天保留，而不是先做 R2。若把每一次审计都写成单独的 R2 对象，Class A 的 $4.50 / 百万次会比 D1 更贵，所以归档必须按天打包，不能一条对象。

Free 档适合开发和演示。只要有别人依赖它来解锁工作流，就按 **每月 5 美元** 的底价来规划，不要停在会在配额处直接报错的 Free 档上。

### 10.4 同步协议

`GET /v1/sync?cursor=<seq>` 返回该设备可见的变更，最多 100 条，加上新的 cursor。

CLI 可见的变更只有：自己的 grants、这些 grant 指向的 items、设备目录、与自己相关的审批。Owner 可见该 vault 的全部 items 和 grants。

每条 item 变更都带签名。客户端验证失败就停止应用这一批，并保留旧数据。cursor 只表示「服务器的日志位置」，不表示这些字节可信。可信来自签名和 revision。

写入条目时，服务器要求 `revision` 比已存储的大 1，并且签名在这台 active 的 ios 设备公钥下验证通过。不满足则 `409`。这不能阻止恶意服务器自己违反规则，但能阻止一个被盗的 CLI 令牌去破坏数据。

## 11. 服务端 API

基址形如 `https://sync.example/v1`。全部请求走 HTTPS。正文是 JSON，二进制字段用标准 Base64。单条 item 的请求正文上限 256 KiB，远大于 64 KiB 的秘密上限加上密文开销。

除了配对登记和创建保险库，请求都带 `Authorization: Bearer <token>`。

| 方法与路径 | 谁可以调用 | 作用 |
| --- | --- | --- |
| `POST /v1/vaults` | 新的 iOS 设备，用其签名公钥自签 | 创建保险库，提交 recovery_wrap 和第一份设备目录 |
| `POST /v1/pair/register` | 尚未加入 vault 的 CLI | 登记公钥和 nonce |
| `POST /v1/pair/complete` | iOS owner | 提交签过名的配对誊本和初始 grants |
| `GET /v1/pair/status?nonce=` | 正在配对的 CLI | 取回签过名的结果 |
| `POST /v1/session` | 已登记设备 | 用签名换 bearer token |
| `GET /v1/sync?cursor=` | 已登录设备 | 增量同步 |
| `PUT /v1/items/:item_id` | iOS owner | 上传新 revision 的密文 |
| `DELETE /v1/items/:item_id` | iOS owner | tombstone |
| `PUT /v1/grants` | iOS owner | 写入或更新包裹 |
| `DELETE /v1/grants` | iOS owner | 删除授予 |
| `PUT /v1/directory` | iOS owner | 更新签名过的设备目录 |
| `POST /v1/approvals` | CLI | 提交加密的审批请求 |
| `GET /v1/approvals?status=pending` | iOS owner | 拉取待审批 |
| `POST /v1/approvals/:id/decision` | iOS owner | 同意（附一次性包裹）或拒绝 |
| `GET /v1/approvals/:id` | 发起的那台 CLI | 轮询；取走后服务器清掉包裹 |
| `POST /v1/audit` | 已登录设备 | 追加一条加密审计 |
| `GET /v1/audit?cursor=` | iOS owner | 拉取审计密文 |

服务器做的校验：

- 设备属于这个 vault，且 `status = active`
- `kind = cli` 的令牌调用 `PUT /v1/items` 或 `DELETE /v1/items` 时返回 `403`
- 签名字段存在，且在该设备当前公钥下验证通过
- item revision 严格递增
- body 大小、`ref` 不在服务器上出现（服务器也不去解密检查）
- 每设备每分钟请求数上限，建议 60，审批轮询单独给一个略宽的上限

服务器不做的事情：解密、根据名称去重、给 CLI 一份「所有条目的列表」。去重 `ref` 是 owner 在本地加密前做的。两台 owner 离线时可能造出相同 `ref`，同步之后由 iOS 显示冲突。

错误正文是固定的错误码，例如 `revision_conflict`、`device_revoked`、`body_too_large`。不要把请求里的字段回显进错误，以免以后有人把明文误传到服务器时又被错误日志放大。

## 12. 三个组件

### 12.1 iOS

Swift 与 SwiftUI，最低 iOS 17。CryptoKit 提供 P-256、AES-GCM、HKDF，以及和 swift-crypto 对齐的 HPKE。生物识别用 `LocalAuthentication`。密钥持久化用 Keychain。

界面用简体中文。至少这些状态要有真实文案，而不是占位句：

- 未创建保险库
- 已锁定，等待 Face ID
- Face ID 失败
- 列表为空
- 同步失败（本地修改仍在）
- 等待 CLI 扫码配对
- 没有待审批的请求
- 恢复密钥只显示一次的警告

主要流程：

1. 创建保险库，展示恢复密钥，确认已抄写。
2. 列表显示名称、`ref`、类型、掩码。
3. 详情里可以编辑名称、描述、`ref`（仅创建时）、值、策略。查看明文需要再验证一次 Face ID。
4. 扫 CLI 的二维码，核对指纹，勾选条目，确认。
5. 设备列表里撤销。
6. 审批单上能看清命令和条目名称。
7. 审计列表由本机解密。

分析 SDK、崩溃上报默认不加。若以后要加，上传前必须去掉用户内容和密钥材料，这是另一项设计，不在 MVP 里顺手开启。

### 12.2 CLI

Rust。选择它是因为秘密缓冲区需要确定性的清零（`zeroize`），进程模型要直接 `posix_spawn`，并且希望给 agent 一个静态二进制。Go 的标准库和交叉编译更省事，但 GC 会复制含有秘密的内存，清零没有语言级保证。实现速度如果压过这一点，可以改用 Go，但那是对这条决定的推翻，不是两套都做。

机器可读输出用英文，避免模型还要处理本地化表头。

`keyref list` 的文本形式：

```text
REF          NAME                TYPE     MASKED
openai-prod  OpenAI production   api_key  sk-****abcd
wifi-home    Home Wi-Fi          password ***
```

`keyref list --format json` 的每个对象只有 `ref`、`name`、`description`、`type`、`masked`、`sensitivity`、`injectable`。`masked` 来自 meta，这条命令不解密 secret。没有 `value` 字段。测试夹具要断言 stdout 和 stderr 都不包含夹具明文及其 base64 / hex。

`keyref get openai-prod` 打印同一组字段。未知 `ref` 退出 `11`，输出里看不出这个保险库里还有哪些别的 `ref`（避免把「猜 ref」变成枚举；不过 `list` 本身会列出已授予的全部 `ref`，所以这只影响没有 view 授权的条目）。

命令一览：`pair`、`status`、`lock`、`unlock`、`sync`、`list`、`get`、`exec`。没有创建、删除、轮换，也没有 reveal。

### 12.3 服务器

TypeScript，跑在 Workers 上，用 D1。框架选体积小的路由库即可（例如 Hono），也可以直接用 Workers 的 fetch handler。校验用明确的 schema，字段未知则拒绝，避免把客户端多传的明文日志下来。

本地开发用 Wrangler。仓库里还没有这些文件。

配置里不放任何解密密钥。部署密钥是 Cloudflare 的 API token，和用户的 VMK 无关。

## 13. 路线图

### Phase 0 — 手机上的本地保险库

- 创建保险库、Face ID、隔区包裹 VMK、恢复密钥
- 条目的增删改、掩码、锁定
- 没有网络，也不能配对

这一阶段用来验证解锁体验和数据格式。格式要从 Phase 0 就按第 9 节来，避免以后迁移明文。

### Phase 1 — MVP

- 同步 API：vault、device、item、grant、sync、session
- iOS 扫码配对，默认不选任何条目
- CLI：`pair`、`list`、`get`、`exec` 的 `--env`、`--stdin`、`--fd`，脱敏，默认拒绝 shell
- 审计加密上传，iOS 能查看
- 跨语言 HPKE 测试向量
- 验收：夹具明文不出现在 CLI 输出里；`echo` / `env` / `sh` 被拒绝；服务器数据库转储里没有名称和秘密

### Phase 2 — 审批与交互

- `approval` 条目和一次性包裹
- APNs
- `--pty` 与 `--reply`
- `allowCommands` / `allowedHosts` 的手机界面
- 第二台 iPhone、撤销并轮换
- `keyref mcp`：工具只有 `list`、`get`、`exec`，返回值与 CLI 相同，仍然没有明文

MCP 放在 Phase 2 而不是 Phase 1，是因为 CLI 已经能被现有 agent 当成 shell 工具调用。若目标 agent 只能接 MCP、不能执行二进制，就把这一项提前。见开放问题。

### Phase 3 — 把 B2 收紧

- 可选沙箱：macOS sandbox / Linux bubblewrap 或 landlock。子进程只能写销毁即弃的临时目录，看不到用户主目录
- 出口代理：只允许 `allowedHosts`，并处理重定向
- 审计按天归档
- 自托管 SQLite 用同一套 API 跑起来，作为发行选项而不是另一套产品

### Phase 4 — 以后再考虑

- 团队保险库和多个主人同时编辑
- 文件、SSH 密钥、OTP
- Windows
- `ref` 重命名
- 浏览器扩展

## 14. 开放问题

下面每一项都给了推荐，方便直接开工。推翻推荐会改变 Phase 1 的范围。

1. **无人值守的默认值。** 推荐：新的 `api_key` 是 `standard`，靠 `deny-shells` 约束；人可以改成 `approval`。另一端是全部默认 `approval`，更安全，agent 在人离开后就不能跑。你更想要哪一个？
2. **沙箱要不要进 MVP。** 推荐：不进。Phase 1 用集成要求（工具面只有 keyref）加上拒绝 shell。若你的 agent 必须同时拥有通用 shell，沙箱就应该提前，否则「看不见明文」只对 keyref 自己的输出成立。
3. **账号。** 推荐：没有邮箱，恢复密钥就是恢复手段。若你希望换手机时用 Apple 登录而不是抄写恢复密钥，需要单独立项，而且仍然不能让 Apple 或服务器解开 VMK。
4. **团队共享。** 推荐：MVP 只有一个 owner 保险库。若一年内要给同事授权某几条密钥，grant 模型可以延伸，但目录签名和「谁有权轮换」要重新设计。
5. **操作系统。** 推荐：CLI 先做 macOS 和 Linux。Windows 的 pty、密钥环和 `/dev/fd` 都不同，放在 Phase 4。
6. **MCP。** 推荐：Phase 2 提供 `keyref mcp`。如果你的第一个使用者只能通过 MCP 接工具，就放进 Phase 1，协议与 `exec` 相同。
7. **自托管是不是硬需求。** 推荐：API 保持可移植，但 MVP 部署在 Cloudflare。若数据不能离开内网，就改为先做 SQLite 服务器，Cloudflare 降为以后的托管发行版。schema 不用改。
8. **Apple Developer 年费和 APNs。** 审批推送需要它。推荐：Phase 1 用前台轮询，把付费账号推迟到 Phase 2。
9. **秘密类型。** 推荐：MVP 只有字符串。SSH 私钥、文件和 OTP 会带来新的注入和脱敏问题。
10. **掩码的末四位。** 推荐：iOS 把 `sk-****abcd` 这种掩码放进 meta，`list` 不解密 secret，因此 `approval` 条目也能显示末四位。view 授权的 agent 会看见 API key 的末四位。若你不接受，就把 `masked` 一律设为 `***`。
11. **审计保留。** 推荐：D1 保留 30 天。更长的保留会先成为 10,000 日活时的存储费用。
12. **产品名和域名。** 仓库和命令用 `keyref`。对外名称、同步服务域名、二维码里的 scheme 是否就用这个词，需要你确认。scheme 一旦随着 CLI 发出去，就不好改。

## 15. 实现时保持不变的约束

这些句子是给以后写代码的人的，避免实现阶段把威胁模型做丢：

- Worker、日志、错误响应和分析里不出现解开的秘密，也不出现用户的名称和 `ref`。`ref` 出现在已解锁客户端的 `list` 输出里，这是 agent 能引用条目的前提；它不出现在服务器能读的列里。
- `list` 和 `get` 不解密 secret。掩码用 meta 里已经算好的 `masked`。
- 不增加 `keyref get --reveal`、环境变量开关或调试 flag 来打印明文。需要明文的是子进程，不是父进程的 stdout。
- 不用 `system()` 或 `sh -c` 执行 agent 的命令。
- 不把 VMK 放进任何 `kind = cli` 的包裹。
- 不把 `approval` 条目的 item key 写进 CLI 的密钥环或 sqlite。
- 配对完成时授予集合为空，直到人勾选。
- 撤销一台可能已经泄密的 CLI 时，轮换它能用的 item key。
