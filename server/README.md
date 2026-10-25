# server

密文同步服务。已实现（Phase 1 + Phase 2 的审批端点）。服务器不持有、也不能解开 VMK 或条目明文。官方托管和自托管是同一份程序。

设计见 [docs/design.md](../docs/design.md) 的「存储、部署与费用」和「服务端 API」两节；线格式以 [docs/protocol.md](../docs/protocol.md) 为准。

- 一份 Go 二进制 `keyref-server`，内嵌 SQLite（纯 Go 驱动，`CGO_ENABLED=0`）。Docker 镜像里就是这个二进制。
- 端点：设计 §11 的全部 26 个——vault、配对三步、会话挑战、sync（`cursor=0` 现状引导、合成变更、revoked 可见性）、items/grants/directory、审批（CLI 签名验证、10 条待处理上限、2 秒轮询下限且不计配额）、恢复接管、审计、healthz、删除保险库。
- 只校验信封的形状、签名是否存在、设备是否有效、体积和配额是否超限。不要在服务器里实现解密。
- CLI 身份的设备不能写入或删除条目。
- 鉴权令牌只代表「这个设备可以来同步」，不是解密密钥。数据库里存令牌的哈希。
- 自托管默认不限额、不校验收据、不向官方服务器上报。官方托管（`KEYREF_ENFORCE_QUOTAS=1`）必须打开配额；超额返回错误，不按量加钱。

布局：

```
server/
├── go.mod
├── Dockerfile
├── cmd/keyref-server/     # 入口：serve / backup / version
└── internal/
    ├── api/               # 全部端点（httptest 流程测试覆盖）
    ├── store/             # §6.3 schema、迁移、查询
    ├── httpserver/        # plain HTTP / ACME（KEYREF_DOMAIN）
    ├── quotas/            # KEYREF_ENFORCE_QUOTAS=1 时的档位与全局预算
    └── pow/               # 托管注册的工作量证明
```

费用（2026-10-20 的公开价，计算过程在设计文档里）：官方托管的固定成本大约 $18/月，含一台小机器、域名和 Apple Developer 年费。诚实用户的边际成本按 $0.01/月规划。免费档有硬配额；Plus 的推荐标价是 $6/月或 $48/年。自托管免费。
