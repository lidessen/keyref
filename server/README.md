# server

密文同步服务。**尚未实现。** 服务器不持有、也不能解开 VMK 或条目明文。

设计见 [docs/design.md](../docs/design.md) 的「存储与同步」和「服务端 API」两节。

- 部署目标是 Cloudflare Workers + D1。数据模型用普通 SQL，方便以后原样搬到自托管的 SQLite。
- 运行时是 TypeScript。只校验信封的形状、签名是否存在、设备是否有效、体积是否超限。不要在 Worker 里实现解密。
- 不要用 Workers KV 当数据源（最终一致性，也不适合按 vault 做游标查询）。不要为了 MVP 引入 Durable Objects。
- CLI 身份的设备不能写入或删除条目。
- 鉴权令牌只代表「这个设备可以来同步」，不是解密密钥。数据库里存令牌的哈希。

建议的后续布局：

```
server/
├── package.json
├── wrangler.toml
└── src/
    └── index.ts
```

费用量级（2026-10-20 的公开价，细节在设计文档里）：个人开发和很小的内测可以落在免费额度里；当作正式服务跑，按 Workers Paid 的 **$5/月** 底价规划。
