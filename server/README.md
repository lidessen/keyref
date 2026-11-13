# server

The ciphertext sync service. Implemented (Phase 1 plus the Phase 2 approval endpoints). The server neither holds nor can decrypt the VMK or any item plaintext. The hosted service and the self-hosted deployment are the same program.

See the "storage, deployment and cost" and "server API" sections of [docs/design.md](../docs/design.md) for the design; [docs/protocol.md](../docs/protocol.md) is the authority on the wire format.

- One Go binary, `keyref-server`, with embedded SQLite (a pure Go driver, `CGO_ENABLED=0`). The Docker image contains exactly this binary.
- Endpoints: all 32 of protocol §5 — vault, the three pairing steps, session challenge, sync (`cursor=0` for the current-state bootstrap, synthetic changes, revoked visibility), items/grants/directory, approvals (CLI signature verification, a ceiling of 10 pending requests, a 2-second polling floor that does not count against quotas), recovery takeover, audit, healthz, vault deletion, APNs token registration (a best-effort fan-out once an approval is stored; pushes are skipped when no credentials are configured), messages and delegation.
- It only validates the shape of an envelope, whether a signature is present, whether the device is valid, and whether size and quota limits are exceeded. Never implement decryption in the server.
- A device with the CLI role cannot write or delete items.
- An auth token only means "this device may come and sync". It is not a decryption key. The database stores the hash of the token.
- Self-hosted defaults to no quotas, no licence check and no reporting to the official server. The hosted deployment (`KEYREF_ENFORCE_QUOTAS=1`) must have quotas enabled; exceeding them is an error, never metered billing.

Layout:

```
server/
├── go.mod
├── Dockerfile
├── cmd/keyref-server/     # entry points: serve / backup / version
└── internal/
    ├── api/               # all endpoints (covered by httptest flow tests)
    ├── store/             # the §6.3 schema, migrations, queries
    ├── httpserver/        # plain HTTP / ACME (KEYREF_DOMAIN)
    ├── quotas/            # the tiers and the global budget when KEYREF_ENFORCE_QUOTAS=1
    └── pow/               # the proof of work for hosted registration
```

Cost (public prices as of 2026-10-20, with the calculation in the design document): the fixed cost of the hosted service is about $18/month, covering a small machine, the domain and the Apple Developer annual fee. The marginal cost of an honest user is budgeted at $0.01/month. The free tier has hard quotas; Plus is recommended at a list price of $6/month or $48/year. Self-hosting is free.
