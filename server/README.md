# server

Versioned self-hosted images are published to
`ghcr.io/lidessen/keyref-server:vX.Y.Z` when a release tag passes CI. Use a
specific version when deploying or rolling back. See the
[release workflow](../.github/workflows/release.yml).

The ciphertext sync service and optional GitHub account vault. For paired sync, the server neither holds the VMK nor can decrypt item plaintext. The account vault has a separate server-managed key model. The hosted service and the self-hosted deployment are the same program.

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

## Deploy on Vercel with Turso

The repository root contains a Vercel Container Runtime entry point,
`Dockerfile.vercel`. Use the repository root as the Vercel project root
so the build can read both Go modules. Vercel terminates TLS and routes
HTTP traffic to port 80 by default. Set the project's `PORT` only if a
different port is needed.

1. Connect a dedicated **Turso Cloud** database through the Vercel
   Marketplace. Place the database in the same region as the function
   where possible. Use separate databases for production and previews.
2. Check that the integration sets `TURSO_DATABASE_URL` (a
   `libsql://` endpoint) and `TURSO_AUTH_TOKEN` (a read/write token)
   in the target environment. Keep the token in Vercel project
   environment variables. TLS is managed by Vercel, so leave
   `KEYREF_DOMAIN` unset.
3. Deploy the root project with Vercel's Container preset. Then request
   `/v1/healthz` on its public HTTPS origin and check for
   `"status":"ok"` and `"db_writable":true`.

The first successful startup initializes an empty Turso database.
Subsequent starts share its schema, ciphertext, device challenges and
rate limits. Use the provider's backups for this database. The existing
`keyref-server backup` command covers embedded SQLite deployments.

Vercel's Functions payload limits apply. In particular, keep vaults
small enough that a full `cursor=0` sync response fits within 4.5 MB.
The hosted free plan (`KEYREF_ENFORCE_QUOTAS=1`) limits vault storage
and requires proof of work at registration. The Vercel deployment
serves the existing paired sync API.

## Browser management

When the account vault is enabled, visit `/manage/` on the server's HTTPS
origin. Configure browser sign-in on the same GitHub OAuth App by setting its
authorization callback to `https://<host>/manage/api/login/github/callback`.
Set the server-only `KEYREF_GITHUB_CLIENT_SECRET` and set
`KEYREF_GITHUB_CALLBACK_URL` to that exact callback URL. The browser uses the
OAuth web flow with PKCE and the existing GitHub account allowlist. Keep
device authorization enabled on the app for CLI sign-in.
The page displays masked metadata and supports creating, editing, and deleting
credentials. A blank value while editing keeps the existing secret.

The container images build the bundled Meowland frontend with Bun. For local
development, run `bun install --frozen-lockfile` and `bun run build` in
`server/web` before building or running the server. The frontend bundle is
generated at `server/internal/accountvault/web/build/main.js`.

## GitHub account vault

The optional account vault exposes `/v1/remote/` alongside device sync.
Set these environment variables together to enable it:

| Variable | Value |
| --- | --- |
| `KEYREF_GITHUB_CLIENT_ID` | Client ID of a GitHub application with device authorization enabled |
| `KEYREF_REMOTE_GITHUB_IDS` | Comma-separated numeric GitHub user IDs allowed to sign in |
| `KEYREF_REMOTE_WRAP_KEY` | Stable 32-byte random wrapping key encoded as standard base64, stored as a sensitive runtime environment variable |

Use HTTPS for a remote host. A client on this service delegates key
custody to the operator. The server wraps each account's vault key
under the deployment wrapping key and returns that vault key on
successful GitHub authorization. The operator can decrypt the account
vault. Preserve the wrapping key in a separate secure backup. Losing
it makes the existing account vaults inaccessible. Use different
wrapping keys and databases for preview and production.

GitHub tokens remain transient on the server and are used only to
resolve the authenticated numeric user ID. Keyref stores a digest of
each 12-hour session token and revokes that session on logout. Removing
a user ID from the allowlist disables that user's existing sessions.
The CLI encrypts metadata and values separately before uploading them.
