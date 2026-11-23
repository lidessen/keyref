# keyref

keyref is a secret manager for humans and a secret broker for AI agents. A human keeps API keys, tokens, passwords and notes in a vault; an agent **uses** those secrets through the CLI, and the content the tools hand back to the model contains **no plaintext**.

Keyref supports an offline vault on the same machine as the CLI and a GitHub account vault on a server. The human-facing app is deferred, and the paired/sync path is frozen until a replacement owner client exists. An optional self-hosted account vault supports GitHub login and direct CLI read/write with server-managed keys. See the [account vault setup](server/README.md#github-account-vault).

Typical use:

```bash
keyref exec --env OPENAI_API_KEY=openai-prod -- \
  curl https://api.openai.com/v1/models
```

The agent writes the stable reference `openai-prod`, not the secret itself. `keyref` injects the real value into the child process and redacts any secret that shows up again in stdout / stderr.

## What is in this repository

| Path | Contents |
| --- | --- |
| [docs/design.md](docs/design.md) | The full design (Chinese) |
| [docs/protocol.md](docs/protocol.md) | The wire contract: endpoints, request/response examples, exact transcript byte layout |
| [PROJECT-MAP.md](PROJECT-MAP.md) | Project map (Chinese): goals, boundaries, mechanisms, risks and health |
| [lib/](lib/) | Standalone Go module for embedding: the offline encrypted store and the exec engine (policy, injection, redaction) |
| [server/](server/) | Ciphertext sync service, Go + SQLite; self-hostable. Frozen: no new sync-protocol features |
| [cli/](cli/) | The `keyref` CLI for agents, Go (same language as the server since v0.4). One command surface over both credential sources |
| [scripts/](scripts/) | Local development scripts: install the CLI, run a dev server, docker compose |

`go vet` + `go test` for server / cli / lib / proto / tools, plus the CLI end-to-end tests (a software owner drives create vault, pair, sync and exec against a real running server) are the CI gate ([.github/workflows/ci.yml](.github/workflows/ci.yml)). The native iOS app and the Android SMS collector were removed on 2026-11-19; the app is planned as a WebView shell over a web UI.

## Install the CLI

On macOS or Linux with Bash and Go 1.26 or newer installed:

```bash
curl -fsSL https://raw.githubusercontent.com/lidessen/keyref/main/scripts/install.sh | bash
keyref --version
```

The installer builds from GitHub source and installs into `~/.local/bin`.
Add that directory to `PATH` if needed. Pass `KEYREF_BIN_DIR=/path/to/bin`
or `KEYREF_REF=<tag-or-commit>` to the `bash` command to override the defaults.

## Local development

```bash
# 1. Start the server (development mode: plain HTTP, no quotas), default 127.0.0.1:8080
scripts/run-server.sh

# 2. Install the CLI onto your PATH (default /usr/local/bin, override with KEYREF_BIN_DIR)
scripts/install-cli.sh

# 3. Or run the same server image with docker compose
scripts/docker-up.sh      # builds the image and starts it; scripts/docker-down.sh stops it
```

The dev server is for development and for the remote read/write work in progress. The CLI's local source needs no server at all.

The same sync API can run on Vercel Container Runtime with a dedicated
Turso Cloud database from the Vercel Marketplace. See the
[server deployment guide](server/README.md#deploy-on-vercel-with-turso).

## Two sources, one command surface

Keyref stores credentials in local vaults and a GitHub account vault. Run `keyref list` to see entries across configured vaults with their source names. `keyref set REF` uses the only writable vault, and requires `--source NAME` when several are configured. The frozen paired `sync` vault remains read-only for the CLI.

```sh
keyref init                              # create the local vault (key → OS keyring)
keyref set my-ref < /path/to/secret      # store a secret, read from stdin
keyref import-env --file /path/to/input.env --map OTHER_TOKEN=other-ref
keyref get my-ref                        # ref, mask, size — never the value
keyref exec --env TOKEN=my-ref -- curl https://api.example.com
```

This example assumes the local vault is the only writable source. See the [CLI guide](cli/README.md) for account login and source selection.

## Decisions already made

- The paired-sync server stores ciphertext only. Names, descriptions, `ref` and secret values all live inside the ciphertext.
- The intended owner model keeps the root key on a human-controlled device, never on the server and never in the CLI. The native app that implemented this was removed; the replacement owner client is deferred, so the paired path is frozen.
- Placeholders are written as `{{keyref:openai-prod}}`. The safer injection shapes are `--env`, stdin or an extra file descriptor, rather than putting a secret in process arguments.
- The sync layer is one Go server with embedded SQLite. Self-hosting is free: deploy it yourself and point the CLI at that address.

The trade-offs, the threat model and the questions that are still open are written up in [docs/design.md](docs/design.md).
