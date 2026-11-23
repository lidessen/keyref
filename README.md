# keyref

<img src="server/internal/accountvault/web/logo.png" alt="" width="72" height="72">

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

On macOS or Linux (amd64 or arm64), install the latest stable binary:

```bash
curl -fsSL https://raw.githubusercontent.com/lidessen/keyref/main/scripts/install.sh | bash
keyref --version
```

The installer checks the release's SHA-256 manifest and installs to
`~/.local/bin`. Add that directory to `PATH` if needed. Go is required
only for source builds. Set `KEYREF_BIN_DIR` on the `bash` invocation
for a custom install directory, `KEYREF_VERSION=vX.Y.Z` for a specific
release, or `KEYREF_REF` for a source build from a branch, tag, or commit.

```bash
keyref update --check  # report whether a newer stable release is available
keyref update          # verify and replace the running CLI executable
```

These commands use [GitHub Releases](https://github.com/lidessen/keyref/releases)
and require a published stable release. An update needs write access to the
executable's directory. For a package-managed installation, use its package
manager to upgrade.

## CI and releases

Pull requests and pushes to `main` run the five Go modules' vet, unit tests
and standalone builds, the CLI/server end-to-end suite, installer smoke tests
on Linux and macOS, and both server container builds.

To release, tag a commit on `main` with a new stable version and push that
tag. For example, with `HEAD` already on the remote `main`:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin refs/tags/v0.1.0
```

[The release workflow](.github/workflows/release.yml) reruns CI for the
tagged commit. It builds four CLI binaries with a shared `SHA256SUMS` file,
pushes the tagged Linux amd64/arm64 server image to
`ghcr.io/lidessen/keyref-server`, and publishes the CLI binaries on GitHub
Releases. Set the GHCR package visibility to public if anonymous pulls are
needed. Use the exact image tag or digest for self-hosting. Vercel deployment
uses the separate server setup in the [deployment guide](server/README.md#deploy-on-vercel-with-turso).

To rehearse packaging locally with the current checkout:

```bash
scripts/build-release.sh v0.1.0 out/release
scripts/test-install.sh out/release v0.1.0
```

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
