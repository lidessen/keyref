# Keyref

<img src="server/internal/website/logo.png" alt="" width="72" height="72">

Keyref is a credential vault and CLI for developers and AI agents. Save an API
key, token, or password under a reference such as `github-token`. Give that
reference to an agent or script. Keyref injects the stored value into the child
process and redacts matching values in captured stdout and stderr.

[Project website](https://keyref.sh/) · [Downloads](https://github.com/lidessen/keyref/releases/latest) · [CLI guide](cli/README.md) · [Self-hosting](server/README.md)

## Install

Install the latest stable CLI on macOS or Linux (arm64 and x86-64).

```sh
curl -fsSL https://keyref.sh/install.sh | bash
keyref --version
```

The installer verifies the release checksum and writes to `~/.local/bin`. Add
that directory to `PATH` if needed. Use `KEYREF_BIN_DIR` on the `bash`
invocation to change it, `KEYREF_VERSION=vX.Y.Z` to pin a release, or
`KEYREF_REF` for a source build with Go. You can also download a binary and its
checksum directly from [GitHub Releases](https://github.com/lidessen/keyref/releases/latest)
or get the [installer source](https://github.com/lidessen/keyref/blob/main/scripts/install.sh).

```sh
keyref update --check
keyref update
```

When upgrading from v0.1.0, switch vault selection in your scripts to
`--vault NAME`. Remote CLI injection now asks for terminal confirmation.

## Quickstart

This example uses a GitHub token and the `gh` CLI. Run `keyref set` in a
terminal, paste the token, then press Enter. The input is hidden.

```sh
keyref init
keyref set github-token --vault local
keyref list
keyref exec --vault local --env GH_TOKEN=github-token -- \
  gh api user --jq .login
```

`keyref list` displays references, masks, and source names. To import selected
variables from a file, use [`keyref import-env`](cli/README.md#importing-selected-environment-variables).
Use trusted child programs. Keyref redacts captured terminal output. A child
can still send or write the credentials it receives.

## Choose a vault

| Vault | How it works |
| --- | --- |
| Local | Encrypted offline storage on your machine. The CLI uses your OS keyring to store the master key. |
| GitHub account | Shared across your devices after sign-in to a configured server. The server operator manages the encryption keys, and sign-in is restricted to approved accounts. |

Open the [hosted account vault](https://keyref.sh/vault/) in a browser, or
follow the [CLI sign-in guide](cli/README.md#github-account-vault). When several
writable vaults are configured, pick one with `keyref set REF --vault NAME`.

## Development

- [CLI](cli/README.md) and [Go library](lib/local/README.md)
- [Server deployment](server/README.md) and [local development scripts](scripts/)
- [Design](docs/design.md), [wire protocol](docs/protocol.md), and [project map](PROJECT-MAP.md)

`scripts/run-server.sh` starts a development server at
`http://127.0.0.1:8080`. The public homepage is embedded in the Go binary.
Build the account vault frontend in `server/web` with `bun install --frozen-lockfile`
and `bun run build` to preview browser management.

The [CI workflow](.github/workflows/ci.yml) covers Go vet and tests, standalone
module builds, CLI/server end-to-end tests, installer checks, and server
container builds. To rehearse a release with a test version:

```sh
scripts/build-release.sh v0.0.0 out/release
scripts/test-install.sh out/release v0.0.0
```

The [release workflow](.github/workflows/release.yml) publishes the tested CLI
binaries and checksums to GitHub Releases and a versioned server image to
`ghcr.io/lidessen/keyref-server` for a stable `vX.Y.Z` tag on `main`.
