# keyref

keyref is a secret manager for humans and a secret broker for AI agents. A human keeps API keys, tokens, passwords and notes on iOS. An agent **uses** those secrets through the CLI, and the content the tools hand back to the model contains **no plaintext**.

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
| [server/](server/) | Ciphertext sync service, Go + SQLite; the hosted and self-hosted deployments are the same binary |
| [cli/](cli/) | The `keyref` CLI for agents, Go (same language as the server since v0.4). One command surface over both credential sources |
| [ios/](ios/) | The iOS owner app, Swift / SwiftUI, implemented |
| [android/](android/) | SMS code collector (`kind = source` device in design v0.8 §14), Kotlin, not compiled or verified yet |
| [scripts/](scripts/) | Local development scripts: install the CLI, run a dev server, docker compose |

All three sides are implemented. `go vet` + `go test` for server / cli / proto / tools, plus the CLI end-to-end tests (create vault, pair, sync and exec against a real running server) are the CI gate ([.github/workflows/ci.yml](.github/workflows/ci.yml)). The iOS KeyrefCore / KeyrefUI tests run locally on the simulator and on macOS (see [ios/README.md](ios/README.md)); CI has no iOS job yet.

## Local development

```bash
# 1. Start the server (development mode: plain HTTP, no quotas), default 127.0.0.1:8080
scripts/run-server.sh

# 2. Install the CLI onto your PATH (default /usr/local/bin, override with KEYREF_BIN_DIR)
scripts/install-cli.sh

# 3. Or run the same server image with docker compose
scripts/docker-up.sh      # builds the image and starts it; scripts/docker-down.sh stops it
```

Point the CLI at the local server: `KEYREF_SERVER=http://127.0.0.1:8080 keyref pair`.

## Two sources, one command surface

`keyref` reads and writes **sources**. `local` is a standalone offline vault on this machine and is the default; `sync` is the paired iOS vault, which the CLI may read but never write. Every data command takes `--source NAME`, `KEYREF_SOURCE` does the same, and `keyref source default NAME` persists the choice.

```sh
keyref init                              # create the local vault (key → OS keyring)
keyref set my-ref < /path/to/secret      # store a secret, read from stdin
keyref get my-ref                        # ref, mask, size — never the value
keyref exec --env TOKEN=my-ref -- curl https://api.example.com
```

The paired vault is what the rest of this README is about; the local source is the same commands with no phone, no server and no approvals. See [cli/README.md](cli/README.md).

## Decisions already made

- The server stores ciphertext only. Names, descriptions, `ref` and secret values all live inside the ciphertext.
- The master key stays under the iOS Secure Enclave. The CLI only ever receives the item keys of the items it was granted; it never gets the master key.
- Placeholders are written as `{{keyref:openai-prod}}`. The safer injection shapes are `--env`, stdin or an extra file descriptor, rather than putting a secret in process arguments.
- The sync layer is one Go server with embedded SQLite. With nothing configured, iOS and the CLI talk to the official hosted service; change the server URL to your own address and you are self-hosting. The hosted service is priced as a fixed monthly fee plus hard quotas, so free usage cannot blow the bill up. Self-hosting is free.

The trade-offs, the threat model and the questions that are still open are written up in [docs/design.md](docs/design.md).
