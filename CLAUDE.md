# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What keyref is

keyref is a secret manager for humans plus a secret broker for AI agents. A human owns the vault on iOS; an agent uses the `keyref` CLI to *use* secrets. The agent writes a stable reference (`openai-prod`), never the secret. The CLI injects the real value into a child process and redacts it back out of stdout/stderr, so plaintext never reaches the model's context.

The trust boundary is the whole design: the server stores ciphertext only and cannot decrypt anything; the master key (VMK) lives in the iOS Secure Enclave; the CLI only ever holds per-item keys for items it was granted.

## Repository layout

| Path | Contents |
| --- | --- |
| `docs/design.md` | The full spec (Chinese) — threat model, architecture, crypto, exec semantics, roadmap |
| `docs/protocol.md` | The wire contract — endpoints, request/response shapes, exact transcript byte layouts |
| `docs/ios-ui.md` | iOS interaction spec — information architecture, per-screen states and final copy |
| `proto/` | Shared Go module: `crypto/` (HPKE, AEAD, HKDF, keys) and `wire/` (transcripts, entity ids, signatures) |
| `server/` | `keyref-server`: ciphertext sync API, Go + embedded SQLite |
| `cli/` | The `keyref` CLI (Go) — the agent-facing entry point |
| `ios/` | SwiftUI app: `Sources/KeyrefCore` (UI-free) + `Sources/KeyrefUI` (all views) |
| `tools/vectordump/` | Generates the cross-language golden vectors from Go (the reference implementation) |
| `android/` | Kotlin SMS-collector device (`kind = source`) |
| `scripts/` | Local dev scripts (server, CLI install, docker, iOS build/test) |

`go.work` joins four modules — `cli`, `server`, `proto`, `tools/vectordump`. There is no vendoring and no root Go module, so `go build ./...` at the repo root fails; always target a module (`go build -C cli ./...`).

## Build, test, run

**Go** (CI runs exactly this; see `.github/workflows/ci.yml`):

```sh
go vet  -C server ./... && go vet  -C cli ./... && go vet  -C proto ./... && go vet  -C tools/vectordump ./...
go test -C server ./... && go test -C cli ./... && go test -C proto ./... && go test -C tools/vectordump ./...
```

Single test / package:

```sh
go test -C cli ./internal/exec -run TestRunEnvInjectionIsRedacted -v
go test -C server ./internal/api -run TestFullFlowSelfHosted -v
```

**End-to-end** (builds the real CLI and server binaries and drives them against each other; every file carries the `e2e` build tag):

```sh
go test -C cli -tags=e2e ./e2e
go test -C cli -tags=e2e ./e2e -run TestStdinLoginApprovalFlow -v
```

**Cross-language vectors** — Go is the reference for every byte-level format. After changing anything in `proto/` or the protocol, regenerate the fixture the iOS suite asserts against:

```sh
go run ./tools/vectordump -out ios/Tests/KeyrefCoreTests/Fixtures/vectors.json
```

The Android `crypto/Envelope.kt` (BouncyCastle HPKE) must match Go's circl and CryptoKit byte-for-byte; the vectors are the admission gate for that.

ECDSA signatures are randomized, so a regenerated fixture never diffs clean — only the `signature_hex` / `owner_signature_hex` lines change. Every other byte (public keys, transcripts, AEAD blobs, HPKE envelopes, info/AAD strings) must be identical to the committed file. If anything else moves, the protocol drifted.

**iOS** (macOS only):

```sh
scripts/dev/xcodebuild.sh -project ios/Keyref.xcodeproj -scheme Keyref \
  -destination 'platform=iOS Simulator,name=iPhone 17' build
scripts/dev/xcodebuild.sh -project ios/Keyref.xcodeproj -scheme Keyref \
  -destination 'platform=iOS Simulator,name=iPhone 17' test
scripts/dev/xcodebuild.sh -project ios/Keyref.xcodeproj -scheme Keyref \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -only-testing:KeyrefCoreTests/CryptoTests test      # single test target/class
```

`scripts/dev/xcodebuild.sh` only sets `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` and execs `xcodebuild`. It is mandatory on this machine: `xcode-select` points at CommandLineTools, which has no `xcodebuild` and no iOS SDK. Package-only work (KeyrefCore/KeyrefUI, no app shell) also builds and tests on macOS:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift build --package-path ios
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test  --package-path ios
```

**Simulator UI end-to-end** — starts a real quota-enforcing `keyref-server` on `127.0.0.1:18080` and drives the actual app UI through it:

```sh
scripts/dev/ui-test.sh                          # whole flow
scripts/dev/ui-test.sh KeyrefUIAutomationTests/KeyrefFlowUITests/SomeTest
```

Port 18080 must be free; it lives in a separate `KeyrefUIAutomation` scheme so it does not slow the default gate.

**Local development:**

```sh
scripts/run-server.sh              # dev server on 127.0.0.1:8080, plain HTTP, no quotas
scripts/install-cli.sh             # install `keyref` to /usr/local/bin (KEYREF_BIN_DIR to override)
scripts/docker-up.sh / scripts/docker-down.sh
KEYREF_SERVER=http://127.0.0.1:8080 keyref pair
```

Server environment: `KEYREF_DATA`, `KEYREF_LISTEN`, `KEYREF_ENFORCE_QUOTAS=1` (hosted behaviour: quotas on, PoW required), `KEYREF_DOMAIN` (ACME/HTTPS), `KEYREF_ACME_EMAIL`. CLI: `KEYREF_SERVER` (origin override), `KEYREF_KEYRING_DIR`.

**Android** has no build environment on this machine — the Kotlin source has never been compiled here. Expect to hand the maintainer compile errors rather than to fix them locally.

## Architecture

### The three roles

- **iOS app (owner)** — holds the VMK in a Secure Enclave P-256 key, encrypts item metadata and secrets, signs ciphertext and pairing records, and approves sensitive `exec` requests behind Face ID. The CLI can never write to the vault.
- **CLI (agent side)** — pairs via QR, syncs only what it was granted, unwraps item keys locally, spawns children directly (never through a shell), injects secrets via env / stdin / extra fd / pty, and redacts every byte stream it captures.
- **Server** — stores ciphertext, grants and audit envelopes. It validates envelope *shape*, signature presence, device validity, size and quota. It never decrypts, and it never sees names or `ref` values.

### Sources

The CLI has one command surface over two backends, called **sources** (`cli/internal/source`): `local`, an offline SQLite vault that is the default, and `sync`, the paired iOS vault, which the CLI may read but never write. Selection is `--source` → `KEYREF_SOURCE` → the configured default in `<data dir>/sources.json` → `local`. A data directory that already held a paired vault before sources existed migrates to `sync`, so upgrading does not move existing commands onto an empty vault; `keyref pair` also sets `sync` as the default.

A local source's master key lives in the OS keyring (`cli/internal/localvault`), with `KEYREF_LOCAL_MASTER` (32 random bytes, standard base64) overriding it for headless use — an environment-provided key is never copied into the keyring. Local refs are stored one-way (the row id is an HMAC of the ref), so `list` is the paired vault's command only. `keyref exec` on a local source reuses `exec.Run` unchanged: same deny-shells policy, same injection shapes, same redactor, with synthetic per-item metas and no grants, approvals or audit.

### Shared protocol module

`proto/wire` is the single source of truth for byte formats used by both the server and the CLI, so transcripts cannot drift between the two sides. Transcripts are **write-only byte strings**: a signer assembles them in the fixed field order, and a verifier *rebuilds* the same bytes and checks the signature over them. Never parse a transcript by splitting on NUL — ciphertexts and public keys contain `0x00`.

### Crypto layering

VMK (Secure Enclave) wraps item keys → item keys encrypt metadata and secret separately → the secret blob is encrypted separately from the meta blob, so `list`/`get` can show masked values without touching the secret. Approval-sensitive items (`sensitivity = approval`) never give the CLI a long-lived item key: each `exec` gets a one-time HPKE wrap, delivered after the owner approves, bound to `approval_id` + `item_id` + a digest of the request transcript.

### SMS collection (design v0.8)

Android `kind = source` devices read the phone's SMS, encrypt each captured code at receipt time (envelope addressed to the active owner plus any delegated decider) and upload via a WorkManager queue. Only `source` can write messages; only the owner and an explicitly delegated decider can read them; messages expire after 24 h; agents consume them as `sms:<message_id>` only through an approval-gated `exec`. A decider's delegation can only *narrow* the owner's scope, never widen it, and its decision API re-check is mandatory.

### Execution path

`keyref exec` resolves argv0 through PATH, symlinks and shebang interpreters (bounded hops), rejects the deny-shell list (`sh`, `env`, `echo`, `cat`, `base64`, `python`, …), checks the item's own `allowCommands`/`allowedHosts`/`allowArgv` policy, and only then spawns. All validation happens *before* the spawn — a rejected command never starts a child. Output is redacted in multiple encodings; the exit-code table is pinned in `cli/internal/exitcode` (10 policy, 11 unknown ref, 12 locked, 13 approval denied, 14 redaction failed, 15 injection invalid, 16 unwrap failed, 17 revoked, 18 cannot start).

### iOS app structure

`KeyrefCore` is deliberately UI-free (crypto, API client, sync engine, vault/approval flows, second-device pairing) so it can be unit-tested on macOS. `KeyrefUI` holds every view plus a `Backend/` protocol with a `LiveBackend` and a `MemoryBackend`, which is how the UI tests run without a network or Keychain.

## Invariants that must not regress

These come from `docs/design.md` §16 — read that section before changing security-sensitive code. The load-bearing ones:

- The server, its logs, its error responses and its analytics never contain decrypted secrets, item names or `ref` values.
- `list` and `get` never decrypt the secret; they show the `masked` value computed at write time.
- On the paired vault there is no reveal path: no `--reveal`, no env var, no debug flag that prints plaintext. The child process gets the plaintext, the parent stdout never does. A **local** source is the one deliberate exception: `keyref get <ref> --reveal` writes the raw bytes to stdout, and only a local source accepts it.
- Item keys for `approval` items never enter the CLI keyring or `cache.sqlite`. VMK never enters any `kind = cli` envelope.
- Grants are empty at pairing completion until a human selects items.
- Revoking a possibly-leaked CLI rotates the item keys it could reach.
- Approval requests carry the CLI's device signature; the one-time wrap binds `approval_id`, `item_id` and the request transcript digest.
- No `system()` / `sh -c`; the child is spawned directly.
- Local-only items (storage class from design v0.7) never upload their secret ciphertext.
- `sms:<message_id>` is not resolvable by `list`/`get` — it appears only in an approval-gated `exec`.

## Language and output conventions

- The READMEs are **English**; the specs in `docs/` (design.md, protocol.md, ios-ui.md) and the iOS UI copy are **Simplified Chinese**. The copy quoted in `docs/ios-ui.md` is final and must not be reworded as a side effect of a change.
- The CLI's machine-readable output is **English** (agent-facing).
- Identifiers, `ref` values, algorithm names, API paths and field names stay English in every language.

## iOS visual direction

The UI follows the "cool editorial" direction settled on 2026-11-01 and specified in `docs/ios-ui.md` §3.8 plus `ios/README.md`: flat near-white (light) / near-black (dark) pages, hairline rules as the only separator, **no cards, no gradients, no shadows, no icon tiles**, monospace for all metadata, amber used only as a tiny signal mark, and the plaintext/recovery-code slab as the single opposite-colour block. Draw flat; use `glassEffect` for genuinely floating custom controls rather than hand-drawn translucency.

## Gotchas

- SourceKit/LSP diagnostics in this workspace are **noise** — the editor's LSP runs against the CommandLineTools toolchain and cannot resolve the module graph ("Cannot find 'X' in scope", "SwiftUIMacros not found"). `swift build --package-path ios` and `scripts/dev/xcodebuild.sh` are the authoritative checks. Plain `xcrun --sdk iphonesimulator` fails the same way.
- The iOS simulator shares the host network namespace, so the UI test hardcodes `http://127.0.0.1:18080`.
- Approval polling has a hard 2-second server-side floor and does **not** count against the daily request quota.
- `keyref exec --stdin-login` is mutually exclusive with `--stdin`/`--pty`, and the same item cannot be used in two injection positions at once.
- The CLI zeroes guarded buffers on every exit path via `secret.Purge()`; that is why fatal errors unwind through a panic instead of calling `os.Exit` directly.
- `out/` and `.build/` are local scratch output and are gitignored — don't commit them.
- After editing `ios/Sources/KeyrefCore`, `xcodebuild` may compile `KeyrefUI` against a **stale KeyrefCore package product** and report signature errors in the *caller* ("Extra argument 'vaultID' in call", "type 'X' has no member 'y'"). Sometimes the next build picks up the new package product; when a re-run fails the same way, run `xcodebuild … clean` for the scheme (or delete the project's DerivedData directory) and build again. `swift build --package-path ios` always reads the sources directly, so use it to tell a real compile error from staleness.
