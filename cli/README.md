# cli

The command line for AI agents. The binary is called `keyref`.

One command surface covers every credential source. A **source** is a backend the commands read from and write to: the standalone **local** vault (the default, offline, no pairing) or the **sync** vault (the paired iOS vault, read-only for the CLI). There is no `local` subcommand — `keyref set` on the default source *is* the local store.

On the paired vault the stdout never contains secret plaintext. A local source has one explicit exception: `keyref get --reveal`, which a person has to ask for by name.

See the "reference syntax", "exec" and "CLI" sections of [docs/design.md](../docs/design.md) for the design, and [docs/protocol.md](../docs/protocol.md) for the wire format.

Commands (design §12.2 and §17, implemented):

| Command | Purpose |
| --- | --- |
| `keyref init` | Create the local vault; the master key goes to the OS keyring |
| `keyref set <ref>` | Store a secret read from stdin (local sources) |
| `keyref get <ref>` | One entry: names, descriptions, `ref`, masks. `--reveal` prints the raw bytes (local sources only) |
| `keyref delete <ref>` | Delete an entry (local sources) |
| `keyref list` | Names, descriptions, `ref`, masks (paired vault) |
| `keyref exec -- ...` | Inject secrets into a child process, redact stdout/stderr; supports `--env`, `--stdin`, `--stdin-login`, `--fd`, `--pty`/`--reply` |
| `keyref source list\|default\|add\|remove` | Show or configure the sources |
| `keyref pair` | Generate a device key, show a QR code in the terminal, pair with the iOS vault |
| `keyref session` | Establish or renew a server session (challenge for a token, protocol §6.7) |
| `keyref status` | Pairing state, whether the session is unlocked, remaining grant lifetime |
| `keyref lock` / `keyref unlock` | Drop or restore the in-memory item keys |
| `keyref sync` | Pull the ciphertext within the granted scope |
| `keyref server` | View or set the sync server URL |
| `keyref mcp` | JSON-RPC 2.0 (MCP) over stdio: the tools are only `list` / `get` / `exec`, with the same semantics as the CLI (design §7.8). The server is a paired CLI device: all three tools speak the `sync` source |

On the paired vault there is no `reveal`, no `export` and no `--print`; the JSON of `get` has no `value` field.

### Sources

Every data command takes `--source NAME`. `KEYREF_SOURCE` does the same, and `keyref source default NAME` persists the choice. With none of them set, the source is `local` — or `sync`, if this data directory already held a paired vault before sources existed.

| Source | Kind | Notes |
| --- | --- | --- |
| `local` | local | The standalone offline vault at `<data dir>/local.db`. Read and write |
| `sync` | sync | The paired iOS vault. Read only: the CLI may never create, edit or delete an item (design §2.1) |

`keyref source add NAME --path /absolute/vault.db` registers another local vault; `keyref source remove NAME` drops it from the configuration and leaves its file alone. A local vault's directory must be private (mode 0700) — keyref refuses to create or open one otherwise.

`keyref pair` makes `sync` the default source, which is what the commands did before sources existed; `keyref source default local` switches back.

### Local sources

```sh
keyref init                                   # create the local vault
keyref set my-ref < /path/to/secret-input     # store a secret, read from stdin
keyref get my-ref                             # ref, source, mask, size
keyref get my-ref --reveal                    # the raw bytes, nothing else
keyref delete my-ref
keyref exec --env TOKEN=my-ref -- /absolute/path/to/consumer
```

The master key is 32 random bytes. `keyref init` generates one and stores it in the OS keyring (macOS Keychain, Linux Secret Service); `KEYREF_LOCAL_MASTER` overrides it for headless use, carrying the same key as the standard base64 encoding of 32 bytes. An environment-provided key is used as-is and never copied into the keyring. Losing the key means losing the vault — keyref cannot recover or regenerate it.

`set` reads 1 byte to 1 MiB from stdin and saves it byte for byte, including a trailing newline; the value never appears in the command arguments or in any output. `get` prints a mask computed from the value (the head and the last four characters, and nothing at all for short, binary or whitespace-containing values). `--reveal` is the one deliberate plaintext path: it writes the raw secret bytes to stdout and nothing else, it exists for local sources only, and the paired vault rejects it.

A local vault stores its refs one-way — the row id is an HMAC of the ref — so `keyref list` cannot enumerate them and a ref cannot be recovered from the file. You need the ref to get the entry.

`exec` on a local source is the same code path as on the paired one: the deny-shells policy, the injection shapes and the redactor are identical (design §7.3, §7.4). There is no grant, no approval round and no remote audit, and `list` is the paired vault's command only.

### Synced login items

```sh
keyref exec --stdin-login login-ref -- /absolute/path/to/consumer
```

The CLI must be paired and unlocked, the item must be injectable, and the item's explicit `allowCommands` policy must permit it. The caller supplies the absolute path of a trusted subcommand; Keyref's item policy checks the command name. Keyref runs one existing authorization flow for that item, including waiting for one owner decision when the item requires approval. After authorization, `username` and `value` are read from the same decryption and written to the child's anonymous stdin pipe as two separate lines, in that order, each line terminated by LF, after which the input is closed. Each field must be 1 to 1024 bytes of UTF-8 and must not contain CR, LF or NUL. If the item or a field is missing, unsupported or fails validation, the child is not started. Both fields join the byte-stream redaction of the child's output and are replaced with the marker `***`. The replacement acts on raw bytes and may therefore change machine-readable content such as JSON. This entry point is for CLI use only.

`--stdin-login` is mutually exclusive with `--stdin` and `--pty`. The same item cannot be used in another injection position at the same time. `--env` and the ordinary `--pass` of other items follow the original rules. Keyref validates the command policy; the consuming program validates where the secret actually ends up.

`--timeout` still bounds the approval wait, not the child's runtime. The child stays in the caller's process group, so the caller can cancel Keyref and the child together. Sending a standalone SIGINT or SIGTERM to the child after it started terminates that child. Operations already issued still have to be settled against the consuming program's receipt. Keyref does not automatically re-issue an approval or restart the child after a cancellation, a timeout or the child's exit.

### Go library: a registrable storage provider

`github.com/lidessen/keyref/cli/store` provides a unified `Store` interface (`Put`, `Use`, `Delete`, `Close`). `Use` provides the plaintext only inside the callback, and callers should avoid retaining or logging it; in-memory clearing is not isolation from a same-user process. Every `store.NewRegistry()` registers the standalone local store by default:

```go
registry := store.NewRegistry()
vault, err := registry.Open(store.Options{Config: store.LocalOptions{Path: path, Key: masterKey}})
// check err; call Close when done with the vault.
```

`Create` uses the same Options and creates according to the backend's semantics. An empty `Provider` selects `local`; an explicitly named unknown provider or a backend error returns the error directly — never a fallback. An application can register its own backend with `Registry.Register(name, factory)`; the factory receives that provider's configuration and a create/open flag, and is responsible for validating the configuration and implementing the storage semantics. Registration is per instance. The only backend Keyref ships with today is the local one; that does not mean the synced vault or a cloud service is available. The CLI's local source calls the same local backend through this entry point.


The default server is the official hosted service. `keyref server set https://keys.example.com` or the `KEYREF_SERVER` environment variable points the CLI at a self-hosted one. The pairing QR code carries that origin, and the phone asks for confirmation before you change the server. Encryption on both sides does not depend on who is running the server.

- The language is **Go** (since design v0.4, the same language as the server; the earlier "Rust + zeroize" decision was overturned and memory hygiene was downgraded to guarded allocation plus explicit zeroing — see design §12.2).
- Private keys go into the OS keyring (macOS Keychain, Linux Secret Service). Unwrapped item keys and secret plaintext live only in guarded memory (memguard: mlock, invisible to the GC, explicitly zeroed at `lock` and on exit).
- Never run user commands through a shell. `sh -c`, `echo`, `env` and the like are rejected by default.
- Machine-readable output uses English headers so agents can parse it.

Directory layout (actual tree, checked 2026-11-13; `cli/internal` has 20 packages):

```
cli/
├── cmd/keyref/          # command entry points (main.go + mcp.go: stdio JSON-RPC)
├── internal/approval/   # approval requests / polling / one-time unwrap for approval items (design §8.3)
├── internal/audit/      # boxing and upload of exec audit events
├── internal/client/     # a thin HTTP client for the sync API
├── internal/config/     # origin configuration (0700 directory)
├── internal/decider/    # the optional auto-approval delegate and its mandatory review gate (design v0.8 §14.8)
├── internal/device/     # device identity: X25519 HPKE key + signing key
├── internal/localvault/ # the local master key: OS keyring, KEYREF_LOCAL_MASTER override
├── internal/exec/       # policy (including shebang parsing), injection, redaction, pty/reply
├── internal/exitcode/   # the exit-code table of design §7.6
├── internal/itemcrypt/  # grant unwrap, meta/secret decryption
├── internal/keyring/    # the SecretStore interface; a go-keyring implementation; a directory implementation for tests
├── internal/meta/       # list/get: decrypts only the meta and prints masks
├── internal/pair/       # QR code generation, pair/register, pair/status polling
├── internal/qr/         # terminal QR rendering
├── internal/secret/     # memguard guarded buffers, secret JSON parsing without strings
├── internal/session/    # challenge → token, token reuse and renewal
├── internal/store/      # cache.sqlite (0600, ciphertext cache)
├── internal/source/     # the source registry: local (default) and sync
├── internal/syncing/    # applying server changes to the local cache
├── internal/testowner/  # a software P-256 owner for tests and e2e
└── e2e/                 # //go:build e2e end-to-end tests
```

Accept against fixed fixtures: the fixture plaintext must not appear in the stdout/stderr of `list`, `get` or `exec`, including base64, hex and URL encodings.
