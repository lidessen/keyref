# cli

The command line for AI agents. The binary is called `keyref`.

One command surface covers every credential source. A **source** is a backend the commands read from and write to: the standalone **local** vault (the default, offline, no pairing) or the **sync** vault (the paired owner vault, read-only for the CLI; frozen while the owner app is deferred). There is no `local` subcommand — `keyref set` on the default source *is* the local store.

On the paired vault the stdout never contains secret plaintext. A local source has one explicit exception: `keyref get --reveal`, which a person has to ask for by name and confirm on the controlling terminal.

See the "reference syntax", "exec" and "CLI" sections of [docs/design.md](../docs/design.md) for the design, and [docs/protocol.md](../docs/protocol.md) for the wire format.

Commands (design §12.2 and §17, implemented):

| Command | Purpose |
| --- | --- |
| `keyref init` | Create the local vault; the master key goes to the OS keyring |
| `keyref set <ref>` | Store a secret read from stdin (`--raw` keeps every byte); local sources |
| `keyref import-env --file PATH --map NAME=REF` | Import explicitly selected assignments into a local vault |
| `keyref get <ref>` | One entry from encrypted meta: names, descriptions, `ref`, masks. `--reveal` prints the raw bytes (local sources only) |
| `keyref delete <ref>` | Delete an entry (local sources) |
| `keyref list` | Names, descriptions, `ref`, masks from encrypted meta (local and paired vaults) |
| `keyref exec -- ...` | Inject secrets into a child process, redact stdout/stderr; supports `--env`, `--stdin`, `--stdin-login`, `--fd`, `--pty`/`--reply` |
| `keyref source list\|default\|add\|remove` | Show or configure the sources |
| `keyref pair` | Generate a device key, show a QR code in the terminal, pair with the owner vault (owner app deferred; path frozen) |
| `keyref session` | Establish or renew a server session (challenge for a token, protocol §6.7) |
| `keyref status` | Report the selected source (`--all` for every configured one): for `local`, whether the vault file exists, where the master key comes from (OS keyring or `KEYREF_LOCAL_MASTER`) and the lock flag; for `sync`, the server, pairing, session and remaining grant lifetime |
| `keyref lock` / `keyref unlock` | Set or clear the lock flag (`<data dir>/locked`); while set, no unwrap path runs |
| `keyref --version` | Print the CLI version; the MCP `serverInfo.version` is the same value |
| `keyref sync` | Pull the ciphertext within the granted scope |
| `keyref server` | View or set the sync server URL |
| `keyref mcp [--source NAME]` | JSON-RPC 2.0 (MCP) over stdio: the tools are only `list` / `get` / `exec`, with the same semantics as the CLI (design §7.8). The source is selected once at startup by the usual order (`--source`, `KEYREF_SOURCE`, the configured default, `local`) and stays fixed for the whole session, so one server serves either source with the same three tools (design §17.5) |

On the paired vault there is no `reveal`, no `export` and no `--print`; the JSON of `get` has no `value` field.

### Sources

Every data command takes `--source NAME`. `KEYREF_SOURCE` does the same, and `keyref source default NAME` persists the choice. With none of them set, the source is `local` — or `sync`, if this data directory already held a paired vault before sources existed.

| Source | Kind | Notes |
| --- | --- | --- |
| `local` | local | The standalone offline vault at `<data dir>/local.db`. Read and write |
| `sync` | sync | The paired owner vault. Read only: the CLI may never create, edit or delete an item (design §2.1); frozen while the owner app is deferred |

`keyref source add NAME --path /absolute/vault.db` registers another local vault; `keyref source remove NAME` drops it from the configuration and leaves its file alone. A local vault's directory must be private (mode 0700) — keyref refuses to create or open one otherwise.

`keyref pair` makes `sync` the default source, which is what the commands did before sources existed; `keyref source default local` switches back.

### Local sources

```sh
keyref init                                   # create the local vault
keyref set my-ref < /path/to/secret-input     # store a secret, read from stdin
keyref set my-ref --allow-command curl --description "docs proxy" < key
keyref get my-ref                             # ref, name, description, type, mask
keyref get my-ref --reveal                    # the raw bytes, nothing else
keyref delete my-ref
keyref exec --env TOKEN=my-ref -- /absolute/path/to/consumer
```

The master key is 32 random bytes. `keyref init` generates one and stores it in the OS keyring (macOS Keychain, Linux Secret Service); `KEYREF_LOCAL_MASTER` overrides it for headless use, carrying the same key as the standard base64 encoding of 32 bytes. An environment-provided key is used as-is and never copied into the keyring. Losing the key means losing the vault — keyref cannot recover or regenerate it.

`set` reads 1 byte to 1 MiB from stdin. By default exactly one trailing newline (`\n` or `\r\n`) is stripped, so `echo "$TOKEN" | keyref set tok` stores the token itself; `--raw` keeps every byte. When stdin is a terminal the value is read as one line without echo. The value never appears in the command arguments or in any output, and the result says `created "tok"` or `replaced "tok"`. A value shorter than 8 bytes gets a warning on stderr because redaction is less reliable for short values. A ref follows design §6.1 — one lowercase letter, or 2–64 lowercase letters, digits and hyphens starting with a letter and ending with a letter or digit — and `set` refuses anything else. `--description`, repeatable `--allow-command` and repeatable `--allow-host` write the entry meta; a replacement rewrites the whole meta, so a caller that does not know the value cannot keep or widen the old policy. `get` prints the mask sealed at write time (a known §6.1 prefix plus the last four characters when the value is long enough, otherwise `***`). `--reveal` is the one deliberate plaintext path: it writes the raw secret bytes to stdout and nothing else, it exists for local sources only, and the paired vault rejects it. It asks for confirmation on the controlling terminal (`/dev/tty`, answering `y` or `yes`), never on stdin/stdout, so `keyref get tok --reveal | pbcopy` still works; without a controlling terminal it refuses with exit 10. There is no flag or environment variable that skips the confirmation.

A local vault stores each row id as an HMAC of the ref, but the ref itself, mask, size, description and policy live in a separately encrypted meta blob; `list` and `get` decrypt only that meta, never the secret. Without the master key the file reveals neither refs nor values. Vaults created before encrypted meta keep working: `get <ref>` returns a conservative `***` mask without decrypting or writing the row. Legacy rows remain absent from `list` until an authorized `exec` reads the secret and backfills its actual mask and size, or `set` replaces the row. The library marks unknown metadata as `Incomplete`; a lost original write time remains zero. Schema migration and backfill are safe across concurrent opens, replacements and deletions.

`exec` on a local source is the same code path as on the paired one: the injection shapes, the redactor and the pre-spawn checks are identical (design §7.3, §7.4). Command policy differs: a local row with an empty `allowCommands` keeps the built-in deny list (a slip guard, not a boundary); a non-empty list written by `keyref set --allow-command` is an exact whitelist; `allowedHosts` parses HTTP(S) URLs in argv and matches the actual hostname, including URLs with userinfo, ports or IPv6 addresses; malformed URLs fail closed without echoing their contents. This is an argument check, not network isolation: it cannot constrain redirects or endpoints loaded from a child's configuration. A paired-vault item must name its commands in `allowCommands` — an empty list allows nothing unless the owner set `commandPolicy = allow-all` on iOS (protocol v2 H). There is no grant, no approval round and no remote audit on a local source.

For both sources, `--pty` drains the terminal output after the child exits. The drain uses a two-second read deadline and accepts at most 1 MiB after draining begins; time spent writing redacted output does not count against the deadline. If the terminal cannot be fully drained, Keyref returns exit code 14 and discards remaining buffered output. Redacted output already delivered to the caller cannot be recalled.

### Importing selected environment variables

```sh
keyref import-env --source local --file /path/to/input.env \
  --map PROVIDER_KEY=provider-key --map OTHER_KEY=other-key
```

Each repeatable `--map` explicitly selects a case-sensitive variable name and a distinct ref. Put values only in the input file; `--map` takes names and refs, which can appear in output. Names use ASCII letters, digits and underscores, starting with a letter or underscore. Duplicate names or refs, missing selected variables, and selected empty values are rejected. A selected value must fit the same 1-byte to 1-MiB range as `set`. A file is limited to 16 MiB and 10,000 assignments, a name to 256 bytes and a batch to 256 mappings.

The input must be a regular file. It accepts blank lines, comments, `NAME=value` and `export NAME=value`, with optional leading spaces or tabs. Lines may end with LF or CRLF, and the last line may omit the newline; a bare carriage return is rejected. Values may be one unquoted token, one single-quoted token, or one double-quoted token. A comment can follow a value after whitespace. Single quotes preserve their contents literally; double quotes allow a backslash before a backslash, double quote, dollar sign or backtick. An unquoted token cannot contain whitespace, `$`, backticks, backslashes, either quote, `;`, `&`, `|`, `<`, `>`, `(` or `)`. Characters such as `*`, `?`, `[`, `]`, `~`, `{` and `}` are accepted literally. Unescaped `$` or backticks in double quotes, multiple quote fragments, multiline values, and other escapes are rejected. The parser never executes a shell or expands variables, commands or process substitutions. Syntax on unselected lines is validated too; duplicate variable assignments are rejected.

The entire input and all mappings are validated before the vault is opened. Entries are committed together: new entries use the local default command policy; replacements preserve their existing description, command whitelist and host restrictions; equal values return `unchanged` without rewriting ciphertext or incrementing the write counter. Existing legacy rows with no meta remain unchanged on an equal-value import and may stay absent from `list` until normal backfill. A corrupt existing row fails the batch. Opening an older vault may separately migrate its schema before the batch begins. The commit is atomic, but `exec` reads multiple refs separately and can observe values from different commits; coordinate imports with consumers that require a matching set.

Output contains only the variable name, ref and `created`, `replaced` or `unchanged` status; error diagnostics contain fixed codes and, for line-specific errors, a line number. Before writing, the command rejects an input if a selected or unselected assignment value would appear in any possible success output; short values can therefore be rejected even when their size is valid. Such a collision reports `OUTPUT_CONFLICT` when it can do so without disclosing a value; after the file is read, a diagnostic that would itself contain a value is suppressed. Invalid value syntax, binary input or an input exceeding the assignment limit can also produce a nonzero exit without a diagnostic because its values cannot be fully checked. Errors reported before the file is read use fixed diagnostics that do not depend on its contents, but they cannot be checked for a coincidental match with a value in the file. No value, mask, hash or value length is intentionally printed. The input file itself is left in place and can contain plaintext; protect or remove it separately as appropriate. Newly created entries use the local built-in deny list, not a per-consumer whitelist. Short values are less reliably redacted. A commit or output I/O failure can leave the outcome unknown. Before retrying, coordinate other writers and check the intended current state: reimporting an older value can overwrite a concurrent rotation.

### Synced login items

```sh
keyref exec --stdin-login login-ref -- /absolute/path/to/consumer
```

The CLI must be paired and unlocked, the item must be injectable, and the item's explicit `allowCommands` policy must permit it. The caller supplies the absolute path of a trusted subcommand; Keyref's item policy checks the command name. Keyref runs one existing authorization flow for that item, including waiting for one owner decision when the item requires approval — which it does when its meta says `sensitivity = approval` or this device holds no usable `use` grant (protocol v2 I). After authorization, `username` and `value` are read from the same decryption and written to the child's anonymous stdin pipe as two separate lines, in that order, each line terminated by LF, after which the input is closed. Each field must be 1 to 1024 bytes of UTF-8 and must not contain CR, LF or NUL. If the item or a field is missing, unsupported or fails validation, the child is not started. Both fields join the byte-stream redaction of the child's output and are replaced with the marker `***`. The replacement acts on raw bytes and may therefore change machine-readable content such as JSON. This entry point is for CLI use only.

`--stdin-login` is mutually exclusive with `--stdin` and `--pty`. The same item cannot be used in another injection position at the same time. `--env` and the ordinary `--pass` of other items follow the original rules. Keyref validates the command policy; the consuming program validates where the secret actually ends up.

`--timeout` still bounds the approval wait, not the child's runtime. The child stays in the caller's process group, so the caller can cancel Keyref and the child together. Sending a standalone SIGINT or SIGTERM to the child after it started terminates that child. Operations already issued still have to be settled against the consuming program's receipt. Keyref does not automatically re-issue an approval or restart the child after a cancellation, a timeout or the child's exit.

### Go library

`github.com/lidessen/keyref/lib` is the standalone module for embedding. It holds the local store, the execution engine and the shared low-level packages; it must not import `cli/`.

`lib/local` provides the offline store (`Create`, `Open`, `Put`, `Import`, `Use`, `Stat`, `List`, `Delete`, `Close`, plus `ValidRef` and `Mask`). `Put` takes `PutOptions` (description, allowCommands, allowedHosts) and reports whether it created the row; `Import` performs an atomic idempotent batch, and its caller owns and wipes the input values. `Stat` and `List` decrypt only the encrypted meta. `Use` provides the plaintext only inside the callback; callers should avoid retaining or logging it, and in-memory clearing is not isolation from a same-user process:

```go
vault, err := local.Open(path, masterKey) // local.Create makes a new vault
// check err; call Close when done with the vault.
```

`lib/exec` is the execution engine (`Run`, `Redactor`, `CheckCommand`, `CollectRefs`). It knows no sources: adapters translate their metadata into `exec.Policy`, and a source whose empty allow-list allows nothing sets `RequireAllowList` (the paired vault does; the local one does not). `lib/secret` holds the guarded buffers and `lib/exitcode` pins the exit-code table.

Store failures are distinguishable without parsing messages (design §17.7): `errors.Is` separates a missing vault from an existing one, insecure permissions, a wrong key, an invalid ref or value, a missing entry, a spent write budget and a corrupt vault, while a cancelled `context` comes back unchanged. `Error()` is a fixed, safe text — the underlying cause stays reachable through `Unwrap`. The table is in [lib/local/README.md](../lib/local/README.md).

The CLI reaches the store through `cli/internal/localvault`, which resolves the master key from the OS keyring or `KEYREF_LOCAL_MASTER`, and the engine through adapters in `cli/cmd/keyref`. No other backend ships today: the paired vault is read through the synced path, not through `lib/local`.

The default server is the official hosted service. `keyref server set https://keys.example.com` or the `KEYREF_SERVER` environment variable points the CLI at a self-hosted one. The pairing QR code carries that origin, and the owner confirms a server change; this pairing path is frozen while the owner app is deferred. Encryption on both sides does not depend on who is running the server.

- The language is **Go** (since design v0.4, the same language as the server; the earlier "Rust + zeroize" decision was overturned and memory hygiene was downgraded to guarded allocation plus explicit zeroing — see design §12.2).
- Private keys go into the OS keyring (macOS Keychain, Linux Secret Service). Unwrapped item keys and secret plaintext live only in guarded memory (memguard: mlock, invisible to the GC, explicitly zeroed at `lock` and on exit).
- Never run user commands through a shell. `sh -c`, `echo`, `env` and the like are rejected by default.
- Machine-readable output uses English headers so agents can parse it.

Directory layout (actual tree, checked 2026-11-19):

```
lib/                      # standalone module for embedding
├── exec/                 # policy (including shebang parsing), injection, redaction, pty/reply
├── exitcode/             # the exit-code table of design §7.6
├── local/                # the offline encrypted store
└── secret/               # memguard guarded buffers, secret JSON parsing without strings

cli/
├── cmd/keyref/           # command entry points (main.go + mcp.go: stdio JSON-RPC) and source adapters
├── internal/approval/    # approval requests / polling / one-time unwrap for approval items (design §8.3)
├── internal/audit/       # boxing and upload of exec audit events
├── internal/client/      # a thin HTTP client for the sync API
├── internal/config/      # origin configuration (0700 directory)
├── internal/decider/     # the optional auto-approval delegate and its mandatory review gate (design v0.8 §14.8)
├── internal/device/      # device identity: X25519 HPKE key + signing key
├── internal/localvault/  # the local master key: OS keyring, KEYREF_LOCAL_MASTER override
├── internal/itemcrypt/   # grant unwrap, meta/secret decryption
├── internal/keyring/     # the SecretStore interface; a go-keyring implementation; a directory implementation for tests
├── internal/meta/        # list/get: decrypts only the meta and prints masks
├── internal/pair/        # QR code generation, pair/register, pair/status polling
├── internal/qr/          # terminal QR rendering
├── internal/session/     # challenge → token, token reuse and renewal
├── internal/cache/       # cache.sqlite (0600, ciphertext cache)
├── internal/source/      # the source registry: local (default) and sync
├── internal/syncing/     # applying server changes to the local cache
├── internal/testowner/   # a software P-256 owner for tests and e2e
└── e2e/                  # //go:build e2e end-to-end tests
```

Accept against fixed fixtures: the fixture plaintext must not appear in the stdout/stderr of `list`, `get` or `exec`, including base64, hex and URL encodings.
