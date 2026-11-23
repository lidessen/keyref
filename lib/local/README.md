# Local store library

`github.com/lidessen/keyref/lib/local` provides an independent, offline store
for applications embedding Keyref. It is separate from the synchronized vault:
it needs no pairing or server, and does not implement owner approval, grants,
remote audit, sync or the owner-side `LOCAL` item type.

The caller must supply the same 32-byte master key on every open and keep it
separately from the store. `Create` explicitly creates a new file and never
overwrites one; `Open` only opens an existing file and verifies the key. Both
require an absolute path inside an existing private directory. The store file
is created with mode 0600. A missing key does not initialize a store. Recovery
of a lost key is not provided.

`Put`, `Use`, `Stat` and `Delete` accept a reference; `List` enumerates metadata. `Put` refuses a
ref outside the design §6.1 grammar (`ValidRef`), takes `PutOptions`
(description, allowedHosts) and reports whether it created a new
entry. `Stat` and `List` decrypt only the encrypted meta and never touch the
secret; `Mask` derives the display mask at write time. `Use` supplies decrypted
bytes to a trusted callback only and wipes that buffer after it returns. The
caller is responsible for determining who may use each reference, choosing the
trusted destination, and ensuring that callback code does not retain or
disclose the secret. The library keeps derived keys and wipes them on `Close`.
A `Use` already decrypted may continue its callback after `Close` returns;
closing or revoking access cannot undo an operation already in flight. Wiping
is best effort: Go, the cryptographic implementation and same-user processes
can retain or access data; this library is not an OS sandbox.

`Import` accepts up to 256 distinct `ImportItem` references and their caller-owned
value slices. It validates the batch and commits all changed rows in one
transaction. It returns one `created`, `replaced` or `unchanged` status per
item only after commit; an error never returns partial statuses. New rows use
the local default policy, and replacements preserve valid existing description
and policy. Equal values do not rewrite ciphertext or consume the write count.
The caller must keep its slices stable during the call and wipe them afterward.
A commit I/O error can leave the outcome unknown. Before retrying, coordinate
other writers and check the intended current state: importing older values can
overwrite a concurrent rotation. Each `Use` reads separately, so a consumer
reading several refs can observe values from different commits even though each
import commits atomically. An equal legacy row with no meta remains without meta
until normal backfill. Opening an older vault may separately migrate its schema
before an import begins.

The SQLite file stores encrypted values, encrypted meta and keyed reference
identifiers. Each row's meta (ref, mask, size, description, update time and
execution policy) is AES-256-GCM encrypted with its own key and AAD; values use
Keyref's existing AES-256-GCM implementation with random nonces and bind each
record to its store and reference identifier. HKDF derives separate
encryption, meta and reference-index keys. Transactions protect concurrent
writes; the store tracks a maximum of 2³²−1 encrypted writes per vault. The
counter is stored in the database, so modifying or restoring the database can
undo that limit. This format does not prevent rollback of an entire old copy
of the file and is not compatible with the synchronized vault's format. Back up
both the encrypted file and the independently stored master key through an
appropriate process. Do not treat deleting an entry as secure deletion of all
previous disk copies.

A vault created before encrypted meta gets a nullable `meta` column on open;
concurrent opens serialize this schema migration. Old rows have only HMAC refs,
so their refs cannot be recovered by decrypting the file. `Stat(ref)` stays
read-only and returns `Incomplete: true`, mask `***`, and zero bytes/update time
meaning unknown. It never persists these placeholder values. `List` omits rows
without meta until `Use(ref)` backfills the mask and size from an authorized
secret read, or `Put` replaces the row. The old write time remains zero because
it cannot be recovered. Backfill compares both ciphertexts and counts the write
in the same transaction, so it cannot overwrite a concurrent replacement or
resurrect a deletion. Previously persisted zero-byte meta is recognized as
incomplete and repaired on `Use` as well. Legacy refs outside `ValidRef` remain
usable by `Use` but require a new `Put` with a valid ref to become listable.
A backfill write failure aborts `Use` before its callback; modern rows do not
need a migration write.

The directory and file must be controlled by the application owner. The final
file is checked for a symlink, but opening SQLite by path is not a defense
against another process with the same filesystem authority changing that path
between checks. If initialization fails after creating the file, the incomplete
file is left for inspection; the library will not silently overwrite it.

The package lives in the standalone `github.com/lidessen/keyref/lib` module and
must never import `cli/`. This package depends only on
`github.com/lidessen/keyref/proto` and the pure-Go SQLite driver; the module as
a whole additionally carries the execution engine's `memguard` and `x/sys`
(pty), but none of the CLI's keyring, D-Bus, QR or HTTP dependencies.
Applications use `github.com/lidessen/keyref/lib/local` directly
(`Create` / `Open`); `cli/internal/localvault` resolves the master key from the
OS keyring or `KEYREF_LOCAL_MASTER`. No other backend ships today. The
repository is public, so no `GOPRIVATE` setting is needed to fetch it; a
consumer outside this workspace normally pulls it through a `replace` directive
or a pinned version.

## Errors

Failures are distinguishable without parsing messages (design §17.7); check them
with `errors.Is`:

| Error | Meaning |
| --- | --- |
| `ErrStoreNotFound` | no vault file at that path |
| `ErrStoreExists` | something is already at the path where a new vault was to be created |
| `ErrInsecurePermissions` | the vault's directory is not mode 0700, or the vault file is not mode 0600 |
| `ErrInvalidKey` | the master key does not open this vault — reported while opening, before any row is read |
| `ErrInvalidRef` | a ref outside the design §6.1 grammar |
| `ErrInvalidValueSize` | a value of 0 bytes or more than 1 MiB |
| `ErrNotFound` | no such entry, including a ref that could never have one |
| `ErrWriteLimit` | the vault's 2³²−1 write budget is spent; every written row is kept |
| `ErrCorruptStore` | the file's contents do not read as a vault: a missing or malformed metadata row, ciphertext or meta that does not decrypt or validate, or a stored value outside the format's limits |
| `ErrMetaTooLarge` | a sealed meta blob over the 64 KiB bound |
| `ErrClosed` | the store is closed |
| `ErrInvalidStore` | a path that cannot hold a vault, an argument rejected outright (an entry policy with an empty or NUL member, an import batch over its limits) and database failures with nothing better to say |

`Error()` returns that fixed text and never includes database or filesystem
error text, which can carry SQL text and parameter values; the underlying cause
stays reachable through `Unwrap` for a caller whose own audience can take it. A
cancelled or expired `context` comes back unchanged and is never reported as a
vault error.

A wrong key and damaged contents are separate failures: the key is verified
against the vault's check blob while opening, so an `ErrCorruptStore` after a
successful open is the row, not the caller's key.
