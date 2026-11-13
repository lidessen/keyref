# Local store library

`github.com/lidessen/keyref/cli/local` provides an independent, offline store
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
(description, allowCommands, allowedHosts) and reports whether it created a new
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

The package is in the Go `cli` module, which pins its `proto` dependency.
Applications use `github.com/lidessen/keyref/cli/local` directly (`Open` /
`Create`); `cli/internal/localvault` resolves the master key from the OS
keyring or `KEYREF_LOCAL_MASTER`. No other backend ships today.

The Keyref repository is private. Consumers need authorized Git access and should
set `GOPRIVATE=github.com/lidessen/keyref` when resolving its modules.
