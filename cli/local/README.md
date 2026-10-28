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

`Put`, `Use` and `Delete` accept a reference. `Use` supplies decrypted bytes to
a trusted callback only and wipes that buffer after it returns. The caller is
responsible for determining who may use each reference, choosing the trusted
destination, and ensuring that callback code does not retain or disclose the
secret. The library keeps derived keys and wipes them on `Close`. A `Use`
already decrypted may continue its callback after `Close` returns; closing or
revoking access cannot undo an operation already in flight.
Wiping is best effort: Go, the cryptographic implementation and same-user
processes can retain or access data; this library is not an OS sandbox.

The SQLite file stores encrypted values and keyed reference identifiers.
Values use Keyref's existing AES-256-GCM implementation with random nonces and
bind each record to its store and reference identifier. HKDF derives separate
encryption and reference-index keys. Transactions protect concurrent writes;
the store tracks a maximum of 2³²−1 encrypted writes per vault. The counter is
stored in the database, so modifying or restoring the database can undo that
limit. This format does not prevent rollback of an entire old copy
of the file and is not compatible with the synchronized vault's format. Back up
both the encrypted file and the independently stored master key through an
appropriate process. Do not treat deleting an entry as secure deletion of all
previous disk copies.

The directory and file must be controlled by the application owner. The final
file is checked for a symlink, but opening SQLite by path is not a defense
against another process with the same filesystem authority changing that path
between checks. If initialization fails after creating the file, the incomplete
file is left for inspection; the library will not silently overwrite it.

The package is in the Go `cli` module, which pins its `proto` dependency.
Applications normally use `github.com/lidessen/keyref/cli/store`: its registry
defaults to this local provider and allows other providers to be registered.
Only local is built in; explicitly selected unavailable providers fail without
falling back. `cli/local` remains the local backend implementation.

The Keyref repository is private. Consumers need authorized Git access and should
set `GOPRIVATE=github.com/lidessen/keyref` when resolving its modules.
