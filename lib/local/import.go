package local

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"
	"unicode/utf8"

	keycrypto "github.com/lidessen/keyref/proto/crypto"
)

// maxImportItems bounds one atomic import batch. It matches the CLI's
// explicit mapping limit so a caller cannot make Import hold an
// unbounded number of caller-owned plaintext values at once.
const maxImportItems = 256

// ImportItem is one requested ref/value pair. Import never mutates or
// wipes Value: the caller keeps ownership and must wipe it when done.
type ImportItem struct {
	Ref   string
	Value []byte
}

// ImportStatus reports what Import did for one item.
type ImportStatus string

const (
	ImportCreated   ImportStatus = "created"
	ImportReplaced  ImportStatus = "replaced"
	ImportUnchanged ImportStatus = "unchanged"
)

// importPlan is one decided row. existing is the already validated meta
// of a replaced row, or nil when the row is new or has legacy null meta.
type importPlan struct {
	status   ImportStatus
	id       string
	existing *Meta
	value    []byte
}

// Import atomically creates or replaces a batch of secrets.
//
// All rows commit in one transaction. A failure before commit rolls back
// the batch; if commit itself fails, its outcome may be unknown. Statuses
// are returned only after a successful commit. An item whose value equals the stored
// secret is ImportUnchanged and is not rewritten at all, including a
// legacy row with missing or incomplete meta and even when the vault is
// at its write limit. A replacement keeps the existing description and
// host restrictions, recomputes the mask, size and
// update time, and keeps the meta size bound; a new item gets the
// default empty policy. A corrupt existing meta or secret fails the
// whole batch closed.
//
// At most 256 items are accepted. Duplicate refs, refs outside ValidRef,
// and values outside 1..1 MiB are rejected before the transaction starts.
// Import holds s.mu.RLock
// until it returns, uses a dedicated connection and BEGIN IMMEDIATE so
// concurrent Store instances serialize their comparisons and writes,
// and counts only actually changed rows against the vault's 32-bit
// write budget.
func (s *Store) Import(ctx context.Context, items []ImportItem) ([]ImportStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	if len(items) > maxImportItems {
		return nil, ErrInvalidStore
	}
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if !ValidRef(item.Ref) {
			return nil, ErrInvalidRef
		}
		if _, ok := seen[item.Ref]; ok {
			return nil, ErrInvalidStore
		}
		seen[item.Ref] = struct{}{}
		if len(item.Value) == 0 || len(item.Value) > maxValue {
			return nil, ErrInvalidValueSize
		}
	}
	if len(items) == 0 {
		return []ImportStatus{}, nil
	}

	// A dedicated connection is required: the pool has one connection,
	// and a database/sql transaction would hide the explicit BEGIN
	// IMMEDIATE lock semantics from the queries below.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, importError(ctx)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		// The driver can report context cancellation after SQLite started
		// the transaction. Discard the connection so an unconfirmed BEGIN
		// cannot return a live transaction to the pool.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		return nil, importError(ctx)
	}
	committed := false
	defer func() {
		if !committed {
			// Rollback must not inherit a cancelled context. If rollback
			// fails, discard the connection instead of returning an
			// unconfirmed transaction to the pool.
			if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
	}()

	// Decide every row before writing anything. Comparisons run under
	// the write reservation, so a concurrent writer either committed
	// before this BEGIN or waits until this transaction ends.
	plans := make([]importPlan, len(items))
	changed := 0
	for i, item := range items {
		id, err := s.entryID(item.Ref)
		if err != nil {
			return nil, err
		}
		plans[i].id = id
		plans[i].value = item.Value

		// Bound every read so a damaged oversized blob or meta cannot
		// make the process allocate more than one row's maximum.
		var blob, metaBlob []byte
		var blobLen int64
		var metaNull bool
		err = conn.QueryRowContext(ctx,
			"SELECT substr(blob,1,?),length(blob),substr(meta,1,?),meta IS NULL FROM entries WHERE id = ?",
			maxValue+29, maxMeta+1, id).Scan(&blob, &blobLen, &metaBlob, &metaNull)
		if errors.Is(err, sql.ErrNoRows) {
			plans[i].status = ImportCreated
			changed++
			continue
		}
		if err != nil {
			return nil, importError(ctx)
		}
		if blobLen < 28 || blobLen > maxValue+28 {
			return nil, ErrCorruptStore
		}
		// Only a genuine legacy NULL meta is accepted as absent; an empty
		// or truncated blob is corrupt and must fail closed.
		if !metaNull {
			existing, err := s.openMeta(id, metaBlob)
			if err != nil || existing.Ref != item.Ref {
				return nil, ErrCorruptStore
			}
			plans[i].existing = existing
		}
		aad, err := keycrypto.SecretAAD(s.id, id)
		if err != nil {
			return nil, classify(ErrInvalidStore, "", err)
		}
		plain, err := keycrypto.OpenBlob(s.key, aad, blob)
		if err != nil {
			return nil, classify(ErrCorruptStore, "", err)
		}
		if len(plain) == 0 || len(plain) > maxValue {
			keycrypto.WipeKey(plain)
			return nil, ErrCorruptStore
		}
		comparison := plain
		if plans[i].existing != nil && plans[i].existing.Type == "login" {
			u, value, err := decodeLogin(plain, plans[i].existing)
			keycrypto.WipeKey(u)
			if err != nil {
				keycrypto.WipeKey(plain)
				return nil, err
			}
			comparison = value
		}
		unchanged := subtle.ConstantTimeCompare(comparison, item.Value) == 1
		if plans[i].existing != nil && plans[i].existing.Type == "login" {
			keycrypto.WipeKey(comparison)
		}
		keycrypto.WipeKey(plain)
		if unchanged {
			plans[i].status = ImportUnchanged
			continue
		}
		plans[i].status = ImportReplaced
		changed++
	}

	if changed > 0 {
		// The comparison decides the exact write count, so the budget
		// check uses that count, not len(items). A single metadata row
		// is required; anything else is a damaged vault.
		res, err := conn.ExecContext(ctx,
			"UPDATE metadata SET writes=writes+? WHERE writes <= ?",
			changed, writeCap-int64(changed))
		if err != nil {
			return nil, writeBudgetError(ctx, conn, "writes <= ?", []any{writeCap - int64(changed)}, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not count the write", err)
		}
		if n != 1 {
			return nil, writeBudgetError(ctx, conn, "writes <= ?", []any{writeCap - int64(changed)}, nil)
		}
	}

	now := time.Now().UnixMilli()
	for i := range plans {
		plan := &plans[i]
		if plan.status != ImportCreated && plan.status != ImportReplaced {
			continue
		}
		m := &Meta{
			V:         1,
			Ref:       items[i].Ref,
			Masked:    Mask(plan.value),
			Bytes:     len(plan.value),
			UpdatedAt: now,
			Policy:    Policy{AllowedHosts: []string{}},
		}
		if plan.existing != nil {
			m.Description = plan.existing.Description
			m.Policy = plan.existing.Policy
			m.Type, m.Username, m.URL = plan.existing.Type, plan.existing.Username, plan.existing.URL
		}
		metaBlob, err := s.sealMeta(plan.id, m)
		if err != nil {
			return nil, err
		}
		if len(metaBlob) > maxMeta {
			return nil, ErrMetaTooLarge
		}
		aad, err := keycrypto.SecretAAD(s.id, plan.id)
		if err != nil {
			return nil, ErrInvalidStore
		}
		stored := plan.value
		if m.Type == "login" {
			if !utf8.Valid(plan.value) {
				return nil, ErrInvalidStore
			}
			stored, err = encodeLogin(m.Username, plan.value)
			if err != nil {
				return nil, err
			}
		}
		blob, err := keycrypto.SealBlob(s.key, aad, stored)
		if m.Type == "login" {
			keycrypto.WipeKey(stored)
		}
		if err != nil {
			return nil, ErrInvalidStore
		}
		if _, err := conn.ExecContext(ctx,
			"INSERT INTO entries(id,meta,blob) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET meta=excluded.meta, blob=excluded.blob",
			plan.id, metaBlob, blob); err != nil {
			return nil, importError(ctx)
		}
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, importError(ctx)
	}
	committed = true

	results := make([]ImportStatus, len(plans))
	for i := range plans {
		results[i] = plans[i].status
	}
	return results, nil
}

// importError maps a database or context failure to a fixed error. Raw
// driver errors can contain SQL text and parameter values, so they are
// never returned.
func importError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrInvalidStore
}
