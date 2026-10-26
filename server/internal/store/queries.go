package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/lidessen/keyref/proto/wire"
)

// ErrNotFound is returned by getters for absent rows.
var ErrNotFound = errors.New("store: row not found")

// ErrRevisionConflict is returned when a write does not satisfy the
// revision rule (exactly stored+1 for items and tombstones, strictly
// increasing for grants and directories, stored+1 for takeovers) at
// commit time. The authoritative check runs inside the write
// transaction, so concurrent writers can never both win.
var ErrRevisionConflict = errors.New("store: revision conflict")

// WithTx runs fn inside one transaction. Composed operations below build
// on it so that row writes and change-log appends commit atomically
// (design §6.3: a grant write and its synthetic item change must land
// together).
func (s *Store) WithTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// vaults

const vaultCols = `vault_id, created_at, recovery_wrap, recovery_kdf_json,
recovery_sign_pub, directory_revision, directory_signed, directory_signature,
plan, plan_expires_at, frozen_at`

func scanVault(row interface{ Scan(...any) error }) (*Vault, error) {
	var v Vault
	err := row.Scan(&v.ID, &v.CreatedAt, &v.RecoveryWrap, &v.RecoveryKDFJSON,
		&v.RecoverySignPub, &v.DirectoryRevision, &v.DirectorySigned, &v.DirectorySignature,
		&v.Plan, &v.PlanExpiresAt, &v.FrozenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan vault: %w", err)
	}
	return &v, nil
}

// GetVault loads a vault row; ErrNotFound when absent.
func (s *Store) GetVault(ctx context.Context, vaultID string) (*Vault, error) {
	return scanVault(s.db.QueryRowContext(ctx,
		`SELECT `+vaultCols+` FROM vaults WHERE vault_id = ?`, vaultID))
}

// CreateVault inserts the vault and its first device, and appends the
// initial directory change, in one transaction.
func (s *Store) CreateVault(ctx context.Context, v *Vault, d *Device) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO vaults (`+vaultCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			v.ID, v.CreatedAt, v.RecoveryWrap, v.RecoveryKDFJSON, v.RecoverySignPub,
			v.DirectoryRevision, v.DirectorySigned, v.DirectorySignature,
			v.Plan, v.PlanExpiresAt, v.FrozenAt); err != nil {
			return fmt.Errorf("store: insert vault: %w", err)
		}
		if err := txInsertDevice(ctx, tx, d); err != nil {
			return err
		}
		eid, err := wire.EntityIDDirectory(v.ID)
		if err != nil {
			return err
		}
		return txAppendChange(ctx, tx, v.ID, wire.EntityDirectory, eid, v.CreatedAt)
	})
}

// UpdateVaultDirectory stores a newly signed directory (v2: including its
// signature), upserts device rows from the directory records, and
// appends the directory change — atomically. Sessions of revoked devices
// are NOT deleted: per design §8.4 the revoked device's session keeps
// GET /v1/sync access (that is how the revocation is delivered); every
// other endpoint rejects it. Returns the device ids that transitioned
// to revoked.
func (s *Store) UpdateVaultDirectory(ctx context.Context, vaultID string, revision int64,
	signed, signature []byte, records []wire.DirectoryDevice, now int64) (revoked []string, err error) {
	err = s.WithTx(ctx, func(tx *sql.Tx) error {
		revoked = nil
		var stored int64
		if err := tx.QueryRowContext(ctx,
			`SELECT directory_revision FROM vaults WHERE vault_id = ?`, vaultID).Scan(&stored); err != nil {
			return fmt.Errorf("store: update vault directory: read current: %w", err)
		}
		if revision <= stored {
			return ErrRevisionConflict // strictly increasing (§6.15)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE vaults SET directory_revision = ?, directory_signed = ?, directory_signature = ? WHERE vault_id = ?`,
			revision, signed, signature, vaultID); err != nil {
			return fmt.Errorf("store: update vault directory: %w", err)
		}
		for _, rec := range records {
			wasRevoked, err := txUpsertDeviceFromDirectory(ctx, tx, vaultID, rec, now)
			if err != nil {
				return err
			}
			if wasRevoked {
				revoked = append(revoked, rec.DeviceID)
			}
		}
		eid, err := wire.EntityIDDirectory(vaultID)
		if err != nil {
			return err
		}
		return txAppendChange(ctx, tx, vaultID, wire.EntityDirectory, eid, now)
	})
	if err != nil {
		return nil, err
	}
	return revoked, nil
}

// TakeoverDirectory re-anchors the directory after recovery takeover
// (design §8.5): stores the new directory, upserts devices, kills every
// session of the vault, inserts the new owner session and appends the
// directory change — atomically.
func (s *Store) TakeoverDirectory(ctx context.Context, vaultID string, revision int64,
	signed, ownerSignature []byte, records []wire.DirectoryDevice,
	newSession *Session, now int64) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		var stored int64
		if err := tx.QueryRowContext(ctx,
			`SELECT directory_revision FROM vaults WHERE vault_id = ?`, vaultID).Scan(&stored); err != nil {
			return fmt.Errorf("store: takeover: read current: %w", err)
		}
		if revision != stored+1 {
			return ErrRevisionConflict // takeover bumps by exactly one (§8.5)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE vaults SET directory_revision = ?, directory_signed = ?, directory_signature = ? WHERE vault_id = ?`,
			revision, signed, ownerSignature, vaultID); err != nil {
			return fmt.Errorf("store: takeover: update vault: %w", err)
		}
		for _, rec := range records {
			if _, err := txUpsertDeviceFromDirectory(ctx, tx, vaultID, rec, now); err != nil {
				return err
			}
		}
		if err := txDeleteSessionsByVault(ctx, tx, vaultID); err != nil {
			return err
		}
		if err := txInsertSession(ctx, tx, newSession); err != nil {
			return err
		}
		eid, err := wire.EntityIDDirectory(vaultID)
		if err != nil {
			return err
		}
		return txAppendChange(ctx, tx, vaultID, wire.EntityDirectory, eid, now)
	})
}

// UpdateVaultRecovery replaces the recovery material (PUT /v1/vault/recovery).
func (s *Store) UpdateVaultRecovery(ctx context.Context, vaultID string, wrap []byte, kdfJSON string, signPub []byte) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE vaults SET recovery_wrap = ?, recovery_kdf_json = ?, recovery_sign_pub = ? WHERE vault_id = ?`,
		wrap, kdfJSON, signPub, vaultID)
	if err != nil {
		return fmt.Errorf("store: update recovery: %w", err)
	}
	return nil
}

// SetVaultFrozen / ClearVaultFrozen maintain the hosted idle-freeze stamp.
func (s *Store) SetVaultFrozen(ctx context.Context, vaultID string, at int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vaults SET frozen_at = ? WHERE vault_id = ? AND frozen_at IS NULL`, at, vaultID)
	return err
}

func (s *Store) ClearVaultFrozen(ctx context.Context, vaultID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vaults SET frozen_at = NULL WHERE vault_id = ?`, vaultID)
	return err
}

// DeleteVaultCascade removes every row of the vault across all tables
// (DELETE /v1/vaults step two). The change log goes too: no device is
// left to consume it.
func (s *Store) DeleteVaultCascade(ctx context.Context, vaultID string) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		for _, stmt := range []string{
			`DELETE FROM sessions WHERE device_id IN (SELECT device_id FROM devices WHERE vault_id = ?)`,
			`DELETE FROM grants WHERE vault_id = ?`,
			`DELETE FROM approvals WHERE vault_id = ?`,
			`DELETE FROM audit_events WHERE vault_id = ?`,
			`DELETE FROM changes WHERE vault_id = ?`,
			`DELETE FROM items WHERE vault_id = ?`,
			`DELETE FROM usage_daily WHERE vault_id = ?`,
			`DELETE FROM devices WHERE vault_id = ?`,
			`DELETE FROM vaults WHERE vault_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, stmt, vaultID); err != nil {
				return fmt.Errorf("store: cascade delete: %w", err)
			}
		}
		return nil
	})
}

// ListAllVaults returns vault rows (hosted budget accounting only).
func (s *Store) ListAllVaults(ctx context.Context) ([]Vault, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+vaultCols+` FROM vaults`)
	if err != nil {
		return nil, fmt.Errorf("store: list vaults: %w", err)
	}
	defer rows.Close()
	var out []Vault
	for rows.Next() {
		v, err := scanVault(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// devices

const deviceCols = `device_id, vault_id, kind, status, hpke_kem, hpke_public_key,
sign_alg, sign_public_key, label, created_at, revoked_at, push_token`

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.VaultID, &d.Kind, &d.Status, &d.HPKEKEM, &d.HPKEPublicKey,
		&d.SignAlg, &d.SignPublicKey, &d.Label, &d.CreatedAt, &d.RevokedAt, &d.PushToken)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan device: %w", err)
	}
	return &d, nil
}

// GetDevice loads a device row by id; ErrNotFound when absent.
func (s *Store) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	return scanDevice(s.db.QueryRowContext(ctx,
		`SELECT `+deviceCols+` FROM devices WHERE device_id = ?`, deviceID))
}

// ListDevicesByVault lists the vault's device rows.
func (s *Store) ListDevicesByVault(ctx context.Context, vaultID string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+deviceCols+` FROM devices WHERE vault_id = ? ORDER BY device_id`, vaultID)
	if err != nil {
		return nil, fmt.Errorf("store: list devices: %w", err)
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// CountActiveDevices counts devices with status active of the given kind
// ("ios" | "cli" | ""), used for plan device limits (design §10.5).
func (s *Store) CountActiveDevices(ctx context.Context, vaultID, kind string) (int64, error) {
	var n int64
	var err error
	if kind == "" {
		err = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM devices WHERE vault_id = ? AND status = 'active'`, vaultID).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM devices WHERE vault_id = ? AND status = 'active' AND kind = ?`, vaultID, kind).Scan(&n)
	}
	if err != nil {
		return 0, fmt.Errorf("store: count devices: %w", err)
	}
	return n, nil
}

// CountActiveDevicesAfterDirectory projects a candidate directory onto
// the devices table and returns the resulting active device counts per
// kind ("ios", "cli"): records override row statuses, table rows not
// mentioned keep theirs. Used by PUT /v1/directory to enforce plan
// device ceilings (design §10.5).
func (s *Store) CountActiveDevicesAfterDirectory(ctx context.Context, vaultID string, records []wire.DirectoryDevice) (ios, cli int64, err error) {
	inDirectory := map[string]bool{}
	for _, rec := range records {
		if rec.Status == wire.DeviceStatusActive {
			switch rec.Kind {
			case wire.DeviceKindIOS:
				ios++
			case wire.DeviceKindCLI:
				cli++
			}
		}
		inDirectory[rec.DeviceID] = true
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT device_id, kind FROM devices WHERE vault_id = ? AND status = 'active'`, vaultID)
	if err != nil {
		return 0, 0, fmt.Errorf("store: count devices after directory: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var deviceID, kind string
		if err := rows.Scan(&deviceID, &kind); err != nil {
			return 0, 0, fmt.Errorf("store: scan device: %w", err)
		}
		if inDirectory[deviceID] {
			continue // already counted via its record
		}
		switch kind {
		case wire.DeviceKindIOS:
			ios++
		case wire.DeviceKindCLI:
			cli++
		}
	}
	return ios, cli, rows.Err()
}

func txInsertDevice(ctx context.Context, tx *sql.Tx, d *Device) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO devices (`+deviceCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		d.ID, d.VaultID, d.Kind, d.Status, d.HPKEKEM, d.HPKEPublicKey,
		d.SignAlg, d.SignPublicKey, d.Label, d.CreatedAt, d.RevokedAt, d.PushToken)
	if err != nil {
		return fmt.Errorf("store: insert device: %w", err)
	}
	return nil
}

// txUpsertDeviceFromDirectory mirrors one directory record into the
// devices table. Returns true when the record transitioned the device to
// revoked (sessions of such devices are killed by the caller).
func txUpsertDeviceFromDirectory(ctx context.Context, tx *sql.Tx, vaultID string, rec wire.DirectoryDevice, now int64) (bool, error) {
	var revokedAt any
	if rec.Status == wire.DeviceStatusRevoked {
		revokedAt = now
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE devices SET kind = ?, status = ?, hpke_kem = ?, hpke_public_key = ?,
sign_alg = ?, sign_public_key = ?, label = label, revoked_at = ? WHERE device_id = ? AND vault_id = ?`,
		rec.Kind, rec.Status, rec.HPKEKEM, rec.HPKEPublicKey, rec.SignAlg, rec.SignPublicKey,
		revokedAt, rec.DeviceID, vaultID)
	if err != nil {
		return false, fmt.Errorf("store: update device from directory: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 0 {
		return rec.Status == wire.DeviceStatusRevoked, nil
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO devices (`+deviceCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.DeviceID, vaultID, rec.Kind, rec.Status, rec.HPKEKEM, rec.HPKEPublicKey,
		rec.SignAlg, rec.SignPublicKey, "", now, revokedAt, nil)
	if err != nil {
		return false, fmt.Errorf("store: insert device from directory: %w", err)
	}
	return rec.Status == wire.DeviceStatusRevoked, nil
}

// SetPushToken stores (overwriting) the APNs push token of one device
// (design §8.3 Phase 2: PUT /v1/devices/push-token).
func (s *Store) SetPushToken(ctx context.Context, deviceID, token string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE devices SET push_token = ? WHERE device_id = ?`, token, deviceID)
	if err != nil {
		return fmt.Errorf("store: set push token: %w", err)
	}
	return nil
}

// ClearPushToken removes the push token wherever it is registered — the
// APNs 410 (token rejected) handler's cleanup. Matching by token value
// (not device id) also catches a token that moved between devices.
func (s *Store) ClearPushToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE devices SET push_token = NULL WHERE push_token = ?`, token)
	if err != nil {
		return fmt.Errorf("store: clear push token: %w", err)
	}
	return nil
}

// ListPushTokens returns the push tokens of the vault's active iOS
// devices — the audience of the approval-created push (design §8.3).
// Revoked or pending devices are never pushed.
func (s *Store) ListPushTokens(ctx context.Context, vaultID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT push_token FROM devices
WHERE vault_id = ? AND kind = 'ios' AND status = 'active' AND push_token IS NOT NULL`,
		vaultID)
	if err != nil {
		return nil, fmt.Errorf("store: list push tokens: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tok sql.NullString
		if err := rows.Scan(&tok); err != nil {
			return nil, fmt.Errorf("store: scan push token: %w", err)
		}
		if tok.Valid && tok.String != "" {
			out = append(out, tok.String)
		}
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// items

const itemCols = `vault_id, item_id, revision, tombstone, meta_ciphertext,
secret_ciphertext, vault_wrapped_meta_key, vault_wrapped_item_key,
writer_device_id, signature, updated_at`

func scanItem(row interface{ Scan(...any) error }) (*Item, error) {
	var it Item
	var tombstone int64
	err := row.Scan(&it.VaultID, &it.ItemID, &it.Revision, &tombstone,
		&it.MetaCiphertext, &it.SecretCiphertext, &it.VaultWrappedMetaKey, &it.VaultWrappedItemKey,
		&it.WriterDeviceID, &it.Signature, &it.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan item: %w", err)
	}
	it.Tombstone = tombstone != 0
	return &it, nil
}

// GetItem loads one item row; ErrNotFound when absent.
func (s *Store) GetItem(ctx context.Context, vaultID, itemID string) (*Item, error) {
	return scanItem(s.db.QueryRowContext(ctx,
		`SELECT `+itemCols+` FROM items WHERE vault_id = ? AND item_id = ?`, vaultID, itemID))
}

// PutItem stores an item row and appends the item change atomically.
// The revision rule (design §6.2, §10.6) is enforced inside the
// transaction: a fresh item must start at 1, an existing row must move
// to exactly stored+1. Concurrent same-revision writers cannot both
// succeed.
func (s *Store) PutItem(ctx context.Context, it *Item) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		var current sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT revision FROM items WHERE vault_id = ? AND item_id = ?`,
			it.VaultID, it.ItemID).Scan(&current); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: put item: read current: %w", err)
		}
		if !current.Valid {
			if it.Revision != 1 {
				return ErrRevisionConflict
			}
		} else if it.Revision != current.Int64+1 {
			return ErrRevisionConflict
		}
		if err := txPutItem(ctx, tx, it); err != nil {
			return err
		}
		return txAppendItemChange(ctx, tx, it.VaultID, it.ItemID, it.UpdatedAt)
	})
}

func txPutItem(ctx context.Context, tx *sql.Tx, it *Item) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO items (`+itemCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (vault_id, item_id) DO UPDATE SET revision = excluded.revision,
tombstone = excluded.tombstone, meta_ciphertext = excluded.meta_ciphertext,
secret_ciphertext = excluded.secret_ciphertext,
vault_wrapped_meta_key = excluded.vault_wrapped_meta_key,
vault_wrapped_item_key = excluded.vault_wrapped_item_key,
writer_device_id = excluded.writer_device_id, signature = excluded.signature,
updated_at = excluded.updated_at`,
		it.VaultID, it.ItemID, it.Revision, it.Tombstone, it.MetaCiphertext,
		it.SecretCiphertext, it.VaultWrappedMetaKey, it.VaultWrappedItemKey,
		it.WriterDeviceID, it.Signature, it.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: put item: %w", err)
	}
	return nil
}

// TombstoneItem marks the item deleted, converts its active grants into
// deletion-form rows (each with revision+1) and appends the per-device
// grant changes plus the item change — the cascade of design §6.3.
func (s *Store) TombstoneItem(ctx context.Context, vaultID, itemID string, revision int64,
	writerDeviceID string, signature []byte, now int64) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		var current int64
		err := tx.QueryRowContext(ctx,
			`SELECT revision FROM items WHERE vault_id = ? AND item_id = ?`,
			vaultID, itemID).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("store: tombstone item: read current: %w", err)
		}
		if revision != current+1 {
			return ErrRevisionConflict
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE items SET revision = ?, tombstone = 1, meta_ciphertext = NULL,
secret_ciphertext = NULL, vault_wrapped_meta_key = NULL, vault_wrapped_item_key = NULL,
writer_device_id = ?, signature = ?, updated_at = ? WHERE vault_id = ? AND item_id = ?`,
			revision, writerDeviceID, signature, now, vaultID, itemID); err != nil {
			return fmt.Errorf("store: tombstone item: %w", err)
		}
		grants, err := txListGrantsByItem(ctx, tx, vaultID, itemID, true /* active only */)
		if err != nil {
			return err
		}
		for i := range grants {
			g := &grants[i]
			g.Revision++
			// Deletion-form rows keep zero-length blobs: the columns are
			// NOT NULL and length(hpke_enc) = 0 marks the deletion.
			g.HPKEEnc = []byte{}
			g.WrappedKey = []byte{}
			g.ExpiresAt = sql.NullInt64{}
			if err := txPutGrant(ctx, tx, g); err != nil {
				return err
			}
			if err := txAppendGrantChange(ctx, tx, g, now); err != nil {
				return err
			}
		}
		return txAppendItemChange(ctx, tx, vaultID, itemID, now)
	})
}

// ListItemsByVault lists item rows; tombstoned rows only on request.
func (s *Store) ListItemsByVault(ctx context.Context, vaultID string, includeTombstones bool) ([]Item, error) {
	q := `SELECT ` + itemCols + ` FROM items WHERE vault_id = ?`
	if !includeTombstones {
		q += ` AND tombstone = 0`
	}
	q += ` ORDER BY item_id`
	rows, err := s.db.QueryContext(ctx, q, vaultID)
	if err != nil {
		return nil, fmt.Errorf("store: list items: %w", err)
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *it)
	}
	return out, rows.Err()
}

// CountLiveItems counts non-tombstoned item rows.
func (s *Store) CountLiveItems(ctx context.Context, vaultID string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM items WHERE vault_id = ? AND tombstone = 0`, vaultID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count items: %w", err)
	}
	return n, nil
}

// CountActiveUseGrants counts the live (non-deletion-form) use grants
// that exist for one item. The storage-class invariant of design §6.6
// (v0.7) rests on it: a local item (secret_ciphertext NULL) must never
// carry a use grant, in either direction of the mutual exclusion.
func (s *Store) CountActiveUseGrants(ctx context.Context, vaultID, itemID string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM grants WHERE vault_id = ? AND item_id = ? AND kind = ? AND length(hpke_enc) > 0`,
		vaultID, itemID, wire.GrantKindUse).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count use grants: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// grants

const grantCols = `vault_id, device_id, item_id, kind, hpke_enc, wrapped_key,
expires_at, revision, signature`

func scanGrant(row interface{ Scan(...any) error }) (*Grant, error) {
	var g Grant
	err := row.Scan(&g.VaultID, &g.DeviceID, &g.ItemID, &g.Kind, &g.HPKEEnc, &g.WrappedKey,
		&g.ExpiresAt, &g.Revision, &g.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan grant: %w", err)
	}
	return &g, nil
}

// grantDeleted reports whether a stored row is a deletion-form row.
func grantDeleted(g *Grant) bool { return len(g.HPKEEnc) == 0 }

// GetGrant loads one grant row (either live or deletion form).
func (s *Store) GetGrant(ctx context.Context, vaultID, deviceID, itemID, kind string) (*Grant, error) {
	return scanGrant(s.db.QueryRowContext(ctx,
		`SELECT `+grantCols+` FROM grants
WHERE vault_id = ? AND device_id = ? AND item_id = ? AND kind = ?`,
		vaultID, deviceID, itemID, kind))
}

// ListGrantsByDevice lists a device's grant rows; deletion-form rows
// only on request.
func (s *Store) ListGrantsByDevice(ctx context.Context, vaultID, deviceID string, includeDeleted bool) ([]Grant, error) {
	q := `SELECT ` + grantCols + ` FROM grants WHERE vault_id = ? AND device_id = ?`
	if !includeDeleted {
		q += ` AND length(hpke_enc) > 0`
	}
	q += ` ORDER BY item_id, kind`
	rows, err := s.db.QueryContext(ctx, q, vaultID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("store: list grants by device: %w", err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

// ListGrantsByVault lists all grant rows of the vault; deletion-form rows
// only on request.
func (s *Store) ListGrantsByVault(ctx context.Context, vaultID string, includeDeleted bool) ([]Grant, error) {
	q := `SELECT ` + grantCols + ` FROM grants WHERE vault_id = ?`
	if !includeDeleted {
		q += ` AND length(hpke_enc) > 0`
	}
	q += ` ORDER BY device_id, item_id, kind`
	rows, err := s.db.QueryContext(ctx, q, vaultID)
	if err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func txListGrantsByItem(ctx context.Context, tx *sql.Tx, vaultID, itemID string, activeOnly bool) ([]Grant, error) {
	q := `SELECT ` + grantCols + ` FROM grants WHERE vault_id = ? AND item_id = ?`
	if activeOnly {
		q += ` AND length(hpke_enc) > 0`
	}
	rows, err := tx.QueryContext(ctx, q, vaultID, itemID)
	if err != nil {
		return nil, fmt.Errorf("store: list grants by item: %w", err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func txPutGrant(ctx context.Context, tx *sql.Tx, g *Grant) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO grants (`+grantCols+`) VALUES (?,?,?,?,?,?,?,?,?)
ON CONFLICT (vault_id, device_id, item_id, kind) DO UPDATE SET
hpke_enc = excluded.hpke_enc, wrapped_key = excluded.wrapped_key,
expires_at = excluded.expires_at, revision = excluded.revision,
signature = excluded.signature`,
		g.VaultID, g.DeviceID, g.ItemID, g.Kind, g.HPKEEnc, g.WrappedKey,
		g.ExpiresAt, g.Revision, g.Signature)
	if err != nil {
		return fmt.Errorf("store: put grant: %w", err)
	}
	return nil
}

// PutGrants stores grant rows and appends, per design §6.3, the grant
// change for each row plus a synthetic item change for every distinct
// item referenced — in one transaction. Each row's revision must be
// strictly greater than the stored one (protocol §6.12), enforced inside
// the transaction.
func (s *Store) PutGrants(ctx context.Context, grants []Grant, now int64) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		seenItems := map[string]bool{}
		for i := range grants {
			g := &grants[i]
			var stored sql.NullInt64
			if err := tx.QueryRowContext(ctx,
				`SELECT revision FROM grants WHERE vault_id = ? AND device_id = ? AND item_id = ? AND kind = ?`,
				g.VaultID, g.DeviceID, g.ItemID, g.Kind).Scan(&stored); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("store: put grants: read current: %w", err)
			}
			if stored.Valid && g.Revision <= stored.Int64 {
				return ErrRevisionConflict
			}
			if err := txPutGrant(ctx, tx, g); err != nil {
				return err
			}
			if err := txAppendGrantChange(ctx, tx, g, now); err != nil {
				return err
			}
			if !seenItems[g.ItemID] {
				seenItems[g.ItemID] = true
				if err := txAppendItemChange(ctx, tx, g.VaultID, g.ItemID, now); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// DeleteGrant converts a grant row to its deletion form and appends the
// grant change visible to that device (design §6.3).
func (s *Store) DeleteGrant(ctx context.Context, vaultID, deviceID, itemID, kind string, revision int64, signature []byte, now int64) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		var stored int64
		err := tx.QueryRowContext(ctx,
			`SELECT revision FROM grants WHERE vault_id = ? AND device_id = ? AND item_id = ? AND kind = ?`,
			vaultID, deviceID, itemID, kind).Scan(&stored)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("store: delete grant: read current: %w", err)
		}
		if revision <= stored {
			return ErrRevisionConflict
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE grants SET hpke_enc = ?, wrapped_key = ?, expires_at = NULL,
revision = ?, signature = ? WHERE vault_id = ? AND device_id = ? AND item_id = ? AND kind = ?`,
			[]byte{}, []byte{}, revision, signature, vaultID, deviceID, itemID, kind); err != nil {
			return fmt.Errorf("store: delete grant: %w", err)
		}
		g := &Grant{VaultID: vaultID, DeviceID: deviceID, ItemID: itemID, Kind: kind,
			Revision: revision, Signature: signature}
		return txAppendGrantChange(ctx, tx, g, now)
	})
}

// ---------------------------------------------------------------------------
// audit events

// AppendAuditEvent stores one encrypted audit event with a per-vault
// sequence number.
func (s *Store) AppendAuditEvent(ctx context.Context, vaultID, deviceID string, ciphertext []byte, now int64) (int64, error) {
	var seq int64
	err := s.WithTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_events WHERE vault_id = ?`, vaultID).Scan(&seq); err != nil {
			return fmt.Errorf("store: audit seq: %w", err)
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO audit_events (vault_id, seq, device_id, created_at, ciphertext) VALUES (?,?,?,?,?)`,
			vaultID, seq, deviceID, now, ciphertext)
		if err != nil {
			return fmt.Errorf("store: insert audit: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// ListAuditEvents returns up to limit events with seq greater than after,
// in ascending order, plus whether more remain.
func (s *Store) ListAuditEvents(ctx context.Context, vaultID string, after int64, limit int) ([]AuditEvent, bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, device_id, created_at, ciphertext FROM audit_events
WHERE vault_id = ? AND seq > ? ORDER BY seq LIMIT ?`,
		vaultID, after, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.Seq, &e.DeviceID, &e.CreatedAt, &e.Ciphertext); err != nil {
			return nil, false, fmt.Errorf("store: scan audit: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := false
	if len(out) > limit {
		more = true
		out = out[:limit]
	}
	return out, more, nil
}

// CountAuditEvents counts stored audit events of a vault.
func (s *Store) CountAuditEvents(ctx context.Context, vaultID string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE vault_id = ?`, vaultID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count audit: %w", err)
	}
	return n, nil
}

// TrimAuditEvents enforces retention (design §10.5): keep at most keepMax
// newest events and drop events older than olderThanMs.
func (s *Store) TrimAuditEvents(ctx context.Context, vaultID string, keepMax int64, olderThanMs int64) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM audit_events WHERE vault_id = ? AND created_at < ? AND seq NOT IN
(SELECT seq FROM audit_events WHERE vault_id = ? ORDER BY seq DESC LIMIT ?)`,
		vaultID, olderThanMs, vaultID, keepMax)
	if err != nil {
		return fmt.Errorf("store: trim audit: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`DELETE FROM audit_events WHERE vault_id = ? AND seq NOT IN
(SELECT seq FROM audit_events WHERE vault_id = ? ORDER BY seq DESC LIMIT ?)`,
		vaultID, vaultID, keepMax)
	if err != nil {
		return fmt.Errorf("store: trim audit by count: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// changes log

// ChangeRow is one raw log row.
type ChangeRow struct {
	Seq       int64
	VaultID   string
	Entity    string
	EntityID  string
	CreatedAt int64
}

func txAppendChange(ctx context.Context, tx *sql.Tx, vaultID, entity, entityID string, at int64) error {
	res, err := tx.ExecContext(ctx,
		`INSERT INTO changes (vault_id, entity, entity_id, created_at) VALUES (?,?,?,?)`,
		vaultID, entity, entityID, at)
	if err != nil {
		return fmt.Errorf("store: append change: %w", err)
	}
	if _, err := res.LastInsertId(); err != nil {
		return fmt.Errorf("store: append change: seq: %w", err)
	}
	return nil
}

func txAppendItemChange(ctx context.Context, tx *sql.Tx, vaultID, itemID string, at int64) error {
	eid, err := wire.EntityIDItem(itemID)
	if err != nil {
		return err
	}
	return txAppendChange(ctx, tx, vaultID, wire.EntityItem, eid, at)
}

func txAppendGrantChange(ctx context.Context, tx *sql.Tx, g *Grant, at int64) error {
	eid, err := wire.EntityIDGrant(g.DeviceID, g.ItemID, g.Kind)
	if err != nil {
		return err
	}
	return txAppendChange(ctx, tx, g.VaultID, wire.EntityGrant, eid, at)
}

func txAppendDeviceChange(ctx context.Context, tx *sql.Tx, vaultID, deviceID string, at int64) error {
	eid, err := wire.EntityIDDevice(deviceID)
	if err != nil {
		return err
	}
	return txAppendChange(ctx, tx, vaultID, wire.EntityDevice, eid, at)
}

// ListChanges returns up to limit log rows for the vault with seq greater
// than after, ascending.
func (s *Store) ListChanges(ctx context.Context, vaultID string, after int64, limit int) ([]ChangeRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, vault_id, entity, entity_id, created_at FROM changes
WHERE vault_id = ? AND seq > ? ORDER BY seq LIMIT ?`,
		vaultID, after, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list changes: %w", err)
	}
	defer rows.Close()
	var out []ChangeRow
	for rows.Next() {
		var c ChangeRow
		if err := rows.Scan(&c.Seq, &c.VaultID, &c.Entity, &c.EntityID, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan change: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// MinChangeSeq returns the smallest seq still retained in the global log.
// A nil pointer means the log is empty.
func (s *Store) MinChangeSeq(ctx context.Context) (*int64, error) {
	var v sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(seq) FROM changes`).Scan(&v); err != nil {
		return nil, fmt.Errorf("store: min change seq: %w", err)
	}
	if !v.Valid {
		return nil, nil
	}
	return &v.Int64, nil
}

// MaxChangeSeq returns the highest seq in the global log (0 when empty).
func (s *Store) MaxChangeSeq(ctx context.Context) (int64, error) {
	var v sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(seq) FROM changes`).Scan(&v); err != nil {
		return 0, fmt.Errorf("store: max change seq: %w", err)
	}
	if !v.Valid {
		return 0, nil
	}
	return v.Int64, nil
}

// DeleteChangesOlderThan implements the rolling 90-day log cleanup
// (design §10.6).
func (s *Store) DeleteChangesOlderThan(ctx context.Context, beforeMs int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM changes WHERE created_at < ?`, beforeMs)
	if err != nil {
		return fmt.Errorf("store: cleanup changes: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// sessions

// Session is declared in domain.go.

func txInsertSession(ctx context.Context, tx *sql.Tx, sess *Session) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, device_id, expires_at) VALUES (?,?,?)`,
		sess.TokenHash, sess.DeviceID, sess.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: insert session: %w", err)
	}
	return nil
}

// InsertSession stores a bearer-token hash.
func (s *Store) InsertSession(ctx context.Context, sess *Session) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error { return txInsertSession(ctx, tx, sess) })
}

// LookupSession resolves a bearer token (raw bytes) to its device row.
// Expired sessions never match. ErrNotFound for unknown/expired tokens.
func (s *Store) LookupSession(ctx context.Context, token []byte, now int64) (*Device, error) {
	sum := sha256.Sum256(token)
	row := s.db.QueryRowContext(ctx,
		`SELECT d.device_id, d.vault_id, d.kind, d.status, d.hpke_kem, d.hpke_public_key,
d.sign_alg, d.sign_public_key, d.label, d.created_at, d.revoked_at, d.push_token
FROM sessions s JOIN devices d ON d.device_id = s.device_id
WHERE s.token_hash = ? AND s.expires_at > ?`, hex.EncodeToString(sum[:]), now)
	return scanDevice(row)
}

// DeleteSessionsByDevice drops a device's sessions (session renewal).
func (s *Store) DeleteSessionsByDevice(ctx context.Context, deviceID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE device_id = ?`, deviceID)
	return err
}

func txDeleteSessionsByVault(ctx context.Context, tx *sql.Tx, vaultID string) error {
	_, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE device_id IN (SELECT device_id FROM devices WHERE vault_id = ?)`, vaultID)
	if err != nil {
		return fmt.Errorf("store: delete vault sessions: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// usage counters (usage_daily, also carrying IP registration counters)

// IncrementUsage bumps the counter for (key, day) and returns the new value.
func (s *Store) IncrementUsage(ctx context.Context, key, day string) (int64, error) {
	var n int64
	err := s.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO usage_daily (vault_id, day, requests) VALUES (?,?,1)
ON CONFLICT (vault_id, day) DO UPDATE SET requests = requests + 1`, key, day); err != nil {
			return fmt.Errorf("store: increment usage: %w", err)
		}
		return tx.QueryRowContext(ctx,
			`SELECT requests FROM usage_daily WHERE vault_id = ? AND day = ?`, key, day).Scan(&n)
	})
	return n, err
}

// GetUsage returns the counter for (key, day), 0 when absent.
func (s *Store) GetUsage(ctx context.Context, key, day string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT requests FROM usage_daily WHERE vault_id = ? AND day = ?`, key, day).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: get usage: %w", err)
	}
	return n, nil
}

// HasUsageSince reports whether the key has any counter row on or after
// the given day (idle-freeze evaluation).
func (s *Store) HasUsageSince(ctx context.Context, key, day string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM usage_daily WHERE vault_id = ? AND day >= ? LIMIT 1`, key, day).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: usage since: %w", err)
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// pair sessions

// PutPairSession upserts a pairing registration row (protocol §6.16).
func (s *Store) PutPairSession(ctx context.Context, ps *PairSession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pair_sessions (nonce_hash, hpke_public_key, sign_public_key, proposed_name, expires_at, consumed_at, result_json)
VALUES (?,?,?,?,?,NULL,NULL)
ON CONFLICT (nonce_hash) DO UPDATE SET hpke_public_key = excluded.hpke_public_key,
sign_public_key = excluded.sign_public_key, proposed_name = excluded.proposed_name,
expires_at = excluded.expires_at, consumed_at = NULL, result_json = NULL`,
		ps.NonceHash, ps.HPKEPublicKey, ps.SignPublicKey, ps.ProposedName, ps.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: put pair session: %w", err)
	}
	return nil
}

// GetPairSession loads a pairing registration; ErrNotFound when absent.
func (s *Store) GetPairSession(ctx context.Context, nonceHash string) (*PairSession, error) {
	var ps PairSession
	err := s.db.QueryRowContext(ctx,
		`SELECT nonce_hash, hpke_public_key, sign_public_key, proposed_name, expires_at, consumed_at, result_json
FROM pair_sessions WHERE nonce_hash = ?`, nonceHash).Scan(
		&ps.NonceHash, &ps.HPKEPublicKey, &ps.SignPublicKey, &ps.ProposedName, &ps.ExpiresAt, &ps.ConsumedAt, &ps.ResultJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get pair session: %w", err)
	}
	return &ps, nil
}

// CompletePairing inserts the CLI device and its initial grants, appends
// the device change plus grant and synthetic item changes, and consumes
// the pair session with its §6.18 result JSON — atomically.
func (s *Store) CompletePairing(ctx context.Context, device *Device, grants []Grant, nonceHash, resultJSON string, now int64) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		if err := txInsertDevice(ctx, tx, device); err != nil {
			return err
		}
		seenItems := map[string]bool{}
		for i := range grants {
			g := &grants[i]
			if err := txPutGrant(ctx, tx, g); err != nil {
				return err
			}
			if err := txAppendGrantChange(ctx, tx, g, now); err != nil {
				return err
			}
			if !seenItems[g.ItemID] {
				seenItems[g.ItemID] = true
				if err := txAppendItemChange(ctx, tx, g.VaultID, g.ItemID, now); err != nil {
					return err
				}
			}
		}
		if err := txAppendDeviceChange(ctx, tx, device.VaultID, device.ID, now); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE pair_sessions SET consumed_at = ?, result_json = ? WHERE nonce_hash = ? AND consumed_at IS NULL`,
			now, resultJSON, nonceHash)
		if err != nil {
			return fmt.Errorf("store: consume pair session: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("store: pair session already consumed")
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// storage accounting (design §10.5: item, audit and pending-approval
// ciphertext bytes)

// VaultStorageBytes sums the metered ciphertext bytes of a vault: item
// ciphertexts, audit ciphertexts and PENDING approval request
// ciphertexts (design §10.5: all three count against the quota).
//
// Local items (design §6.6, v0.7) store NULL in secret_ciphertext and
// vault_wrapped_item_key; every length() is therefore wrapped in
// COALESCE so such a row still contributes its meta ciphertext bytes
// (only the missing columns drop out of the sum — length(NULL) is NULL
// and would otherwise void the whole row).
func (s *Store) VaultStorageBytes(ctx context.Context, vaultID string) (int64, error) {
	itemBytes, auditBytes, approvalBytes := int64(0), int64(0), int64(0)
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(COALESCE(length(meta_ciphertext), 0) + COALESCE(length(secret_ciphertext), 0) +
COALESCE(length(vault_wrapped_meta_key), 0) + COALESCE(length(vault_wrapped_item_key), 0)), 0)
FROM items WHERE vault_id = ?`, vaultID).Scan(&itemBytes); err != nil {
		return 0, fmt.Errorf("store: item bytes: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(length(ciphertext)), 0) FROM audit_events WHERE vault_id = ?`,
		vaultID).Scan(&auditBytes); err != nil {
		return 0, fmt.Errorf("store: audit bytes: %w", err)
	}
	approvalBytes, err := s.PendingApprovalBytes(ctx, vaultID)
	if err != nil {
		return 0, err
	}
	return itemBytes + auditBytes + approvalBytes, nil
}

// HealthzWriteProbe verifies the database accepts writes by rewriting the
// user_version pragma with its current value.
func (s *Store) HealthzWriteProbe(ctx context.Context) error {
	var v int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v))
	return err
}
