package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/wire"
)

const (
	tvVault  = "00112233445566778899aabbccddeeff"
	tvItem   = "ffeeddccbbaa99887766554433221100"
	tvDevice = "0123456789abcdef0123456789abcdef"
)

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// schemaSnapshot captures the full sqlite_master definition (excluding
// SQLite's internal objects) to detect any drift across migrations.
func schemaSnapshot(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.db.Query(
		`SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var typ, name, ddl string
		if err := rows.Scan(&typ, &name, &ddl); err != nil {
			t.Fatalf("scan sqlite_master: %v", err)
		}
		out = append(out, typ+" "+name+" "+ddl)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate sqlite_master: %v", err)
	}
	return out
}

func TestOpenCreatesSchemaInWalMode(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))

	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != SchemaVersion {
		t.Fatalf("user_version = %d, want %d", version, SchemaVersion)
	}

	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}

	wantTables := map[string]bool{
		"vaults": false, "devices": false, "items": false, "grants": false,
		"approvals": false, "audit_events": false, "changes": false,
		"sessions": false, "usage_daily": false, "pair_sessions": false,
	}
	wantIndexes := map[string]bool{
		"idx_changes_vault_seq":      false,
		"idx_grants_vault_device":    false,
		"idx_devices_vault_status":   false,
		"idx_approvals_vault_status": false,
		"idx_approvals_cli_status":   false,
	}
	rows, err := s.db.Query(`SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ, name string
		if err := rows.Scan(&typ, &name); err != nil {
			t.Fatal(err)
		}
		switch typ {
		case "table":
			if _, ok := wantTables[name]; !ok {
				t.Errorf("unexpected table %q", name)
			} else {
				wantTables[name] = true
			}
		case "index":
			if _, ok := wantIndexes[name]; !ok {
				t.Errorf("unexpected index %q", name)
			} else {
				wantIndexes[name] = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for name, seen := range wantTables {
		if !seen {
			t.Errorf("missing table %q", name)
		}
	}
	for name, seen := range wantIndexes {
		if !seen {
			t.Errorf("missing index %q", name)
		}
	}
}

func TestMigrateIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DBFileName)

	s1 := openTestStore(t, path)
	itemID, err := wire.EntityIDItem(tvItem)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.AppendChange(context.Background(), tvVault, wire.EntityItem, itemID, 42); err != nil {
		t.Fatalf("seed change: %v", err)
	}
	// An explicit second Migrate call on the live handle must be a no-op.
	if err := s1.Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate on live handle: %v", err)
	}
	snap1 := schemaSnapshot(t, s1)
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening runs startup migration again on the same file.
	s2 := openTestStore(t, path)
	defer s2.Close()
	if err := s2.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate after reopen: %v", err)
	}
	snap2 := schemaSnapshot(t, s2)

	if len(snap1) != len(snap2) {
		t.Fatalf("schema object count changed: %d -> %d", len(snap1), len(snap2))
	}
	for i := range snap1 {
		if snap1[i] != snap2[i] {
			t.Fatalf("schema drifted:\n before: %s\n after:  %s", snap1[i], snap2[i])
		}
	}

	// Data written before the reopen must survive.
	var count int
	if err := s2.db.QueryRow("SELECT COUNT(*) FROM changes").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("changes count after reopen = %d, want 1", count)
	}
}

func TestAppendChangeMonotonicSeq(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()

	grantID, err := wire.EntityIDGrant(tvDevice, tvItem, wire.GrantKindUse)
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := wire.EntityIDDevice(tvDevice)
	if err != nil {
		t.Fatal(err)
	}
	itemID, err := wire.EntityIDItem(tvItem)
	if err != nil {
		t.Fatal(err)
	}

	appends := []struct {
		entity   string
		entityID string
	}{
		{wire.EntityItem, itemID},
		{wire.EntityGrant, grantID},
		{wire.EntityDevice, deviceID},
	}
	var wantSeq int64
	for i, a := range appends {
		seq, err := s.AppendChange(ctx, tvVault, a.entity, a.entityID, int64(1000+i))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		wantSeq++
		if seq != wantSeq {
			t.Fatalf("append %d: seq = %d, want %d", i, seq, wantSeq)
		}
	}

	rows, err := s.db.Query(`SELECT seq, vault_id, entity, entity_id, created_at FROM changes ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var seq, createdAt int64
		var vaultID, entity, entityID string
		if err := rows.Scan(&seq, &vaultID, &entity, &entityID, &createdAt); err != nil {
			t.Fatal(err)
		}
		if seq != int64(i+1) {
			t.Fatalf("row %d: seq = %d", i, seq)
		}
		if vaultID != tvVault || entity != appends[i].entity || entityID != appends[i].entityID {
			t.Fatalf("row %d mismatch: %s %s %s", i, vaultID, entity, entityID)
		}
		if createdAt != int64(1000+i) {
			t.Fatalf("row %d: created_at = %d", i, createdAt)
		}
		i++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if i != len(appends) {
		t.Fatalf("read %d rows, want %d", i, len(appends))
	}
}

func TestAppendChangeValidatesEntityID(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()

	itemID, err := wire.EntityIDItem(tvItem)
	if err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		name     string
		vaultID  string
		entity   string
		entityID string
	}{
		{"entity prefix mismatch", tvVault, wire.EntityDevice, itemID},
		{"unknown entity", tvVault, "bogus", "bogus:" + tvItem},
		{"malformed entity id", tvVault, wire.EntityItem, "item:not-hex"},
		{"bad vault id", "nothex", wire.EntityItem, itemID},
	}
	for _, b := range bad {
		t.Run(b.name, func(t *testing.T) {
			if _, err := s.AppendChange(ctx, b.vaultID, b.entity, b.entityID, 1); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM changes").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("changes count = %d, want 0 (rejected appends must not write rows)", count)
	}
}

func TestBackup(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()

	itemID, err := wire.EntityIDItem(tvItem)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.AppendChange(ctx, tvVault, wire.EntityItem, itemID, int64(i)); err != nil {
			t.Fatal(err)
		}
	}

	out := filepath.Join(t.TempDir(), "backup.db")
	size, err := s.Backup(ctx, out)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if size <= 0 {
		t.Fatalf("backup size = %d, want > 0", size)
	}

	// A second backup to the same target must refuse to overwrite.
	if _, err := s.Backup(ctx, out); err == nil {
		t.Fatal("backup to an existing target should fail")
	}

	// The snapshot must be openable and contain the committed rows.
	s2 := openTestStore(t, out)
	defer s2.Close()
	var count int
	if err := s2.db.QueryRow("SELECT COUNT(*) FROM changes").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("backup changes count = %d, want 3", count)
	}
	var version int
	if err := s2.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != SchemaVersion {
		t.Fatalf("backup user_version = %d, want %d", version, SchemaVersion)
	}
}

func TestDeleteChangesOlderThan(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	itemID, err := wire.EntityIDItem(tvItem)
	if err != nil {
		t.Fatal(err)
	}
	// One stale row (91 days old) and one fresh row.
	if _, err := s.AppendChange(ctx, tvVault, wire.EntityItem, itemID, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE changes SET created_at = ? WHERE seq = 1`, int64(1))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendChange(ctx, tvVault, wire.EntityItem, itemID, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	ninetyDaysAgo := time.Now().Add(-90 * 24 * time.Hour).UnixMilli()
	if err := s.DeleteChangesOlderThan(ctx, ninetyDaysAgo); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM changes").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("changes after cleanup = %d, want 1", count)
	}
}

func TestDevicePushTokenRoundTrip(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	insertDevice := func(deviceID, kind, status string) {
		t.Helper()
		_, err := s.db.Exec(
			`INSERT INTO devices (device_id, vault_id, kind, status, hpke_kem, hpke_public_key,
sign_alg, sign_public_key, label, created_at, revoked_at) VALUES (?,?,?,?,?,?,?,?,?,?,NULL)`,
			deviceID, tvVault, kind, status, "P-256", []byte{1}, "ed25519", []byte{2}, "d", int64(1))
		if err != nil {
			t.Fatal(err)
		}
	}
	insertDevice(tvDevice, "ios", "active")
	owner2 := "22222222222222222222222222222222"
	revoked := "33333333333333333333333333333333"
	cliDev := "44444444444444444444444444444444"
	insertDevice(owner2, "ios", "active")
	insertDevice(revoked, "ios", "revoked")
	insertDevice(cliDev, "cli", "active")

	// Registering overwrites; reading the device row shows the newest
	// token (schema v3 push_token column).
	if err := s.SetPushToken(ctx, tvDevice, "aabb"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPushToken(ctx, tvDevice, "ccdd"); err != nil {
		t.Fatal(err)
	}
	d, err := s.GetDevice(ctx, tvDevice)
	if err != nil {
		t.Fatal(err)
	}
	if !d.PushToken.Valid || d.PushToken.String != "ccdd" {
		t.Fatalf("push_token = %v, want ccdd", d.PushToken)
	}
	if err := s.SetPushToken(ctx, owner2, "eeff"); err != nil {
		t.Fatal(err)
	}

	// The approval push audience is exactly the vault's active iOS
	// devices with a token — not revoked devices, not CLIs.
	toks, err := s.ListPushTokens(ctx, tvVault)
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 2 {
		t.Fatalf("push tokens = %v, want 2", toks)
	}

	// ClearPushToken matches by token value: the APNs 410 handler drops
	// the rejected token wherever it is registered.
	if err := s.ClearPushToken(ctx, "ccdd"); err != nil {
		t.Fatal(err)
	}
	d, err = s.GetDevice(ctx, tvDevice)
	if err != nil {
		t.Fatal(err)
	}
	if d.PushToken.Valid {
		t.Fatalf("push_token not cleared: %v", d.PushToken)
	}
	toks, err = s.ListPushTokens(ctx, tvVault)
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 || toks[0] != "eeff" {
		t.Fatalf("push tokens after clear = %v, want [eeff]", toks)
	}
}
