package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lidessen/keyref/proto/wire"
)

const dirTestVault = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func seedDirectoryVault(t *testing.T, s *Store, devices []Device) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO vaults (vault_id, created_at, recovery_wrap, recovery_kdf_json,
recovery_sign_pub, directory_revision, directory_signed, directory_signature, plan)
VALUES (?, 1, x'00', '{}', x'00', 1, x'00', x'00', 'unlimited')`, dirTestVault); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(ctx, func(tx *sql.Tx) error {
		for i := range devices {
			d := devices[i]
			d.VaultID = dirTestVault
			d.HPKEKEM = wire.KEMX25519
			d.HPKEPublicKey, d.SignPublicKey = []byte{1}, []byte{2}
			d.SignAlg = wire.SignAlgEd25519
			if err := txInsertDevice(ctx, tx, &d); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed devices: %v", err)
	}
}

func deviceRecord(id, kind string, status string) wire.DirectoryDevice {
	return wire.DirectoryDevice{
		DeviceID: id, Kind: kind, Status: status,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: []byte{1},
		SignAlg: wire.SignAlgEd25519, SignPublicKey: []byte{2},
		GrantsDigest: wire.EmptyGrantsDigest(),
	}
}

func deviceStatus(t *testing.T, s *Store, id string) (string, bool) {
	t.Helper()
	var status string
	err := s.db.QueryRow(`SELECT status FROM devices WHERE device_id = ?`, id).Scan(&status)
	if err != nil {
		return "", false
	}
	return status, true
}

// TestUpdateVaultDirectoryRevokesOmittedDevices is the v2 G rule at the
// store layer: the signed directory is the whole device set, so a row
// the directory leaves out is revoked in the same transaction.
func TestUpdateVaultDirectoryRevokesOmittedDevices(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	ownerID, cliID := "owner", "cli"
	seedDirectoryVault(t, s, []Device{
		{ID: ownerID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive, CreatedAt: 1},
		{ID: cliID, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive, CreatedAt: 1},
	})

	revoked, err := s.UpdateVaultDirectory(ctx, dirTestVault, 2, []byte("dir2"), []byte("sig2"),
		[]wire.DirectoryDevice{deviceRecord(ownerID, wire.DeviceKindIOS, wire.DeviceStatusActive)}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0] != cliID {
		t.Fatalf("revoked = %v, want [%s]", revoked, cliID)
	}
	if status, ok := deviceStatus(t, s, cliID); !ok || status != wire.DeviceStatusRevoked {
		t.Fatalf("omitted CLI status = %q (found %v), want revoked", status, ok)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM devices WHERE vault_id = ? AND status = 'active'`, dirTestVault); n != 1 {
		t.Fatalf("active devices = %d, want 1", n)
	}
}

// TestUpdateVaultDirectoryRejectsRevivingRevokedDevice pins the other
// half of v2 G: revocation is terminal, so a directory that lists a
// revoked device as active is refused and nothing is written.
func TestUpdateVaultDirectoryRejectsRevivingRevokedDevice(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	ownerID, cliID := "owner", "cli"
	seedDirectoryVault(t, s, []Device{
		{ID: ownerID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive, CreatedAt: 1},
		{ID: cliID, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusRevoked, CreatedAt: 1},
	})

	_, err := s.UpdateVaultDirectory(ctx, dirTestVault, 2, []byte("dir2"), []byte("sig2"),
		[]wire.DirectoryDevice{
			deviceRecord(ownerID, wire.DeviceKindIOS, wire.DeviceStatusActive),
			deviceRecord(cliID, wire.DeviceKindCLI, wire.DeviceStatusActive),
		}, 100)
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("revive error = %v, want ErrDeviceRevoked", err)
	}
	v, err := s.GetVault(ctx, dirTestVault)
	if err != nil {
		t.Fatal(err)
	}
	if v.DirectoryRevision != 1 {
		t.Fatalf("directory revision = %d, want the refused write rolled back to 1", v.DirectoryRevision)
	}
	if status, _ := deviceStatus(t, s, cliID); status != wire.DeviceStatusRevoked {
		t.Fatalf("CLI status = %q, want revoked", status)
	}
}

// TestTakeoverDirectoryRevokesOmittedDevices applies the same omission
// rule to recovery takeover (design §6.3): the takeover directory is a
// complete device set, and anything it leaves out cannot stay active.
func TestTakeoverDirectoryRevokesOmittedDevices(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	ownerID, cliID := "owner", "cli"
	seedDirectoryVault(t, s, []Device{
		{ID: ownerID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive, CreatedAt: 1},
		{ID: cliID, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive, CreatedAt: 1},
	})

	newOwner := "newowner"
	sess := &Session{TokenHash: "hash", DeviceID: newOwner, ExpiresAt: 1 << 40}
	if err := s.TakeoverDirectory(ctx, dirTestVault, 2, []byte("dir2"), []byte("sig2"),
		[]wire.DirectoryDevice{deviceRecord(newOwner, wire.DeviceKindIOS, wire.DeviceStatusActive)},
		sess, 100); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{ownerID, cliID} {
		if status, _ := deviceStatus(t, s, id); status != wire.DeviceStatusRevoked {
			t.Fatalf("%s status = %q, want revoked after takeover", id, status)
		}
	}
	if status, _ := deviceStatus(t, s, newOwner); status != wire.DeviceStatusActive {
		t.Fatalf("new owner status = %q, want active", status)
	}
}
