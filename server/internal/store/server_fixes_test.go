package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lidessen/keyref/proto/wire"
)

func countRows(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDeleteVaultCascadeRemovesMessages(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO devices (device_id, vault_id, kind, status, hpke_kem, hpke_public_key, sign_alg, sign_public_key, label, created_at)
VALUES ('dev1','v1','source','active','x25519',x'00','ed25519',x'00','l',1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertMessage(ctx, &Message{VaultID: "v1", MessageID: "m1", SourceDeviceID: "dev1",
		Status: wire.MessageStatusActive, Envelope: []byte("e"), RequestSignature: []byte("s"),
		CreatedAt: 1, ExpiresAt: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO message_usage_daily (device_id, day, uploads) VALUES ('dev1','2026-01-01',1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteVaultCascade(ctx, "v1"); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM messages`); n != 0 {
		t.Fatalf("messages left: %d", n)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM message_usage_daily`); n != 0 {
		t.Fatalf("message_usage_daily left: %d", n)
	}
}

func TestCountActiveMessagesByDeviceSkipsExpired(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	for id, exp := range map[string]int64{"m1": 100, "m2": 200} {
		if err := s.InsertMessage(ctx, &Message{VaultID: "v1", MessageID: id, SourceDeviceID: "d",
			Status: wire.MessageStatusActive, Envelope: []byte("e"), RequestSignature: []byte("s"),
			CreatedAt: 1, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.CountActiveMessagesByDevice(ctx, "v1", "d", 150)
	if err != nil || n != 1 {
		t.Fatalf("count = %d, %v; want 1", n, err)
	}
}

func TestPutPairSessionIsOneShot(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	ps := &PairSession{NonceHash: "h1", HPKEPublicKey: []byte("a"), SignPublicKey: []byte("b"), ProposedName: "n", ExpiresAt: 10}
	if err := s.PutPairSession(ctx, ps); err != nil {
		t.Fatal(err)
	}
	other := *ps
	other.HPKEPublicKey = []byte("evil")
	if err := s.PutPairSession(ctx, &other); !errors.Is(err, ErrPairConsumed) {
		t.Fatalf("re-register err = %v, want ErrPairConsumed", err)
	}
	got, err := s.GetPairSession(ctx, "h1")
	if err != nil || string(got.HPKEPublicKey) != "a" {
		t.Fatalf("pending row overwritten: %+v %v", got, err)
	}
	if err := s.DeleteExpiredPairSessions(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPairSession(ctx, "h1"); err != nil {
		t.Fatalf("unexpired row swept: %v", err)
	}
	if err := s.DeleteExpiredPairSessions(ctx, 11); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPairSession(ctx, "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired row kept: %v", err)
	}
}

func TestDecideApprovalForMessageRefusesExpired(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	if err := s.InsertMessage(ctx, &Message{VaultID: "v1", MessageID: "m1", SourceDeviceID: "d",
		Status: wire.MessageStatusActive, Envelope: []byte("e"), RequestSignature: []byte("s"),
		CreatedAt: 1, ExpiresAt: 100}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertApproval(ctx, &Approval{ID: "a1", VaultID: "v1", CLIDeviceID: "c", ItemID: "m1",
		Subject: "message:m1", RequestCiphertext: []byte("x"), RequestSignature: []byte("y"),
		Status: wire.ApprovalStatusPending, ExpiresAt: 1000, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	err := s.DecideApprovalForMessage(ctx, "v1", "a1", "m1", "dec", true, []byte("w"), 2000, 150)
	if !errors.Is(err, ErrApprovalNotPending) {
		t.Fatalf("expired message: err = %v, want ErrApprovalNotPending", err)
	}
	a, _ := s.GetApproval(ctx, "v1", "a1")
	if a.Status != wire.ApprovalStatusPending {
		t.Fatalf("approval status = %s", a.Status)
	}
}

func TestDecideApprovalExpiresLatePending(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), DBFileName))
	ctx := context.Background()
	aid := "0123456789abcdef0123456789abcdef"
	if err := s.InsertApproval(ctx, &Approval{ID: aid, VaultID: "v1", CLIDeviceID: "c", ItemID: "i",
		Subject: "item:i", RequestCiphertext: []byte("x"), RequestSignature: []byte("y"),
		Status: wire.ApprovalStatusPending, ExpiresAt: 1000, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	err := s.DecideApproval(ctx, "v1", aid, "dec", true, []byte("w"), 5000, 1001)
	if !errors.Is(err, ErrApprovalNotPending) {
		t.Fatalf("err = %v, want ErrApprovalNotPending", err)
	}
	a, _ := s.GetApproval(ctx, "v1", aid)
	if a.Status != wire.ApprovalStatusExpired {
		t.Fatalf("status = %s, want expired (flip must commit)", a.Status)
	}
}
