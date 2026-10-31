package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidessen/keyref/proto/wire"
)

const (
	fxVault  = "00112233445566778899aabbccddeeff"
	fxItem   = "ffeeddccbbaa99887766554433221100"
	fxItem2  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fxDevice = "0123456789abcdef0123456789abcdef"
	fxWriter = "99998888777766665555444433332222"
)

// The cache must never contain plaintext secrets (design.md §6.5, §15);
// fixtures use a recognisable marker that tests search for in the raw
// database file.
const fxPlaintextMarker = "sk-CACHE-PLAINTEXT-MARKER"

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	base, err := os.MkdirTemp("", "keyref-store-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "keyref")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// TestCachePermissions pins the permission model of design.md §6.5:
// directory 0700, cache.sqlite 0600 — even when the file already existed
// with looser modes from a previous run.
func TestCachePermissions(t *testing.T) {
	base, err := os.MkdirTemp("", "keyref-perm-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })

	// Pre-create the directory and file with wrong modes to prove Open
	// tightens them.
	dir := filepath.Join(base, "keyref")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CacheFileName), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if got := mode(t, dir); got != 0o700 {
		t.Fatalf("cache directory mode %o, want 0700", got)
	}
	if got := mode(t, s.Path()); got != 0o600 {
		t.Fatalf("cache file mode %o, want 0600", got)
	}
}

func fixtureItem(revision uint64) *wire.ItemData {
	return &wire.ItemData{
		VaultID:          fxVault,
		ItemID:           fxItem,
		Revision:         revision,
		MetaCiphertext:   bytes.Repeat([]byte{0xa1}, 40),
		SecretCiphertext: bytes.Repeat([]byte{0xb2}, 60),
		WriterDeviceID:   fxWriter,
		Signature:        bytes.Repeat([]byte{0xc3}, 64),
		UpdatedAt:        1790000000000,
	}
}

func TestItemRoundtripAndDelete(t *testing.T) {
	s, _ := openTemp(t)
	if err := s.PutItem(fixtureItem(1)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetItem(fxItem)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	want := fixtureItem(1)
	if got.Revision != want.Revision || got.Tombstone != false ||
		!bytes.Equal(got.MetaCiphertext, want.MetaCiphertext) ||
		!bytes.Equal(got.SecretCiphertext, want.SecretCiphertext) ||
		!bytes.Equal(got.Signature, want.Signature) ||
		got.WriterDeviceID != want.WriterDeviceID || got.UpdatedAt != want.UpdatedAt {
		t.Fatalf("item roundtrip mismatch: %+v", got)
	}

	if err := s.PutItem(fixtureItem(2)); err != nil {
		t.Fatal(err)
	}
	got, _, err = s.GetItem(fxItem)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 2 {
		t.Fatalf("upsert did not update revision: %d", got.Revision)
	}

	if _, ok, _ := s.GetItem(fxItem2); ok {
		t.Fatal("unknown item returned")
	}

	if err := s.DeleteItem(fxItem); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetItem(fxItem); ok {
		t.Fatal("deleted item returned")
	}
	// The revision floor survives deletion: a stale row (revision 1
	// after revision 2 was seen) must be rejected — this is the
	// tombstone-rollback replay guard (design §6.2).
	if err := s.PutItem(fixtureItem(1)); err == nil {
		t.Fatal("stale item below revision floor accepted")
	}
	if err := s.PutItem(&wire.ItemData{VaultID: fxVault, ItemID: "bad", Revision: 1, WriterDeviceID: fxWriter}); err == nil {
		t.Fatal("invalid item accepted")
	}
}

func TestGrantRoundtripAndDelete(t *testing.T) {
	s, _ := openTemp(t)
	g := &wire.GrantData{
		DeviceID:   fxDevice,
		ItemID:     fxItem,
		Kind:       wire.GrantKindUse,
		HPKEEnc:    bytes.Repeat([]byte{0x0e}, 32),
		WrappedKey: bytes.Repeat([]byte{0x0f}, 48),
		ExpiresAt:  1790000000000,
		Revision:   1,
		Signature:  bytes.Repeat([]byte{0x0a}, 64),
	}
	if err := s.PutGrant(g); err != nil {
		t.Fatal(err)
	}
	grants, err := s.Grants()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("stored %d grants, want 1", len(grants))
	}
	got := grants[0]
	if got.Kind != g.Kind || got.DeviceID != g.DeviceID || got.ItemID != g.ItemID ||
		got.Revision != g.Revision || got.ExpiresAt != g.ExpiresAt ||
		!bytes.Equal(got.HPKEEnc, g.HPKEEnc) || !bytes.Equal(got.WrappedKey, g.WrappedKey) ||
		!bytes.Equal(got.Signature, g.Signature) {
		t.Fatalf("grant roundtrip mismatch: %+v", got)
	}

	g.Revision = 2
	if err := s.PutGrant(g); err != nil {
		t.Fatal(err)
	}
	grants, _ = s.Grants()
	if len(grants) != 1 || grants[0].Revision != 2 {
		t.Fatal("grant upsert failed")
	}

	if err := s.DeleteGrant(fxItem, wire.GrantKindUse); err != nil {
		t.Fatal(err)
	}
	grants, _ = s.Grants()
	if len(grants) != 0 {
		t.Fatal("deleted grant still present")
	}
	// The revision floor survives deletion: a stale live row (revision
	// 1 after revision 2 was seen) must be rejected — the anti-
	// resurrection replay guard (design §8.4).
	stale := *g
	stale.Revision = 1
	if err := s.PutGrant(&stale); err == nil {
		t.Fatal("stale grant below revision floor accepted")
	}

	// Item tombstone removes the item's grants too (design §6.3).
	if err := s.PutGrant(g); err != nil {
		t.Fatal(err)
	}
	if err := s.PutItem(fixtureItem(3)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteItem(fxItem); err != nil {
		t.Fatal(err)
	}
	if grants, _ = s.Grants(); len(grants) != 0 {
		t.Fatal("item deletion left grants behind")
	}
}

func TestKV(t *testing.T) {
	s, _ := openTemp(t)
	if _, ok, _ := s.GetKV("cursor"); ok {
		t.Fatal("unknown kv returned")
	}
	if err := s.SetKV("cursor", []byte("1051")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetKV("cursor", []byte("2000")); err != nil {
		t.Fatal(err)
	}
	v, ok, err := s.GetKV("cursor")
	if err != nil || !ok || string(v) != "2000" {
		t.Fatalf("kv roundtrip: %q %v %v", v, ok, err)
	}
}

// TestCacheHoldsNoPlaintext asserts the cache file contains exactly the
// ciphertext blobs it was handed and never a plaintext marker: the cache
// is end-to-end ciphertext by construction (design.md §6.5). The marker
// exists only in this test process, standing in for a decrypted value.
func TestCacheHoldsNoPlaintext(t *testing.T) {
	s, _ := openTemp(t)
	item := fixtureItem(1)
	item.SecretCiphertext = bytes.Repeat([]byte{0x5e}, 64) // fake ciphertext
	if err := s.PutItem(item); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(fxPlaintextMarker)) {
		t.Fatal("plaintext marker found in the raw cache file")
	}
	if !bytes.Contains(raw, item.SecretCiphertext) {
		t.Fatal("ciphertext not persisted")
	}
}
