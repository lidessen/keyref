package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	keycrypto "github.com/lidessen/keyref/proto/crypto"
)

func keyForTest() []byte { return bytes.Repeat([]byte{0x42}, 32) }
func pathForTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "vault.sqlite")
}

func TestLocalLifecycle(t *testing.T) {
	ctx := context.Background()
	path := pathForTest(t)
	key := keyForTest()
	if _, err := Open(path, key); !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("missing open: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("open created store: %v", err)
	}
	if _, err := Create(path, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing key touched path: %v", err)
	}
	s, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("store mode: %v %v", info, err)
	}
	if _, err := Create(path, key); !errors.Is(err, ErrStoreExists) {
		t.Fatalf("overwrite accepted: %v", err)
	}
	value := []byte("synthetic-plaintext-value-not-a-real-key")
	if _, err := s.Put(ctx, "synthetic-ref", value, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	var observed []byte
	if err := s.Use(ctx, "synthetic-ref", func(data []byte) error {
		if !bytes.Equal(data, value) {
			t.Errorf("wrong value")
		}
		observed = data
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(observed, make([]byte, len(value))) {
		t.Fatal("callback buffer was not cleared")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "synthetic-ref", value, PutOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed put: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{value, []byte("synthetic-ref"), key} {
		if bytes.Contains(raw, forbidden) {
			t.Fatal("plaintext in database")
		}
	}
	if _, err := Open(path, bytes.Repeat([]byte{0x43}, 32)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("wrong key: %v", err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Use(ctx, "synthetic-ref", func(data []byte) error {
		if !bytes.Equal(data, value) {
			t.Error("reopen lost value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "synthetic-ref"); err != nil {
		t.Fatal(err)
	}
	if err := s.Use(ctx, "synthetic-ref", func([]byte) error { t.Error("deleted value delivered"); return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted value: %v", err)
	}
	if err := s.Delete(ctx, "synthetic-ref"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted twice: %v", err)
	}
}

func TestLocalPrivatePath(t *testing.T) {
	key := keyForTest()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault")
	if _, err := Create("relative", key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("relative: %v", err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(path, key); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("public directory: %v", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, key); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("public file: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := Create(link, key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("overwrite symlink: %v", err)
	}
}

func TestLocalAADDetectsSubstitution(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Put(ctx, "first", []byte("value-one"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Put(ctx, "second", []byte("value-two"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	first, _ := s.entryID("first")
	second, _ := s.entryID("second")
	var blob []byte
	if err = s.db.QueryRow("SELECT blob FROM entries WHERE id = ?", first).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE entries SET blob = ? WHERE id = ?", blob, second); err != nil {
		t.Fatal(err)
	}
	if err = s.Use(ctx, "second", func([]byte) error { t.Error("substitution delivered plaintext"); return nil }); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("tamper: %v", err)
	}
}

func TestLocalConcurrentInstances(t *testing.T) {
	ctx := context.Background()
	path := pathForTest(t)
	key := keyForTest()
	a, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 != 0 {
				s = b
			}
			_, err := s.Put(ctx, fmt.Sprintf("ref-%d", i), []byte(fmt.Sprintf("value-%d", i)), PutOptions{})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent put: %v", err)
		}
	}
	for i := 0; i < 40; i++ {
		i := i
		if err := a.Use(ctx, fmt.Sprintf("ref-%d", i), func(b []byte) error {
			if string(b) != fmt.Sprintf("value-%d", i) {
				t.Errorf("wrong value %d", i)
			}
			return nil
		}); err != nil {
			t.Errorf("read %d: %v", i, err)
		}
	}
}

func TestLocalInputAndCancellation(t *testing.T) {
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	for _, ref := range []string{"", string([]byte{'x', 0, 'y'}), string(bytes.Repeat([]byte{'x'}, 513))} {
		if _, err = s.Put(ctx, ref, []byte("x"), PutOptions{}); err == nil {
			t.Error("accepted invalid ref")
		}
	}
	for _, v := range [][]byte{nil, bytes.Repeat([]byte{'x'}, maxValue+1)} {
		if _, err = s.Put(ctx, "valid", v, PutOptions{}); err == nil {
			t.Error("accepted invalid value")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.Put(cancelled, "cancelled", []byte("x"), PutOptions{}); err == nil {
		t.Error("cancelled write succeeded")
	}
	if _, err = s.Put(ctx, "existing", []byte("synthetic"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = s.Use(cancelled, "existing", func([]byte) error { t.Error("cancelled read delivered plaintext"); return nil }); err == nil {
		t.Error("cancelled read succeeded")
	}
	if err = s.Use(ctx, "cancelled", func([]byte) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancelled write persisted: %v", err)
	}
	if err = s.Use(ctx, "valid", nil); err == nil {
		t.Error("nil callback accepted")
	}
}

func TestLocalCallbackFailureAndPanicWipe(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(ctx, "ref", []byte("synthetic-value"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("callback failure")
	var data []byte
	if err := s.Use(ctx, "ref", func(b []byte) error { data = b; return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("callback failure: %v", err)
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("callback failure did not clear plaintext")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("callback panic was swallowed")
			}
		}()
		_ = s.Use(ctx, "ref", func(b []byte) error { data = b; panic("synthetic panic") })
	}()
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("panic did not clear plaintext")
	}
}

func TestLocalConcurrentSameRefRemainsWhole(t *testing.T) {
	ctx := context.Background()
	path := pathForTest(t)
	a, err := Create(path, keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path, keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	const writes = 32
	var wg sync.WaitGroup
	errs := make(chan error, writes)
	for i := 0; i < writes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 != 0 {
				s = b
			}
			_, err := s.Put(ctx, "same-ref", []byte(fmt.Sprintf("value-%02d", i)), PutOptions{})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("put: %v", err)
		}
	}
	if err := a.Use(ctx, "same-ref", func(value []byte) error {
		matched := false
		for i := 0; i < writes; i++ {
			if string(value) == fmt.Sprintf("value-%02d", i) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("concurrent value is not a complete write")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalCallbackMayCloseStore(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "ref", []byte("synthetic"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- s.Use(ctx, "ref", func(value []byte) error {
			if string(value) != "synthetic" {
				return errors.New("unexpected value")
			}
			return s.Close()
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("callback Close deadlocked")
	}
	if err := s.Use(ctx, "ref", func([]byte) error { t.Error("closed store delivered plaintext"); return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed read: %v", err)
	}
}

func TestLocalOversizedBlobRejected(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(ctx, "ref", []byte("synthetic"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	id, err := s.entryID("ref")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE entries SET blob=zeroblob(?) WHERE id=?", maxValue+29, id); err != nil {
		t.Fatal(err)
	}
	if err := s.Use(ctx, "ref", func([]byte) error { t.Error("oversized blob delivered plaintext"); return nil }); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("oversized blob: %v", err)
	}
}

func TestLocalWriteLimitPreservesExistingValue(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(ctx, "ref", []byte("original"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE metadata SET writes=4294967295"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "ref", []byte("replacement"), PutOptions{}); !errors.Is(err, ErrWriteLimit) {
		t.Fatalf("write at limit: %v", err)
	}
	if err := s.Use(ctx, "ref", func(value []byte) error {
		if string(value) != "original" {
			t.Error("rejected write modified value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := s.db.QueryRow("SELECT writes FROM metadata").Scan(&count); err != nil || count != 4294967295 {
		t.Fatalf("counter: %d, %v", count, err)
	}
}

// ReadStoreID returns the id the vault was created with, without the
// master key, and never creates a missing file (issue #2: the keyring
// entry is bound to this id).
func TestReadStoreID(t *testing.T) {
	path := pathForTest(t)
	if _, err := ReadStoreID(path); !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("missing vault: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("ReadStoreID created a file: %v", err)
	}
	s, err := Create(path, keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := ReadStoreID(path)
	if err != nil {
		t.Fatal(err)
	}
	if id != s.StoreID() || len(id) != 32 {
		t.Fatalf("store id %q vs %q", id, s.StoreID())
	}
}

func TestValidRefGrammar(t *testing.T) {
	for _, ref := range []string{"a", "ab", "tok", "openai-prod", "a1", "a-1", strings.Repeat("a", 64)} {
		if !ValidRef(ref) {
			t.Errorf("rejected valid ref %q", ref)
		}
	}
	for _, ref := range []string{"", "A", "1a", "a-", "-a", "a_b", "sms:abc", "a b", "a=b", "{a}", "a--", strings.Repeat("a", 65)} {
		if ValidRef(ref) {
			t.Errorf("accepted invalid ref %q", ref)
		}
	}
}

func TestPutReportsCreationAndRejectsInvalidRefs(t *testing.T) {
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	created, err := s.Put(ctx, "tok", []byte("first-value"), PutOptions{})
	if err != nil || !created {
		t.Fatalf("first put: created=%v err=%v", created, err)
	}
	created, err = s.Put(ctx, "tok", []byte("second-value"), PutOptions{})
	if err != nil || created {
		t.Fatalf("replacement put: created=%v err=%v", created, err)
	}
	if created, err := s.Put(ctx, "Not-A-Ref", []byte("value"), PutOptions{}); !errors.Is(err, ErrInvalidRef) || created {
		t.Fatalf("malformed ref: created=%v err=%v", created, err)
	}
	if err := s.Use(ctx, "tok", func(value []byte) error {
		if string(value) != "second-value" {
			t.Errorf("stored value %q", value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMask(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
		want  string
	}{
		{"empty", nil, "***"},
		{"no prefix, too short", []byte("abcdefg"), "***"},
		{"no prefix, exactly prefix+8", []byte("abcdefgh"), "****efgh"},
		{"no prefix, long", []byte("abcdefghij"), "****ghij"},
		{"sk- too short", []byte("sk-abc"), "***"},
		{"sk- at the boundary", []byte("sk-12345678"), "sk-****5678"},
		{"sk- one byte short", []byte("sk-1234567"), "***"},
		{"sk-proj- wins over sk-", []byte("sk-proj-12345678"), "sk-proj-****5678"},
		{"github token", []byte("ghp_abcdefghijkl"), "ghp_****ijkl"},
		{"aws access key", []byte("AKIAIOSFODNN7EXAMPLE"), "AKIA****MPLE"},
		{"binary", []byte{0x00, 0x01, 0x02, 0x03, 0xff, 0x10, 0x20, 0x30}, "***"},
		{"trailing newline", []byte("sk-abc1234567890wxyz\n"), "***"},
		{"space inside", []byte("two words here ok"), "***"},
		{"non-ASCII", []byte("pässwort-long-value"), "***"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Mask(tc.value); got != tc.want {
				t.Fatalf("Mask(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestLocalMetaRoundTripAndListOrder(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	value := []byte("sk-proj-abcdefghijklmnop")
	if _, err := s.Put(ctx, "zeta", value, PutOptions{
		Description:   "the last one",
		AllowCommands: []string{"curl", "cat"},
		AllowedHosts:  []string{"api.openai.com"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "alpha", []byte("plain-value"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "mid", []byte("another-value"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	m, err := s.Stat(ctx, "zeta")
	if err != nil {
		t.Fatal(err)
	}
	if m.V != 1 || m.Ref != "zeta" || m.Description != "the last one" {
		t.Fatalf("meta = %+v", m)
	}
	if m.Masked != Mask(value) || m.Masked != "sk-proj-****mnop" {
		t.Fatalf("masked = %q", m.Masked)
	}
	if m.Bytes != len(value) || m.UpdatedAt <= 0 {
		t.Fatalf("bytes=%d updated=%d", m.Bytes, m.UpdatedAt)
	}
	if len(m.Policy.AllowCommands) != 2 || m.Policy.AllowCommands[0] != "curl" || m.Policy.AllowCommands[1] != "cat" {
		t.Fatalf("allowCommands = %v", m.Policy.AllowCommands)
	}
	if len(m.Policy.AllowedHosts) != 1 || m.Policy.AllowedHosts[0] != "api.openai.com" {
		t.Fatalf("allowedHosts = %v", m.Policy.AllowedHosts)
	}
	metas, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 3 || metas[0].Ref != "alpha" || metas[1].Ref != "mid" || metas[2].Ref != "zeta" {
		t.Fatalf("list order = %+v", metas)
	}
	if _, err := s.Stat(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing ref: %v", err)
	}
	if _, err := s.Stat(ctx, "Not-A-Ref"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid ref: %v", err)
	}
}

// Put always writes a complete meta: a replacement without options
// resets description and policy, so a caller that does not know the
// value cannot widen what the item may do.
func TestLocalPutReplacesMeta(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(ctx, "tok", []byte("first-value"), PutOptions{
		Description:   "first",
		AllowCommands: []string{"cat"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "tok", []byte("second-value-longer"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	m, err := s.Stat(ctx, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if m.Description != "" || len(m.Policy.AllowCommands) != 0 || len(m.Policy.AllowedHosts) != 0 {
		t.Fatalf("replacement kept options: %+v", m)
	}
	if m.Bytes != len("second-value-longer") || m.Masked != Mask([]byte("second-value-longer")) {
		t.Fatalf("replacement meta = %+v", m)
	}
}

// List and Stat must not touch the secret ciphertext: with the blob
// corrupted they still answer from the meta, while Use fails closed.
func TestLocalListAndStatDoNotDecryptSecret(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(ctx, "tok", []byte("sk-abcdefghijklmnop"), PutOptions{Description: "desc"}); err != nil {
		t.Fatal(err)
	}
	id, err := s.entryID("tok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE entries SET blob=zeroblob(32) WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	m, err := s.Stat(ctx, "tok")
	if err != nil {
		t.Fatalf("Stat decrypted the secret: %v", err)
	}
	if m.Masked != "sk-****mnop" || m.Bytes != len("sk-abcdefghijklmnop") {
		t.Fatalf("meta = %+v", m)
	}
	metas, err := s.List(ctx)
	if err != nil || len(metas) != 1 || metas[0].Ref != "tok" {
		t.Fatalf("List = %+v, %v", metas, err)
	}
	if err := s.Use(ctx, "tok", func([]byte) error { t.Error("corrupt blob delivered plaintext"); return nil }); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("Use on corrupt blob: %v", err)
	}
}

func TestLocalMetaBoundToRow(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(ctx, "first", []byte("value-one"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "second", []byte("value-two"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	first, _ := s.entryID("first")
	second, _ := s.entryID("second")
	var metaBlob []byte
	if err := s.db.QueryRow("SELECT meta FROM entries WHERE id=?", first).Scan(&metaBlob); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", metaBlob, second); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat(ctx, "second"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("substituted meta: %v", err)
	}
}

func TestLocalMetaRejectsMalformedPlaintext(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(ctx, "tok", []byte("abcdefghij"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	id, err := s.entryID("tok")
	if err != nil {
		t.Fatal(err)
	}
	aad, err := keycrypto.MetaAAD(s.StoreID(), id)
	if err != nil {
		t.Fatal(err)
	}
	for name, plain := range map[string][]byte{
		"empty command": []byte(`{"v":1,"ref":"tok","masked":"***","bytes":10,"policy":{"allowCommands":[""]}}`),
		"nul command":   []byte(`{"v":1,"ref":"tok","masked":"***","bytes":10,"policy":{"allowCommands":["curl\u0000"]}}`),
		"empty host":    []byte(`{"v":1,"ref":"tok","masked":"***","bytes":10,"policy":{"allowedHosts":[""]}}`),
		"nul host":      []byte(`{"v":1,"ref":"tok","masked":"***","bytes":10,"policy":{"allowedHosts":["api\u0000.example"]}}`),
		"unknown field": []byte(`{"v":1,"ref":"tok","description":"","masked":"***","bytes":10,"updated_at":0,"policy":{"allowCommands":[],"allowedHosts":[]},"future":true}`),
		"wrong version": []byte(`{"v":2,"ref":"tok","description":"","masked":"***","bytes":10,"updated_at":0,"policy":{"allowCommands":[],"allowedHosts":[]}}`),
		"ref mismatch":  []byte(`{"v":1,"ref":"other","description":"","masked":"***","bytes":10,"updated_at":0,"policy":{"allowCommands":[],"allowedHosts":[]}}`),
		"empty masked":  []byte(`{"v":1,"ref":"tok","description":"","masked":"","bytes":10,"updated_at":0,"policy":{"allowCommands":[],"allowedHosts":[]}}`),
		"trailing data": []byte(`{"v":1,"ref":"tok","description":"","masked":"***","bytes":10,"updated_at":0,"policy":{"allowCommands":[],"allowedHosts":[]}} {}`),
	} {
		sealed, err := keycrypto.SealBlob(s.metaKey, aad, plain)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", sealed, id); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Stat(ctx, "tok"); !errors.Is(err, ErrCorruptStore) {
			t.Errorf("%s: %v", name, err)
		}
		if err := s.Use(ctx, "tok", func([]byte) error { return nil }); err != nil {
			t.Errorf("%s: secret became unreadable: %v", name, err)
		}
	}
}

func TestLocalPutRejectsInvalidPolicy(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for name, opts := range map[string]PutOptions{
		"empty command": {AllowCommands: []string{""}},
		"nul command":   {AllowCommands: []string{"curl\x00"}},
		"empty host":    {AllowedHosts: []string{""}},
		"nul host":      {AllowedHosts: []string{"api\x00.example"}},
	} {
		if _, err := s.Put(ctx, "tok", []byte("value"), opts); !errors.Is(err, ErrInvalidStore) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := s.Use(ctx, "tok", func([]byte) error { t.Error("rejected put stored a value"); return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected put: %v", err)
	}
}

func TestLocalPutRejectsOversizedMeta(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(ctx, "big", []byte("value"), PutOptions{Description: strings.Repeat("x", maxMeta)}); !errors.Is(err, ErrMetaTooLarge) {
		t.Fatalf("oversized meta: %v", err)
	}
	if err := s.Use(ctx, "big", func([]byte) error { t.Error("rejected put stored a value"); return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected put: %v", err)
	}
}

func TestLocalMetaAndSecretCannotBeSwapped(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(ctx, "tok", []byte("synthetic-value"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	id, err := s.entryID("tok")
	if err != nil {
		t.Fatal(err)
	}
	var metaBlob, secretBlob []byte
	if err := s.db.QueryRow("SELECT meta, blob FROM entries WHERE id=?", id).Scan(&metaBlob, &secretBlob); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE entries SET meta=?, blob=? WHERE id=?", secretBlob, secretBlob, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat(ctx, "tok"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("secret ciphertext accepted as meta: %v", err)
	}
	if _, err := s.db.Exec("UPDATE entries SET meta=?, blob=? WHERE id=?", metaBlob, metaBlob, id); err != nil {
		t.Fatal(err)
	}
	if err := s.Use(ctx, "tok", func([]byte) error { t.Error("meta ciphertext delivered plaintext"); return nil }); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("meta ciphertext accepted as secret: %v", err)
	}
}

// Legacy reads expose incomplete metadata without decrypting or writing.
// An authorized Use backfills the mask and size for later List calls.
func TestLocalLegacyRowMigratesOnUse(t *testing.T) {
	ctx := context.Background()
	path := pathForTest(t)
	key := keyForTest()
	s, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "legacy", []byte("synthetic-value"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	// Rebuild the pre-meta shape: the column did not exist at all, and
	// Open must add it back as a nullable column.
	if _, err := s.db.Exec("ALTER TABLE entries DROP COLUMN meta"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := s.List(ctx)
	if err != nil || len(metas) != 0 {
		t.Fatalf("list before stat = %+v, %v", metas, err)
	}
	m, err := s.Stat(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if m.Ref != "legacy" || m.Masked != "***" || m.Bytes != 0 || !m.Incomplete || m.UpdatedAt != 0 || len(m.Policy.AllowCommands) != 0 {
		t.Fatalf("incomplete meta = %+v", m)
	}
	metas, err = s.List(ctx)
	if err != nil || len(metas) != 0 {
		t.Fatalf("Stat must not persist invented metadata: %+v, %v", metas, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Use(ctx, "legacy", func(value []byte) error {
		if string(value) != "synthetic-value" {
			t.Error("migration changed the stored value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	metas, err = s.List(ctx)
	if err != nil || len(metas) != 1 || metas[0].Ref != "legacy" || metas[0].Incomplete || metas[0].Bytes != len("synthetic-value") || metas[0].Masked != Mask([]byte("synthetic-value")) || metas[0].UpdatedAt != 0 {
		t.Fatalf("migrated metadata = %+v, %v", metas, err)
	}
}
