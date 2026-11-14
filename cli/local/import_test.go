package local

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	keycrypto "github.com/lidessen/keyref/proto/crypto"
)

// importValue generates a synthetic secret at runtime. Tests must never
// print it, its mask, its ciphertext or its hash on failure.
func importValue(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal("random source failed")
	}
	return b
}

func importStore(t *testing.T) *Store {
	t.Helper()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal("create store failed")
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// importSnapshot returns copies of one row's ciphertexts; meta is nil for
// a legacy row whose meta column is NULL.
func importSnapshot(t *testing.T, s *Store, ref string) (blob, meta []byte, metaNull bool) {
	t.Helper()
	id, err := s.entryID(ref)
	if err != nil {
		t.Fatal("ref id failed")
	}
	var rowBlob, rowMeta []byte
	if err := s.db.QueryRow("SELECT blob,meta,meta IS NULL FROM entries WHERE id=?", id).Scan(&rowBlob, &rowMeta, &metaNull); err != nil {
		t.Fatal("row snapshot failed")
	}
	blob = append([]byte(nil), rowBlob...)
	if rowMeta != nil {
		meta = append([]byte(nil), rowMeta...)
	}
	return blob, meta, metaNull
}

func importWrites(t *testing.T, s *Store) int64 {
	t.Helper()
	var writes int64
	if err := s.db.QueryRow("SELECT writes FROM metadata").Scan(&writes); err != nil {
		t.Fatal("write counter snapshot failed")
	}
	return writes
}

func requireImportValue(t *testing.T, s *Store, ref string, want []byte, what string) {
	t.Helper()
	err := s.Use(context.Background(), ref, func(got []byte) error {
		if !bytes.Equal(got, want) {
			t.Fatalf("%s value mismatch", what)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%s read failed: %v", what, err)
	}
}

func requireImportMissing(t *testing.T, s *Store, ref, what string) {
	t.Helper()
	err := s.Use(context.Background(), ref, func([]byte) error {
		t.Fatalf("%s unexpectedly exists", what)
		return nil
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("%s missing check: %v", what, err)
	}
}

func TestImportMixedStatusesAndPreservedPolicy(t *testing.T) {
	ctx := context.Background()
	s := importStore(t)
	freshValue := importValue(t, 21)
	oldValue := importValue(t, 18)
	replacementValue := importValue(t, 30)
	keepValue := importValue(t, 24)

	if _, err := s.Put(ctx, "keep", keepValue, PutOptions{
		Description:   "keep description",
		AllowCommands: []string{"cat"},
		AllowedHosts:  []string{"keep.example"},
	}); err != nil {
		t.Fatal("seed keep failed")
	}
	if _, err := s.Put(ctx, "replace", oldValue, PutOptions{
		Description:   "replace description",
		AllowCommands: []string{"curl", "git"},
		AllowedHosts:  []string{"api.example"},
	}); err != nil {
		t.Fatal("seed replace failed")
	}
	// Make the old update time clearly stale so the replacement has to
	// move it.
	replaceID, err := s.entryID("replace")
	if err != nil {
		t.Fatal("ref id failed")
	}
	var staleBlob []byte
	if err := s.db.QueryRow("SELECT meta FROM entries WHERE id=?", replaceID).Scan(&staleBlob); err != nil {
		t.Fatal("seed meta read failed")
	}
	stale, err := s.openMeta(replaceID, staleBlob)
	if err != nil {
		t.Fatal("seed meta open failed")
	}
	stale.UpdatedAt = 7
	sealed, err := s.sealMeta(replaceID, stale)
	if err != nil {
		t.Fatal("seed meta seal failed")
	}
	if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", sealed, replaceID); err != nil {
		t.Fatal("seed meta write failed")
	}

	keepBefore, err := s.Stat(ctx, "keep")
	if err != nil {
		t.Fatal("keep stat failed")
	}
	keepBlobBefore, keepMetaBefore, _ := importSnapshot(t, s, "keep")
	callerFresh := append([]byte(nil), freshValue...)
	callerReplace := append([]byte(nil), replacementValue...)
	callerKeep := append([]byte(nil), keepValue...)

	statuses, err := s.Import(ctx, []ImportItem{
		{Ref: "fresh", Value: freshValue},
		{Ref: "replace", Value: replacementValue},
		{Ref: "keep", Value: keepValue},
	})
	if err != nil {
		t.Fatal("import failed")
	}
	if len(statuses) != 3 {
		t.Fatalf("status count = %d, want 3", len(statuses))
	}
	want := []ImportStatus{ImportCreated, ImportReplaced, ImportUnchanged}
	for i := range want {
		if statuses[i] != want[i] {
			t.Fatalf("status %d = %q, want %q", i, statuses[i], want[i])
		}
	}

	// Import must not mutate or wipe caller-owned input.
	if !bytes.Equal(freshValue, callerFresh) || !bytes.Equal(replacementValue, callerReplace) || !bytes.Equal(keepValue, callerKeep) {
		t.Fatal("import modified a caller-owned value")
	}

	requireImportValue(t, s, "fresh", freshValue, "fresh")
	requireImportValue(t, s, "replace", replacementValue, "replaced")
	requireImportValue(t, s, "keep", keepValue, "unchanged")

	freshMeta, err := s.Stat(ctx, "fresh")
	if err != nil {
		t.Fatal("fresh stat failed")
	}
	if freshMeta.Ref != "fresh" || freshMeta.V != 1 || freshMeta.Description != "" ||
		len(freshMeta.Policy.AllowCommands) != 0 || len(freshMeta.Policy.AllowedHosts) != 0 {
		t.Fatal("new item did not use the default identity and policy")
	}
	if freshMeta.Masked != Mask(freshValue) || freshMeta.Bytes != len(freshValue) ||
		freshMeta.UpdatedAt <= 0 || freshMeta.Incomplete {
		t.Fatal("new item meta was not computed from the value")
	}

	replaceMeta, err := s.Stat(ctx, "replace")
	if err != nil {
		t.Fatal("replace stat failed")
	}
	if replaceMeta.Description != "replace description" ||
		len(replaceMeta.Policy.AllowCommands) != 2 || replaceMeta.Policy.AllowCommands[0] != "curl" || replaceMeta.Policy.AllowCommands[1] != "git" ||
		len(replaceMeta.Policy.AllowedHosts) != 1 || replaceMeta.Policy.AllowedHosts[0] != "api.example" {
		t.Fatal("replacement lost the existing description or policy")
	}
	if replaceMeta.Masked != Mask(replacementValue) || replaceMeta.Bytes != len(replacementValue) ||
		replaceMeta.UpdatedAt <= 7 || replaceMeta.Incomplete {
		t.Fatal("replacement did not refresh mask, size and time")
	}

	keepMeta, err := s.Stat(ctx, "keep")
	if err != nil {
		t.Fatal("keep stat failed")
	}
	if keepMeta.UpdatedAt != keepBefore.UpdatedAt || keepMeta.Description != keepBefore.Description ||
		keepMeta.Masked != keepBefore.Masked || keepMeta.Bytes != keepBefore.Bytes {
		t.Fatal("unchanged row meta changed")
	}
	keepBlobAfter, keepMetaAfter, _ := importSnapshot(t, s, "keep")
	if !bytes.Equal(keepBlobBefore, keepBlobAfter) || !bytes.Equal(keepMetaBefore, keepMetaAfter) {
		t.Fatal("unchanged row ciphertext changed")
	}

	metas, err := s.List(ctx)
	if err != nil || len(metas) != 3 {
		t.Fatalf("list size = %d, want 3", len(metas))
	}
}

func TestImportUnchangedDoesNotRewriteRowOrCounter(t *testing.T) {
	ctx := context.Background()
	s := importStore(t)
	value := importValue(t, 26)
	if _, err := s.Put(ctx, "stable", value, PutOptions{
		Description:   "stable description",
		AllowCommands: []string{"git"},
	}); err != nil {
		t.Fatal("seed failed")
	}
	blobBefore, metaBefore, _ := importSnapshot(t, s, "stable")
	writesBefore := importWrites(t, s)

	statuses, err := s.Import(ctx, []ImportItem{{Ref: "stable", Value: value}})
	if err != nil || len(statuses) != 1 || statuses[0] != ImportUnchanged {
		t.Fatal("rerun of the same value was not unchanged")
	}
	blobAfter, metaAfter, _ := importSnapshot(t, s, "stable")
	if !bytes.Equal(blobBefore, blobAfter) || !bytes.Equal(metaBefore, metaAfter) {
		t.Fatal("unchanged rerun rewrote ciphertext")
	}
	if writes := importWrites(t, s); writes != writesBefore {
		t.Fatalf("unchanged rerun moved the write counter from %d to %d", writesBefore, writes)
	}

	// The unchanged path must also work at the 32-bit write cap, where
	// even a no-op counter update would overflow the budget.
	if _, err := s.db.Exec("UPDATE metadata SET writes=4294967295"); err != nil {
		t.Fatal("cap setup failed")
	}
	statuses, err = s.Import(ctx, []ImportItem{{Ref: "stable", Value: value}})
	if err != nil || len(statuses) != 1 || statuses[0] != ImportUnchanged {
		t.Fatal("unchanged import failed at the write cap")
	}
	blobCap, metaCap, _ := importSnapshot(t, s, "stable")
	if !bytes.Equal(blobBefore, blobCap) || !bytes.Equal(metaBefore, metaCap) {
		t.Fatal("unchanged import at the cap rewrote ciphertext")
	}
	if writes := importWrites(t, s); writes != 4294967295 {
		t.Fatalf("write counter at cap = %d, want 4294967295", writes)
	}
}

func TestImportWriteBudgetRollsBackBatch(t *testing.T) {
	ctx := context.Background()
	s := importStore(t)
	aOld, aNew := importValue(t, 19), importValue(t, 20)
	bOld, bNew := importValue(t, 21), importValue(t, 22)
	if _, err := s.Put(ctx, "a", aOld, PutOptions{}); err != nil {
		t.Fatal("seed a failed")
	}
	if _, err := s.Put(ctx, "b", bOld, PutOptions{}); err != nil {
		t.Fatal("seed b failed")
	}
	aBlob, aMeta, _ := importSnapshot(t, s, "a")
	bBlob, bMeta, _ := importSnapshot(t, s, "b")

	// Only one write of budget remains, but the batch needs two.
	if _, err := s.db.Exec("UPDATE metadata SET writes=4294967294"); err != nil {
		t.Fatal("budget setup failed")
	}
	statuses, err := s.Import(ctx, []ImportItem{{Ref: "a", Value: aNew}, {Ref: "b", Value: bNew}})
	if !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("over-budget import error = %v", err)
	}
	if statuses != nil {
		t.Fatal("over-budget import returned statuses")
	}
	requireImportValue(t, s, "a", aOld, "a after budget failure")
	requireImportValue(t, s, "b", bOld, "b after budget failure")
	aBlobAfter, aMetaAfter, _ := importSnapshot(t, s, "a")
	bBlobAfter, bMetaAfter, _ := importSnapshot(t, s, "b")
	if !bytes.Equal(aBlob, aBlobAfter) || !bytes.Equal(aMeta, aMetaAfter) ||
		!bytes.Equal(bBlob, bBlobAfter) || !bytes.Equal(bMeta, bMetaAfter) {
		t.Fatal("over-budget import changed a row")
	}
	if writes := importWrites(t, s); writes != 4294967294 {
		t.Fatalf("counter after budget failure = %d, want 4294967294", writes)
	}

	// Exactly enough budget succeeds and reaches the cap.
	if _, err := s.db.Exec("UPDATE metadata SET writes=4294967293"); err != nil {
		t.Fatal("budget setup failed")
	}
	statuses, err = s.Import(ctx, []ImportItem{{Ref: "a", Value: aNew}, {Ref: "b", Value: bNew}})
	if err != nil || len(statuses) != 2 || statuses[0] != ImportReplaced || statuses[1] != ImportReplaced {
		t.Fatal("import with exact budget failed")
	}
	requireImportValue(t, s, "a", aNew, "a after exact budget")
	requireImportValue(t, s, "b", bNew, "b after exact budget")
	if writes := importWrites(t, s); writes != 4294967295 {
		t.Fatalf("counter after exact budget = %d, want 4294967295", writes)
	}

	// A later change must fail without touching the committed rows.
	statuses, err = s.Import(ctx, []ImportItem{{Ref: "a", Value: aOld}})
	if !errors.Is(err, ErrInvalidStore) || statuses != nil {
		t.Fatal("change at the write cap was not rejected")
	}
	requireImportValue(t, s, "a", aNew, "a after cap rejection")
	if writes := importWrites(t, s); writes != 4294967295 {
		t.Fatalf("counter after cap rejection = %d, want 4294967295", writes)
	}

	// Unchanged items still succeed at the cap.
	statuses, err = s.Import(ctx, []ImportItem{{Ref: "a", Value: aNew}, {Ref: "b", Value: bNew}})
	if err != nil || len(statuses) != 2 || statuses[0] != ImportUnchanged || statuses[1] != ImportUnchanged {
		t.Fatal("unchanged import at the cap failed")
	}
}

// A replacement that would grow the preserved meta past its bound fails
// after another row in the same batch was already written; the whole
// batch must roll back.
func TestImportMetaBoundFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	s := importStore(t)
	firstOld, firstNew := importValue(t, 17), importValue(t, 28)
	limitOld := importValue(t, 15)
	if _, err := s.Put(ctx, "first", firstOld, PutOptions{}); err != nil {
		t.Fatal("seed first failed")
	}
	if _, err := s.Put(ctx, "limit", limitOld, PutOptions{}); err != nil {
		t.Fatal("seed limit failed")
	}
	limitID, err := s.entryID("limit")
	if err != nil {
		t.Fatal("ref id failed")
	}
	// Find the largest description whose sealed meta still fits, then
	// persist it. A new value with a longer mask and size no longer
	// fits, so sealing the replacement meta fails inside the batch.
	base := Meta{V: 1, Ref: "limit", Masked: "***",
		Policy: Policy{AllowCommands: []string{}, AllowedHosts: []string{}}}
	var largest []byte
	lo, hi := 0, maxMeta
	for lo <= hi {
		mid := (lo + hi) / 2
		candidate := base
		candidate.Description = strings.Repeat("d", mid)
		sealed, err := s.sealMeta(limitID, &candidate)
		if err != nil {
			t.Fatal("candidate seal failed")
		}
		if len(sealed) <= maxMeta {
			largest = sealed
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if largest == nil {
		t.Fatal("no fitting meta candidate")
	}
	if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", largest, limitID); err != nil {
		t.Fatal("crafted meta write failed")
	}
	longValue := append([]byte("sk-proj-"), []byte(hex.EncodeToString(importValue(t, 8)))...)

	firstBlob, firstMeta, _ := importSnapshot(t, s, "first")
	limitBlob, limitMeta, _ := importSnapshot(t, s, "limit")
	writes := importWrites(t, s)
	statuses, err := s.Import(ctx, []ImportItem{{Ref: "first", Value: firstNew}, {Ref: "limit", Value: longValue}})
	if !errors.Is(err, ErrMetaTooLarge) {
		t.Fatalf("oversized replacement error = %v", err)
	}
	if statuses != nil {
		t.Fatal("failed import returned statuses")
	}
	requireImportValue(t, s, "first", firstOld, "first after meta bound failure")
	firstBlobAfter, firstMetaAfter, _ := importSnapshot(t, s, "first")
	limitBlobAfter, limitMetaAfter, _ := importSnapshot(t, s, "limit")
	if !bytes.Equal(firstBlob, firstBlobAfter) || !bytes.Equal(firstMeta, firstMetaAfter) ||
		!bytes.Equal(limitBlob, limitBlobAfter) || !bytes.Equal(limitMeta, limitMetaAfter) {
		t.Fatal("meta bound failure left a partial write")
	}
	if got := importWrites(t, s); got != writes {
		t.Fatalf("counter after meta bound failure = %d, want %d", got, writes)
	}
}

func TestImportCorruptionFailsClosedWholeBatch(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		corrupt func(t *testing.T, s *Store, badID string)
	}{
		{"secret ciphertext", func(t *testing.T, s *Store, badID string) {
			if _, err := s.db.Exec("UPDATE entries SET blob=? WHERE id=?", importValue(t, 32), badID); err != nil {
				t.Fatal("corrupt secret failed")
			}
		}},
		{"authenticated empty secret", func(t *testing.T, s *Store, badID string) {
			aad, err := keycrypto.SecretAAD(s.id, badID)
			if err != nil {
				t.Fatal("empty secret AAD failed")
			}
			blob, err := keycrypto.SealBlob(s.key, aad, nil)
			if err != nil {
				t.Fatal("empty secret seal failed")
			}
			if _, err := s.db.Exec("UPDATE entries SET blob=? WHERE id=?", blob, badID); err != nil {
				t.Fatal("empty secret write failed")
			}
		}},
		{"meta ciphertext", func(t *testing.T, s *Store, badID string) {
			if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", importValue(t, 32), badID); err != nil {
				t.Fatal("corrupt meta failed")
			}
		}},
		{"empty meta blob", func(t *testing.T, s *Store, badID string) {
			if _, err := s.db.Exec("UPDATE entries SET meta=zeroblob(0) WHERE id=?", badID); err != nil {
				t.Fatal("empty meta write failed")
			}
		}},
		{"oversized secret", func(t *testing.T, s *Store, badID string) {
			if _, err := s.db.Exec("UPDATE entries SET blob=zeroblob(?) WHERE id=?", maxValue+29, badID); err != nil {
				t.Fatal("corrupt oversized secret failed")
			}
		}},
		{"foreign meta", func(t *testing.T, s *Store, badID string) {
			otherID, err := s.entryID("other")
			if err != nil {
				t.Fatal("ref id failed")
			}
			var otherMeta []byte
			if err := s.db.QueryRow("SELECT meta FROM entries WHERE id=?", otherID).Scan(&otherMeta); err != nil {
				t.Fatal("other meta read failed")
			}
			if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", otherMeta, badID); err != nil {
				t.Fatal("foreign meta write failed")
			}
		}},
		{"ref mismatch meta", func(t *testing.T, s *Store, badID string) {
			m := &Meta{V: 1, Ref: "other", Masked: "***", Bytes: 1, UpdatedAt: 1,
				Policy: Policy{AllowCommands: []string{}, AllowedHosts: []string{}}}
			sealed, err := s.sealMeta(badID, m)
			if err != nil {
				t.Fatal("mismatched meta seal failed")
			}
			if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", sealed, badID); err != nil {
				t.Fatal("mismatched meta write failed")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := importStore(t)
			goodOld, goodNew := importValue(t, 18), importValue(t, 19)
			badOld, badNew := importValue(t, 20), importValue(t, 21)
			if _, err := s.Put(ctx, "good", goodOld, PutOptions{}); err != nil {
				t.Fatal("seed good failed")
			}
			if _, err := s.Put(ctx, "bad", badOld, PutOptions{}); err != nil {
				t.Fatal("seed bad failed")
			}
			if _, err := s.Put(ctx, "other", importValue(t, 22), PutOptions{}); err != nil {
				t.Fatal("seed other failed")
			}
			badID, err := s.entryID("bad")
			if err != nil {
				t.Fatal("ref id failed")
			}
			tc.corrupt(t, s, badID)

			goodBlob, goodMeta, _ := importSnapshot(t, s, "good")
			badBlob, badMeta, _ := importSnapshot(t, s, "bad")
			writes := importWrites(t, s)
			statuses, err := s.Import(ctx, []ImportItem{{Ref: "good", Value: goodNew}, {Ref: "bad", Value: badNew}})
			if !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("corrupt import error = %v", err)
			}
			if err.Error() != ErrInvalidStore.Error() {
				t.Fatal("corrupt import error text is not the fixed sentinel")
			}
			if statuses != nil {
				t.Fatal("corrupt import returned statuses")
			}
			requireImportValue(t, s, "good", goodOld, "good after corruption")
			goodBlobAfter, goodMetaAfter, _ := importSnapshot(t, s, "good")
			badBlobAfter, badMetaAfter, _ := importSnapshot(t, s, "bad")
			if !bytes.Equal(goodBlob, goodBlobAfter) || !bytes.Equal(goodMeta, goodMetaAfter) {
				t.Fatal("corrupt batch changed a valid row")
			}
			if !bytes.Equal(badBlob, badBlobAfter) || !bytes.Equal(badMeta, badMetaAfter) {
				t.Fatal("corrupt batch changed the corrupt row")
			}
			if got := importWrites(t, s); got != writes {
				t.Fatalf("counter after corrupt batch = %d, want %d", got, writes)
			}
		})
	}
}

// Corrupt meta fails closed even when the requested value is unchanged
// and no write would be needed.
func TestImportCorruptMetaFailsEvenWhenUnchanged(t *testing.T) {
	ctx := context.Background()
	s := importStore(t)
	value := importValue(t, 18)
	if _, err := s.Put(ctx, "bad", value, PutOptions{}); err != nil {
		t.Fatal("seed failed")
	}
	id, err := s.entryID("bad")
	if err != nil {
		t.Fatal("ref id failed")
	}
	if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", importValue(t, 32), id); err != nil {
		t.Fatal("corrupt meta failed")
	}
	blobBefore, metaBefore, _ := importSnapshot(t, s, "bad")
	writes := importWrites(t, s)
	statuses, err := s.Import(ctx, []ImportItem{{Ref: "bad", Value: value}})
	if !errors.Is(err, ErrInvalidStore) || statuses != nil {
		t.Fatal("unchanged corrupt row did not fail closed")
	}
	blobAfter, metaAfter, _ := importSnapshot(t, s, "bad")
	if !bytes.Equal(blobBefore, blobAfter) || !bytes.Equal(metaBefore, metaAfter) {
		t.Fatal("failed import changed the corrupt row")
	}
	if got := importWrites(t, s); got != writes {
		t.Fatalf("counter after failed import = %d, want %d", got, writes)
	}
}

func TestImportValidationRejectsWholeBatch(t *testing.T) {
	ctx := context.Background()
	s := importStore(t)
	value := importValue(t, 16)
	tooMany := make([]ImportItem, maxImportItems+1)
	for i := range tooMany {
		tooMany[i] = ImportItem{Ref: fmt.Sprintf("item%d", i), Value: value}
	}
	cases := []struct {
		name  string
		items []ImportItem
		want  error
	}{
		{"duplicate ref", []ImportItem{{Ref: "dup", Value: value}, {Ref: "dup", Value: importValue(t, 16)}}, ErrInvalidStore},
		{"invalid ref", []ImportItem{{Ref: "pending", Value: value}, {Ref: "Not-Legal", Value: value}}, ErrInvalidRef},
		{"empty value", []ImportItem{{Ref: "empty", Value: nil}}, ErrInvalidStore},
		{"oversized value", []ImportItem{{Ref: "oversized", Value: make([]byte, maxValue+1)}}, ErrInvalidStore},
		{"too many items", tooMany, ErrInvalidStore},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			statuses, err := s.Import(ctx, tc.items)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if statuses != nil {
				t.Fatal("rejected import returned statuses")
			}
			metas, err := s.List(ctx)
			if err != nil || len(metas) != 0 {
				t.Fatal("rejected batch wrote a row")
			}
		})
	}
	statuses, err := s.Import(ctx, nil)
	if err != nil || len(statuses) != 0 {
		t.Fatal("empty import was not a valid no-op")
	}
}

func newLegacyImportStore(t *testing.T, value []byte) *Store {
	t.Helper()
	s := importStore(t)
	ctx := context.Background()
	if _, err := s.Put(ctx, "legacy", value, PutOptions{}); err != nil {
		t.Fatal("legacy seed failed")
	}
	if _, err := s.db.Exec("ALTER TABLE entries DROP COLUMN meta"); err != nil {
		t.Fatal("legacy schema setup failed")
	}
	if err := ensureMetaColumn(s.db); err != nil {
		t.Fatal("legacy schema migration failed")
	}
	return s
}

func TestImportLegacyRows(t *testing.T) {
	ctx := context.Background()

	t.Run("missing meta unchanged", func(t *testing.T) {
		old := importValue(t, 22)
		s := newLegacyImportStore(t, old)
		blobBefore, metaBefore, metaNull := importSnapshot(t, s, "legacy")
		if !metaNull {
			t.Fatal("legacy row unexpectedly has meta")
		}
		writes := importWrites(t, s)
		statuses, err := s.Import(ctx, []ImportItem{{Ref: "legacy", Value: old}})
		if err != nil || len(statuses) != 1 || statuses[0] != ImportUnchanged {
			t.Fatal("unchanged legacy row was not unchanged")
		}
		blobAfter, metaAfter, stillNull := importSnapshot(t, s, "legacy")
		if !stillNull || !bytes.Equal(blobBefore, blobAfter) || !bytes.Equal(metaBefore, metaAfter) {
			t.Fatal("unchanged legacy row was rewritten")
		}
		if got := importWrites(t, s); got != writes {
			t.Fatalf("counter after unchanged legacy import = %d, want %d", got, writes)
		}
	})

	t.Run("missing meta replaced", func(t *testing.T) {
		old := importValue(t, 22)
		replacement := importValue(t, 23)
		s := newLegacyImportStore(t, old)
		statuses, err := s.Import(ctx, []ImportItem{{Ref: "legacy", Value: replacement}})
		if err != nil || len(statuses) != 1 || statuses[0] != ImportReplaced {
			t.Fatal("replaced legacy row did not report replaced")
		}
		requireImportValue(t, s, "legacy", replacement, "replaced legacy")
		m, err := s.Stat(ctx, "legacy")
		if err != nil {
			t.Fatal("legacy stat failed")
		}
		if m.Description != "" || len(m.Policy.AllowCommands) != 0 || len(m.Policy.AllowedHosts) != 0 {
			t.Fatal("replaced legacy row did not get the default policy")
		}
		if m.Masked != Mask(replacement) || m.Bytes != len(replacement) || m.UpdatedAt <= 0 || m.Incomplete {
			t.Fatal("replaced legacy row meta was not completed")
		}
	})

	t.Run("unchanged at write cap", func(t *testing.T) {
		old := importValue(t, 22)
		s := newLegacyImportStore(t, old)
		if _, err := s.db.Exec("UPDATE metadata SET writes=4294967295"); err != nil {
			t.Fatal("cap setup failed")
		}
		blobBefore, metaBefore, _ := importSnapshot(t, s, "legacy")
		statuses, err := s.Import(ctx, []ImportItem{{Ref: "legacy", Value: old}})
		if err != nil || len(statuses) != 1 || statuses[0] != ImportUnchanged {
			t.Fatal("unchanged legacy import failed at the write cap")
		}
		blobAfter, metaAfter, metaNull := importSnapshot(t, s, "legacy")
		if !metaNull || !bytes.Equal(blobBefore, blobAfter) || !bytes.Equal(metaBefore, metaAfter) {
			t.Fatal("unchanged legacy import at the cap rewrote the row")
		}
		if got := importWrites(t, s); got != 4294967295 {
			t.Fatalf("counter at cap = %d, want 4294967295", got)
		}
	})

	seedIncomplete := func(t *testing.T, s *Store) {
		t.Helper()
		id, err := s.entryID("legacy")
		if err != nil {
			t.Fatal("ref id failed")
		}
		m := &Meta{V: 1, Ref: "legacy", Description: "legacy description", Masked: "***", UpdatedAt: 5,
			Policy: Policy{AllowCommands: []string{"curl"}, AllowedHosts: []string{"legacy.example"}}}
		sealed, err := s.sealMeta(id, m)
		if err != nil {
			t.Fatal("incomplete meta seal failed")
		}
		if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", sealed, id); err != nil {
			t.Fatal("incomplete meta write failed")
		}
	}

	t.Run("incomplete meta unchanged", func(t *testing.T) {
		old := importValue(t, 22)
		s := newLegacyImportStore(t, old)
		seedIncomplete(t, s)
		blobBefore, metaBefore, _ := importSnapshot(t, s, "legacy")
		writes := importWrites(t, s)
		statuses, err := s.Import(ctx, []ImportItem{{Ref: "legacy", Value: old}})
		if err != nil || len(statuses) != 1 || statuses[0] != ImportUnchanged {
			t.Fatal("unchanged incomplete row was not unchanged")
		}
		blobAfter, metaAfter, _ := importSnapshot(t, s, "legacy")
		if !bytes.Equal(blobBefore, blobAfter) || !bytes.Equal(metaBefore, metaAfter) {
			t.Fatal("unchanged incomplete row was rewritten")
		}
		if got := importWrites(t, s); got != writes {
			t.Fatalf("counter after unchanged incomplete import = %d, want %d", got, writes)
		}
	})

	t.Run("incomplete meta replaced", func(t *testing.T) {
		old := importValue(t, 22)
		replacement := importValue(t, 23)
		s := newLegacyImportStore(t, old)
		seedIncomplete(t, s)
		statuses, err := s.Import(ctx, []ImportItem{{Ref: "legacy", Value: replacement}})
		if err != nil || len(statuses) != 1 || statuses[0] != ImportReplaced {
			t.Fatal("replaced incomplete row did not report replaced")
		}
		requireImportValue(t, s, "legacy", replacement, "replaced incomplete")
		m, err := s.Stat(ctx, "legacy")
		if err != nil {
			t.Fatal("incomplete stat failed")
		}
		if m.Description != "legacy description" ||
			len(m.Policy.AllowCommands) != 1 || m.Policy.AllowCommands[0] != "curl" ||
			len(m.Policy.AllowedHosts) != 1 || m.Policy.AllowedHosts[0] != "legacy.example" {
			t.Fatal("replaced incomplete row lost its description or policy")
		}
		if m.Masked != Mask(replacement) || m.Bytes != len(replacement) || m.UpdatedAt <= 0 || m.Incomplete {
			t.Fatal("replaced incomplete row meta was not completed")
		}
	})
}

func TestImportContextCancellationAndClosedStore(t *testing.T) {
	ctx := context.Background()
	s := importStore(t)
	old := importValue(t, 19)
	replacement := importValue(t, 20)
	if _, err := s.Put(ctx, "existing", old, PutOptions{}); err != nil {
		t.Fatal("seed failed")
	}
	blobBefore, metaBefore, _ := importSnapshot(t, s, "existing")
	writes := importWrites(t, s)

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	statuses, err := s.Import(cancelled, []ImportItem{
		{Ref: "existing", Value: replacement},
		{Ref: "new", Value: replacement},
	})
	if !errors.Is(err, context.Canceled) || statuses != nil {
		t.Fatal("cancelled import did not fail cleanly")
	}
	requireImportValue(t, s, "existing", old, "existing after cancellation")
	requireImportMissing(t, s, "new", "new after cancellation")
	blobAfter, metaAfter, _ := importSnapshot(t, s, "existing")
	if !bytes.Equal(blobBefore, blobAfter) || !bytes.Equal(metaBefore, metaAfter) {
		t.Fatal("cancelled import changed a row")
	}
	if got := importWrites(t, s); got != writes {
		t.Fatalf("counter after cancelled import = %d, want %d", got, writes)
	}

	if err := s.Close(); err != nil {
		t.Fatal("close failed")
	}
	if _, err := s.Import(ctx, []ImportItem{{Ref: "closed", Value: old}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed store import error = %v", err)
	}
}

func TestImportCancelledWhileWaitingForWriteLock(t *testing.T) {
	ctx := context.Background()
	path := pathForTest(t)
	master := importValue(t, 32)
	defer clear(master)
	writer, err := Create(path, master)
	if err != nil {
		t.Fatal("create store failed")
	}
	defer writer.Close()
	contender, err := Open(path, master)
	if err != nil {
		t.Fatal("open store failed")
	}
	defer contender.Close()

	conn, err := writer.db.Conn(ctx)
	if err != nil {
		t.Fatal("could not obtain writer connection")
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal("could not hold writer lock")
	}
	defer conn.ExecContext(ctx, "ROLLBACK")

	value := importValue(t, 24)
	defer clear(value)
	cancelled, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	statuses, err := contender.Import(cancelled, []ImportItem{{Ref: "entry", Value: value}})
	if !errors.Is(err, context.DeadlineExceeded) || statuses != nil {
		t.Fatal("contended import did not stop at its deadline")
	}
	if contender.db.Stats().OpenConnections != 0 {
		t.Fatal("cancelled import did not discard its connection")
	}

	// The cancelled BEGIN discards its connection. The replacement must
	// still wait for the existing writer instead of failing immediately.
	var busyTimeout int
	if err := contender.db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatal("could not inspect replacement connection")
	}
	type result struct {
		statuses []ImportStatus
		err      error
	}
	retryCtx, cancelRetry := context.WithTimeout(ctx, 2*time.Second)
	defer cancelRetry()
	started := make(chan struct{})
	finished := make(chan result, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		statuses, err := contender.Import(retryCtx, []ImportItem{{Ref: "entry", Value: value}})
		finished <- result{statuses: statuses, err: err}
	}()
	defer func() {
		cancelRetry()
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		<-done
	}()
	<-started
	select {
	case <-finished:
		t.Fatalf("import returned before the writer released its lock (busy_timeout=%d)", busyTimeout)
	case <-time.After(150 * time.Millisecond):
	}
	if busyTimeout != 5000 {
		t.Fatalf("replacement connection has unexpected busy_timeout=%d", busyTimeout)
	}
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal("could not release writer lock")
	}
	select {
	case got := <-finished:
		if got.err != nil || len(got.statuses) != 1 || got.statuses[0] != ImportCreated {
			t.Fatal("store could not import after the writer released its lock")
		}
	case <-retryCtx.Done():
		t.Fatal("import did not finish after the writer released its lock")
	}
	requireImportValue(t, contender, "entry", value, "import after cancellation")
}

func TestImportConcurrentStoresSameRef(t *testing.T) {
	ctx := context.Background()
	path := pathForTest(t)
	a, err := Create(path, keyForTest())
	if err != nil {
		t.Fatal("create store failed")
	}
	defer a.Close()
	b, err := Open(path, keyForTest())
	if err != nil {
		t.Fatal("open store failed")
	}
	defer b.Close()

	type outcome struct {
		status ImportStatus
		ok     bool
	}
	race := func(ref string, valueA, valueB []byte) []outcome {
		t.Helper()
		start := make(chan struct{})
		out := make(chan outcome, 2)
		run := func(s *Store, value []byte) {
			<-start
			statuses, err := s.Import(ctx, []ImportItem{{Ref: ref, Value: value}})
			if err != nil || len(statuses) != 1 {
				out <- outcome{}
				return
			}
			out <- outcome{status: statuses[0], ok: true}
		}
		go run(a, valueA)
		go run(b, valueB)
		close(start)
		return []outcome{<-out, <-out}
	}
	count := func(results []outcome, want ImportStatus) int {
		n := 0
		for _, result := range results {
			if !result.ok {
				t.Fatal("concurrent import failed")
			}
			if result.status == want {
				n++
			}
		}
		return n
	}

	valueA, valueB := importValue(t, 24), importValue(t, 25)
	results := race("contended", valueA, valueB)
	if count(results, ImportCreated) != 1 || count(results, ImportReplaced) != 1 {
		t.Fatal("concurrent distinct writes did not yield one create and one replace")
	}
	final := func(ref string, allowed ...[]byte) {
		t.Helper()
		err := a.Use(ctx, ref, func(got []byte) error {
			for _, want := range allowed {
				if bytes.Equal(got, want) {
					return nil
				}
			}
			return errors.New("value is not one complete import")
		})
		if err != nil {
			t.Fatal("final value is not one complete import")
		}
	}
	final("contended", valueA, valueB)
	if writes := importWrites(t, a); writes != 3 {
		t.Fatalf("counter after two concurrent changes = %d, want 3", writes)
	}

	// The same value raced onto a fresh ref: exactly one create and one
	// unchanged, and the counter moves by one.
	value := importValue(t, 21)
	results = race("same-value", value, value)
	if count(results, ImportCreated) != 1 || count(results, ImportUnchanged) != 1 {
		t.Fatal("concurrent identical writes did not yield one create and one unchanged")
	}
	final("same-value", value)
	if writes := importWrites(t, a); writes != 4 {
		t.Fatalf("counter after concurrent identical writes = %d, want 4", writes)
	}
}
