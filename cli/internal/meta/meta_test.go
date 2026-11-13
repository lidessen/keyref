package meta

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/cache"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/pair"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/testowner"
)

const (
	tvVault  = "00112233445566778899aabbccddeeff"
	tvOwner  = "99998888777766665555444433332222"
	tvDevice = "0123456789abcdef0123456789abcdef"
	tvItem   = "deadbeefdeadbeefdeadbeefdeadbeef"
)

const fxSecret = "sk-META-TEST-never-in-output"

func fixture(t *testing.T) (*cache.Store, *device.Identity, *testowner.Owner) {
	t.Helper()
	owner := testowner.New(t, tvVault, tvOwner)
	base, err := os.MkdirTemp("", "meta-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	ks, err := keyring.NewDirStore(filepath.Join(base, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := device.LoadOrCreate(ks)
	if err != nil {
		t.Fatal(err)
	}
	st, err := cache.Open(filepath.Join(base, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_ = st.SetKV(session.KVVaultID, []byte(tvVault))
	_ = st.SetKV(session.KVDeviceID, []byte(tvDevice))
	_ = st.SetKV(pair.KVOwnerSignPub, owner.SignPub)
	return st, id, owner
}

func TestItemsDecryptsMetaOnlyAndMasks(t *testing.T) {
	st, id, owner := fixture(t)
	item := owner.SealItem(tvItem, tvOwner, "openai-prod", "OpenAI production", "sk-****abcd", fxSecret)
	if err := st.PutItem(&item.Data); err != nil {
		t.Fatal(err)
	}
	view := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindView, 1, 0, item.MetaKey)
	if err := st.PutGrant(&view); err != nil {
		t.Fatal(err)
	}

	entries, err := Items(st, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries %d", len(entries))
	}
	e := entries[0]
	if e.Ref != "openai-prod" || e.Name != "OpenAI production" || e.Type != "api_key" || e.Masked != "sk-****abcd" {
		t.Fatalf("entry %+v", e)
	}
	// The entry has no value field at all: marshalled JSON must not
	// contain "value" or the fixture secret (design.md §12.2, §15).
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "value") {
		t.Fatalf("entry JSON carries a value field: %s", b)
	}
	if strings.Contains(string(b), fxSecret) {
		t.Fatal("entry JSON carries the secret")
	}

	got, err := Lookup(st, id, "openai-prod")
	if err != nil || got.Ref != "openai-prod" {
		t.Fatalf("lookup: %v", err)
	}
	if _, err := Lookup(st, id, "nope"); err != ErrUnknownRef {
		t.Fatalf("lookup unknown: %v", err)
	}
}

func TestItemsWithoutViewGrantIsSkipped(t *testing.T) {
	st, id, owner := fixture(t)
	item := owner.SealItem(tvItem, tvOwner, "openai-prod", "n", "***", "v")
	if err := st.PutItem(&item.Data); err != nil {
		t.Fatal(err)
	}
	entries, err := Items(st, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("item without view grant listed: %v", entries)
	}
	_, err = Lookup(st, id, "openai-prod")
	if err != ErrUnknownRef {
		t.Fatalf("lookup without grant: %v", err)
	}
}
