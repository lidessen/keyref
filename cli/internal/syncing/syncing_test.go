package syncing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/pair"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/store"
	"github.com/lidessen/keyref/cli/internal/testowner"
)

const (
	tvVault  = "00112233445566778899aabbccddeeff"
	tvOwner  = "99998888777766665555444433332222"
	tvDevice = "0123456789abcdef0123456789abcdef"
	tvItem   = "deadbeefdeadbeefdeadbeefdeadbeef"
	tvItem2  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func newIdentity(t *testing.T) *device.Identity {
	t.Helper()
	base, err := os.MkdirTemp("", "sync-dev-*")
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
	return id
}

func newStore(t *testing.T, owner *testowner.Owner) *store.Store {
	t.Helper()
	base, err := os.MkdirTemp("", "sync-store-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	st, err := store.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_ = st.SetKV(session.KVVaultID, []byte(owner.VaultID))
	_ = st.SetKV(session.KVDeviceID, []byte(tvDevice))
	_ = st.SetKV(pair.KVOwnerSignPub, owner.SignPub)
	return st
}

// syncServer serves one batch of changes then "current", plus
// grants/self.
type syncServer struct {
	*httptest.Server
	mu      sync.Mutex
	batches [][]wire.SyncChange
	self    *wire.GrantsSelfResponse
}

func newSyncServer(t *testing.T, changes []wire.SyncChange) *syncServer {
	t.Helper()
	ss := &syncServer{}
	ss.batches = [][]wire.SyncChange{changes}
	ss.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ss.mu.Lock()
		defer ss.mu.Unlock()
		switch r.URL.Path {
		case "/v1/sync":
			cursor, _ := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
			next := cursor + 10
			if len(ss.batches) > 0 {
				b := ss.batches[0]
				ss.batches = ss.batches[1:]
				writeJSON(w, wire.SyncResponse{Cursor: next, HasMore: false, Changes: b})
				return
			}
			writeJSON(w, wire.SyncResponse{Cursor: cursor, HasMore: false, Changes: nil})
		case "/v1/grants/self":
			if ss.self == nil {
				writeJSON(w, wire.GrantsSelfResponse{Grants: nil})
				return
			}
			writeJSON(w, *ss.self)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ss.Close)
	return ss
}

func writeJSON(w http.ResponseWriter, v any) {
	json.NewEncoder(w).Encode(v)
}

func change(entity, entityID string, data any) wire.SyncChange {
	raw, _ := json.Marshal(data)
	return wire.SyncChange{Seq: 1, Entity: entity, EntityID: entityID, CreatedAt: 1, Data: raw}
}

func TestSyncAppliesItemsGrantsDirectory(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)

	item := owner.SealItem(tvItem, tvOwner, "openai-prod", "OpenAI production", "sk-****abcd", "sk-value-1")
	view := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindView, 1, 0, item.MetaKey)
	use := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindUse, 1, 0, item.ItemKey)

	digest, err := wire.GrantsDigest([]wire.GrantTranscript{view.Transcript(tvVault), use.Transcript(tvVault)})
	if err != nil {
		t.Fatal(err)
	}
	dirSigned, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: tvVault, DirectoryRevision: 2,
		Devices: []wire.DirectoryDevice{{
			DeviceID: tvDevice, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: id.HPKEPublic,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: id.SignPublic,
			GrantsDigest: digest,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	changes := []wire.SyncChange{
		change(wire.EntityItem, "item:"+tvItem, item.Data),
		change(wire.EntityGrant, "grant:", view),
		change(wire.EntityGrant, "grant:", use),
		change(wire.EntityDirectory, "directory:"+tvVault, wire.DirectoryData{
			DirectoryRevision: 2, Signed: dirSigned, Signature: owner.Sign(dirSigned),
		}),
	}
	ss := newSyncServer(t, changes)
	self := &wire.GrantsSelfResponse{Grants: []wire.GrantData{view, use}, GrantsDigest: digest, DirectoryRevision: 2}
	ss.self = self

	res, err := Run(st, client.New(ss.URL, func() (string, error) { return "t", nil }), tvDevice)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 4 {
		t.Fatalf("applied %d, want 4", res.Applied)
	}
	if it, ok, _ := st.GetItem(tvItem); !ok || it.Revision != 1 {
		t.Fatal("item not applied")
	}
	if grants, _ := st.Grants(); len(grants) != 2 {
		t.Fatalf("grants %d", len(grants))
	}
	if v, ok, _ := st.GetKV(pair.KVDirectorySigned); !ok || len(v) == 0 {
		t.Fatal("directory not stored")
	}
}

// TestSyncAppliesLocalItemRow pins the v0.7 local-item sync semantics
// (design §6.6): a row with an empty secret_ciphertext (the wire form of
// SQL NULL) applies like any other — the absence is NOT corruption. The
// cached row keeps the empty secret so exec branches to the
// approval-delivers-secret path.
func TestSyncAppliesLocalItemRow(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)

	item := owner.SealItem(tvItem, tvOwner, "totp-seed", "n", "abcd****", "v")
	// Turn the sealed row into its local-item form: no secret and no
	// vault-wrapped item key, resigned over the §3.1 transcript.
	local := item.Data
	local.SecretCiphertext = nil
	local.VaultWrappedItemKey = nil
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: tvVault, ItemID: tvItem, Revision: 1,
		MetaCiphertext: local.MetaCiphertext, SecretCiphertext: nil,
		VaultWrappedMetaKey: local.VaultWrappedMetaKey, VaultWrappedItemKey: nil,
		WriterDeviceID: tvOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	local.Signature = owner.Sign(tb)

	view := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindView, 1, 0, item.MetaKey)
	ss := newSyncServer(t, []wire.SyncChange{
		change(wire.EntityItem, "item:"+tvItem, local),
		change(wire.EntityGrant, "grant:", view),
	})
	res, err := Run(st, client.New(ss.URL, tokn()), tvDevice)
	if err != nil {
		t.Fatalf("sync rejected the NULL-secret row: %v", err)
	}
	if res.Applied != 2 {
		t.Fatalf("applied %d, want 2", res.Applied)
	}
	it, ok, err := st.GetItem(tvItem)
	if err != nil || !ok {
		t.Fatalf("local item not cached: ok=%v err=%v", ok, err)
	}
	if len(it.SecretCiphertext) != 0 {
		t.Fatalf("cached secret must stay empty for a local item, got %d bytes", len(it.SecretCiphertext))
	}
	if len(it.MetaCiphertext) == 0 {
		t.Fatal("meta ciphertext lost")
	}
}

func TestSyncTombstoneAndGrantDeletionClearCache(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)

	item := owner.SealItem(tvItem, tvOwner, "openai-prod", "n", "***", "v")
	view := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindView, 1, 0, item.MetaKey)

	ss := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "item:"+tvItem, item.Data),
		change(wire.EntityGrant, "g", view)})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.GetItem(tvItem); !ok {
		t.Fatal("setup failed")
	}

	// Item tombstone deletes the row and its grants (design §6.3).
	ss2 := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "item:"+tvItem,
		wire.ItemData{VaultID: tvVault, ItemID: tvItem, Revision: 2, Tombstone: true, WriterDeviceID: tvOwner})})
	if _, err := Run(st, client.New(ss2.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.GetItem(tvItem); ok {
		t.Fatal("tombstone did not delete item")
	}
	if grants, _ := st.Grants(); len(grants) != 0 {
		t.Fatalf("tombstone left %d grants", len(grants))
	}

	// Grant deletion (pointing at us) clears the wrap (design §6.3).
	item2 := owner.SealItem(tvItem2, tvOwner, "second", "n2", "***", "v2")
	view2 := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem2, wire.GrantKindView, 1, 0, item2.MetaKey)
	ss3 := newSyncServer(t, []wire.SyncChange{
		change(wire.EntityItem, "item:"+tvItem2, item2.Data),
		change(wire.EntityGrant, "g", view2),
	})
	if _, err := Run(st, client.New(ss3.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}
	del := wire.GrantData{DeviceID: tvDevice, ItemID: tvItem2, Kind: wire.GrantKindView,
		Deleted: true, Revision: 2}
	ss4 := newSyncServer(t, []wire.SyncChange{change(wire.EntityGrant, "g", del)})
	if _, err := Run(st, client.New(ss4.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}
	if grants, _ := st.Grants(); len(grants) != 0 {
		t.Fatalf("grant deletion left %d grants", len(grants))
	}
}

// TestSyncRejectsTombstoneRollback pins the revision-floor replay guard
// (design §6.2): after a tombstone, a malicious server replaying the
// older live row must not resurrect the old (possibly rolled-back)
// secret. The stale row is dropped silently.
func TestSyncRejectsTombstoneRollback(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	st := newStore(t, owner)

	item := owner.SealItem(tvItem, tvOwner, "openai-prod", "n", "***", "v")
	ss := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "item:"+tvItem, item.Data)})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}

	// Tombstone at revision 2 deletes the row.
	ss2 := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "item:"+tvItem,
		wire.ItemData{VaultID: tvVault, ItemID: tvItem, Revision: 2, Tombstone: true, WriterDeviceID: tvOwner})})
	if _, err := Run(st, client.New(ss2.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.GetItem(tvItem); ok {
		t.Fatal("tombstone did not delete item")
	}

	// Replay of the stale revision-1 row must be rejected, not applied.
	ss3 := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "item:"+tvItem, item.Data)})
	if _, err := Run(st, client.New(ss3.URL, tokn()), tvDevice); err != nil {
		t.Fatalf("stale replay must be dropped silently, got error: %v", err)
	}
	if _, ok, _ := st.GetItem(tvItem); ok {
		t.Fatal("tombstone rollback resurrected the item")
	}
}

// TestSyncRejectsGrantResurrection pins the grant replay guard
// (design §8.4): after a revocation, a replayed lower-revision,
// correctly signed live grant must not resurrect the grant.
func TestSyncRejectsGrantResurrection(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)

	item := owner.SealItem(tvItem, tvOwner, "openai-prod", "n", "***", "v")
	view := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindView, 1, 0, item.MetaKey)
	ss := newSyncServer(t, []wire.SyncChange{
		change(wire.EntityItem, "item:"+tvItem, item.Data),
		change(wire.EntityGrant, "g", view),
	})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}

	// Revoke the grant (deletion form, revision 2).
	del := wire.GrantData{DeviceID: tvDevice, ItemID: tvItem, Kind: wire.GrantKindView,
		Deleted: true, Revision: 2}
	ss2 := newSyncServer(t, []wire.SyncChange{change(wire.EntityGrant, "g", del)})
	if _, err := Run(st, client.New(ss2.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}
	if grants, _ := st.Grants(); len(grants) != 0 {
		t.Fatal("deletion did not clear grant")
	}

	// Replay the correctly signed revision-1 live grant: must be dropped.
	ss3 := newSyncServer(t, []wire.SyncChange{change(wire.EntityGrant, "g", view)})
	if _, err := Run(st, client.New(ss3.URL, tokn()), tvDevice); err != nil {
		t.Fatalf("stale grant replay must be dropped silently, got error: %v", err)
	}
	if grants, _ := st.Grants(); len(grants) != 0 {
		t.Fatal("revoked grant was resurrected by replay")
	}
}

// TestSyncRejectsStaleDirectory pins directory revision monotonicity:
// a correctly signed but older directory must not overwrite a newer one
// (a malicious server could otherwise replay a pre-revocation directory
// and suppress revocation delivery).
func TestSyncRejectsStaleDirectory(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)

	buildDir := func(rev uint64) wire.DirectoryData {
		digest, err := wire.GrantsDigest(nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
			VaultID: tvVault, DirectoryRevision: rev,
			Devices: []wire.DirectoryDevice{{
				DeviceID: tvDevice, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMX25519, HPKEPublicKey: id.HPKEPublic,
				SignAlg: wire.SignAlgEd25519, SignPublicKey: id.SignPublic,
				GrantsDigest: digest,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return wire.DirectoryData{DirectoryRevision: rev, Signed: signed, Signature: owner.Sign(signed)}
	}

	ss := newSyncServer(t, []wire.SyncChange{change(wire.EntityDirectory, "d", buildDir(3))})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}
	storedRev, ok, _ := st.GetKV(pair.KVDirectoryRev)
	if !ok || string(storedRev) != "3" {
		t.Fatalf("directory revision 3 not stored: %s", storedRev)
	}

	// A replayed revision-2 directory must be ignored.
	ss2 := newSyncServer(t, []wire.SyncChange{change(wire.EntityDirectory, "d", buildDir(2))})
	if _, err := Run(st, client.New(ss2.URL, tokn()), tvDevice); err != nil {
		t.Fatalf("stale directory replay must be dropped silently, got error: %v", err)
	}
	storedRev, _, _ = st.GetKV(pair.KVDirectoryRev)
	if string(storedRev) != "3" {
		t.Fatalf("stale directory overwrote revision: %s", storedRev)
	}
}

func TestSyncDetectsRevocationAndCleansUp(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)

	item := owner.SealItem(tvItem, tvOwner, "r", "n", "***", "v")
	use := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindUse, 1, 0, item.ItemKey)
	ss := newSyncServer(t, []wire.SyncChange{
		change(wire.EntityItem, "i", item.Data),
		change(wire.EntityGrant, "g", use),
	})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}

	revoked := change(wire.EntityDevice, "device:"+tvDevice, wire.DeviceData{
		DeviceID: tvDevice, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusRevoked,
	})
	// The device entity is owner-only on the real server; a CLI learns
	// its revocation from the signed directory (design.md §8.4, §10.6).
	// Both deliveries must trigger the cleanup.
	digest, err := wire.GrantsDigest([]wire.GrantTranscript{use.Transcript(tvVault)})
	if err != nil {
		t.Fatal(err)
	}
	dirSigned, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: tvVault, DirectoryRevision: 2,
		Devices: []wire.DirectoryDevice{{
			DeviceID: tvDevice, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusRevoked,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: id.HPKEPublic,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: id.SignPublic,
			GrantsDigest: digest,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	revokedDir := change(wire.EntityDirectory, "directory:"+tvVault, wire.DirectoryData{
		DirectoryRevision: 2, Signed: dirSigned, Signature: owner.Sign(dirSigned),
	})
	ss2 := newSyncServer(t, []wire.SyncChange{revoked, revokedDir})
	_, err = Run(st, client.New(ss2.URL, tokn()), tvDevice)
	if err != ErrRevoked {
		t.Fatalf("got %v, want ErrRevoked", err)
	}
	if grants, _ := st.Grants(); len(grants) != 0 {
		t.Fatal("revocation cleanup left grants behind")
	}
}

func TestSyncRejectsTamperedGrant(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)

	item := owner.SealItem(tvItem, tvOwner, "r", "n", "***", "v")
	view := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindView, 1, 0, item.MetaKey)
	// Tamper with the wrapped key after signing.
	view.WrappedKey[0] ^= 1

	ss := newSyncServer(t, []wire.SyncChange{change(wire.EntityGrant, "g", view)})
	_, err := Run(st, client.New(ss.URL, tokn()), tvDevice)
	if err == nil {
		t.Fatal("tampered grant applied")
	}
}

func TestSyncReconcilesDigestMismatch(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)

	item := owner.SealItem(tvItem, tvOwner, "r", "n", "***", "v")
	use := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindUse, 1, 0, item.ItemKey)

	ss := newSyncServer(t, []wire.SyncChange{
		change(wire.EntityItem, "i", item.Data),
		change(wire.EntityGrant, "g", use),
	})
	// grants/self reports a digest that does not match its own rows —
	// a server suppressing or forging the grant set (design §9.1).
	fakeDigest := make([]byte, 32)
	fakeDigest[0] = 0xAA
	ss.self = &wire.GrantsSelfResponse{Grants: []wire.GrantData{use}, GrantsDigest: fakeDigest, DirectoryRevision: 1}

	_, err := Run(st, client.New(ss.URL, tokn()), tvDevice)
	if err == nil {
		t.Fatal("digest mismatch accepted")
	}
}

func tokn() func() (string, error) {
	return func() (string, error) { return "test-token", nil }
}
