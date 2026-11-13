package syncing

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/cache"
	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/pair"
	"github.com/lidessen/keyref/cli/internal/testowner"
)

// ownerDirectory builds a signed directory carrying the CLI device and
// the given owner (ios) devices.
func ownerDirectory(t *testing.T, signer *testowner.Owner, rev uint64, cli *device.Identity, owners ...*testowner.Owner) wire.DirectoryData {
	t.Helper()
	digest, err := wire.GrantsDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	devices := []wire.DirectoryDevice{{
		DeviceID: tvDevice, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli.HPKEPublic,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: cli.SignPublic,
		GrantsDigest: digest,
	}}
	for _, o := range owners {
		devices = append(devices, wire.DirectoryDevice{
			DeviceID: o.OwnerDev, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
			HPKEKEM: wire.KEMP256, HPKEPublicKey: o.HPKEPub,
			SignAlg: wire.SignAlgECDSAP256, SignPublicKey: o.SignPub,
			GrantsDigest: digest,
		})
	}
	signed, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: tvVault, DirectoryRevision: rev, Devices: devices,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire.DirectoryData{DirectoryRevision: rev, Signed: signed, Signature: signer.Sign(signed)}
}

// storeDirectory seeds the saved-directory KV directly (the state a
// completed pairing leaves behind).
func storeDirectory(t *testing.T, st *cache.Store, d wire.DirectoryData) {
	t.Helper()
	if err := st.SetKV(pair.KVDirectorySigned, d.Signed); err != nil {
		t.Fatal(err)
	}
	if err := st.SetKV(pair.KVDirectorySig, d.Signature); err != nil {
		t.Fatal(err)
	}
	if err := st.SetKV(pair.KVDirectoryRev, []byte(strconv.FormatUint(d.DirectoryRevision, 10))); err != nil {
		t.Fatal(err)
	}
}

func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	Warn = &buf
	t.Cleanup(func() { Warn = nil })
	return &buf
}

// TestSyncSkipsItemWithBadDigest pins the v2 E per-field digest rule: a
// row whose visible ciphertext does not hash to its digest is skipped.
func TestSyncSkipsItemWithBadDigest(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	st := newStore(t, owner)
	warned := captureWarnings(t)

	item := owner.SealItem(tvItem, tvOwner, "r", "n", "***", "v")
	item.Data.MetaCiphertext[0] ^= 1 // signature and digests now disagree

	ss := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "i", item.Data)})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatalf("row skip must not fail the sync: %v", err)
	}
	if _, ok, _ := st.GetItem(tvItem); ok {
		t.Fatal("row with a digest mismatch was applied")
	}
	if !bytes.Contains(warned.Bytes(), []byte("sync skipped item")) {
		t.Fatal("no warning for the skipped item row")
	}
}

// TestSyncSkipsItemWithBadSignature pins signature verification on the
// digest-form transcript: a row whose signature does not verify is
// skipped even when its digests are self-consistent.
func TestSyncSkipsItemWithBadSignature(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	st := newStore(t, owner)
	captureWarnings(t)

	// A self-consistent row under a DIFFERENT owner key: the signature
	// verifies under nobody the CLI trusts.
	rogue := testowner.New(t, tvVault, tvOwner)
	item := rogue.SealItem(tvItem, tvOwner, "r", "n", "***", "v")

	ss := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "i", item.Data)})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatalf("row skip must not fail the sync: %v", err)
	}
	if _, ok, _ := st.GetItem(tvItem); ok {
		t.Fatal("row signed by an unknown key was applied")
	}
}

// TestSyncSkipsTamperedTombstone pins that tombstones are verified too:
// an unsigned or tampered tombstone must not delete local data.
func TestSyncSkipsTamperedTombstone(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	st := newStore(t, owner)
	captureWarnings(t)

	item := owner.SealItem(tvItem, tvOwner, "r", "n", "***", "v")
	ss := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "i", item.Data)})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}

	tomb := owner.TombstoneRow(tvItem, tvOwner, 2)
	tomb.Signature[0] ^= 1
	ss2 := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "i", tomb)})
	if _, err := Run(st, client.New(ss2.URL, tokn()), tvDevice); err != nil {
		t.Fatalf("row skip must not fail the sync: %v", err)
	}
	if _, ok, _ := st.GetItem(tvItem); !ok {
		t.Fatal("tampered tombstone deleted the item")
	}
}

// TestSyncRejectsTamperedDirectory pins that a directory that does not
// verify aborts the sync and is not stored (v2 F).
func TestSyncRejectsTamperedDirectory(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)

	d := ownerDirectory(t, owner, 2, id, owner)
	d.Signature[0] ^= 1
	ss := newSyncServer(t, []wire.SyncChange{change(wire.EntityDirectory, "d", d)})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err == nil {
		t.Fatal("tampered directory did not abort the sync")
	}
	if _, ok, _ := st.GetKV(pair.KVDirectorySigned); ok {
		t.Fatal("tampered directory was stored")
	}
}

// TestSyncFailsClosedWithoutActiveOwner pins the v2 F edge: once a
// directory is saved, a vault whose directory lists no active iOS device
// must not fall back to the pinned key (it may name a revoked owner).
func TestSyncFailsClosedWithoutActiveOwner(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newIdentity(t)
	st := newStore(t, owner)
	captureWarnings(t)

	// Saved directory with the CLI device only.
	digest, err := wire.GrantsDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: tvVault, DirectoryRevision: 1,
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
	storeDirectory(t, st, wire.DirectoryData{DirectoryRevision: 1, Signed: signed,
		Signature: owner.Sign(signed)})

	// Rows that verify under the pinned key are still rejected.
	item := owner.SealItem(tvItem, tvOwner, "r", "n", "***", "v")
	view := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindView, 1, 0, item.MetaKey)
	ss := newSyncServer(t, []wire.SyncChange{
		change(wire.EntityItem, "i", item.Data),
		change(wire.EntityGrant, "g", view),
	})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatalf("row skip must not fail the sync: %v", err)
	}
	if _, ok, _ := st.GetItem(tvItem); ok {
		t.Fatal("item accepted without an active owner device in the saved directory")
	}
	if grants, _ := st.Grants(); len(grants) != 0 {
		t.Fatal("grant accepted without an active owner device in the saved directory")
	}

	// A new directory cannot be accepted either.
	next := ownerDirectory(t, owner, 2, id, owner)
	ss2 := newSyncServer(t, []wire.SyncChange{change(wire.EntityDirectory, "d", next)})
	if _, err := Run(st, client.New(ss2.URL, tokn()), tvDevice); err == nil {
		t.Fatal("directory accepted without an active owner device in the saved directory")
	}
}

// TestSyncUsesOwnerKeyChain pins v2 F end to end: a directory signed by
// any active owner device of the saved directory is accepted, items are
// verified under their writer's directory key, and a directory signed by
// an unknown key aborts.
func TestSyncUsesOwnerKeyChain(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner) // pinned at pairing
	other := testowner.New(t, tvVault, tvOther) // second owner device
	stranger := testowner.New(t, tvVault, tvStranger)
	id := newIdentity(t)
	st := newStore(t, owner)
	captureWarnings(t)

	// Initial directory: pinned owner signs it, listing itself and the
	// second owner as active ios devices.
	storeDirectory(t, st, ownerDirectory(t, owner, 1, id, owner, other))

	// An item signed by the second owner, named by writer_device_id,
	// verifies under the chain.
	item := other.SealItem(tvItem, tvOther, "r", "n", "***", "v")
	ss := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "i", item.Data)})
	if _, err := Run(st, client.New(ss.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.GetItem(tvItem); !ok {
		t.Fatal("item signed by a chain owner device was not applied")
	}

	// An item signed by a stranger whose writer device is listed in the
	// saved directory verifies (the row names the device, not the key),
	// but a writer NOT in the directory is rejected.
	foreign := stranger.SealItem(tvItem2, tvStranger, "r2", "n2", "***", "v2")
	ss2 := newSyncServer(t, []wire.SyncChange{change(wire.EntityItem, "i2", foreign.Data)})
	if _, err := Run(st, client.New(ss2.URL, tokn()), tvDevice); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.GetItem(tvItem2); ok {
		t.Fatal("item from a writer outside the directory was applied")
	}

	// A new directory signed by the second owner device is accepted: it
	// is an active ios device in the saved directory.
	next := ownerDirectory(t, other, 2, id, owner, other)
	ss3 := newSyncServer(t, []wire.SyncChange{change(wire.EntityDirectory, "d", next)})
	if _, err := Run(st, client.New(ss3.URL, tokn()), tvDevice); err != nil {
		t.Fatalf("directory signed by a chain owner rejected: %v", err)
	}
	rev, _, _ := st.GetKV(pair.KVDirectoryRev)
	if string(rev) != "2" {
		t.Fatalf("directory revision %s, want 2", rev)
	}

	// A directory signed by a key no active device carries aborts.
	rogue := ownerDirectory(t, stranger, 3, id, owner, other)
	ss4 := newSyncServer(t, []wire.SyncChange{change(wire.EntityDirectory, "d", rogue)})
	if _, err := Run(st, client.New(ss4.URL, tokn()), tvDevice); err == nil {
		t.Fatal("directory signed by an unknown key did not abort the sync")
	}
	rev, _, _ = st.GetKV(pair.KVDirectoryRev)
	if string(rev) != "2" {
		t.Fatalf("rejected directory overwrote revision: %s", rev)
	}
}
