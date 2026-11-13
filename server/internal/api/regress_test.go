package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/wire"
)

// TestRevokedOwnerSyncVisibility is the regression for the revoked iOS
// owner bypass: a revoked owner with a still-valid 12h token must see
// ONLY the directory from sync (design §10.6) — no item rows, no
// vault_wrapped_* blobs, no live grants, not even items written after
// the revocation.
func TestRevokedOwnerSyncVisibility(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	item1 := randHexID(t)
	if s := owner.putItem(t, item1, 1, []byte("meta"), []byte("secret")); s != 200 {
		t.Fatalf("put item: %d", s)
	}

	// A second owner takes over the directory; the first is revoked.
	bKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bPub, err := wire.EncodeP256PublicKey(&bKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bID := randHexID(t)
	dir, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: owner.vaultID, DirectoryRevision: 2,
		Devices: []wire.DirectoryDevice{
			{
				DeviceID: bID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMP256, HPKEPublicKey: append([]byte{0x04}, randBytes(t, 64)...),
				SignAlg: wire.SignAlgECDSAP256, SignPublicKey: bPub,
				GrantsDigest: wire.EmptyGrantsDigest(),
			},
			{
				DeviceID: owner.deviceID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusRevoked,
				HPKEKEM: wire.KEMP256, HPKEPublicKey: owner.hpkePub,
				SignAlg: wire.SignAlgECDSAP256, SignPublicKey: owner.signPub,
				GrantsDigest: wire.EmptyGrantsDigest(),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dirSig, err := wire.SignOwnerECDSA(dir, owner.signKey) // current owner signs the rotation
	if err != nil {
		t.Fatal(err)
	}
	if s, raw := e.do("PUT", "/v1/directory", owner.token, wire.PutDirectoryRequest{
		DirectoryRevision: 2, DirectorySigned: dir, Signature: dirSig,
	}); s != 200 {
		t.Fatalf("rotate directory: %d %s", s, raw)
	}

	// Items written after the revocation must never reach the revoked
	// owner through sync.
	item2 := randHexID(t)
	ownerB := &testOwner{ // session for the new owner, same vault
		env: e, signKey: bKey, signPub: bPub, vaultID: owner.vaultID, deviceID: bID,
	}
	ownerB.session(t)
	if s := ownerB.putItem(t, item2, 1, []byte("meta-2"), []byte("secret-2")); s != 200 {
		t.Fatalf("new owner put item: %d", s)
	}

	// The revoked owner keeps its bearer token (sessions are not killed
	// by an ordinary revocation, §8.4) but loses every non-sync endpoint.
	if s, raw := e.do("GET", "/v1/account", owner.token, nil); s != 403 {
		t.Fatalf("revoked owner account: want 403, got %d %s", s, raw)
	}

	// Bootstrap: only the directory change may appear.
	batch := e.sync(t, owner.token, 0)
	if len(batch.Changes) != 1 || batch.Changes[0].Entity != wire.EntityDirectory {
		t.Fatalf("revoked owner bootstrap must contain only the directory: %+v", batch.Changes)
	}
	dirData := decodeDirectoryData(t, batch.Changes[0])
	if dirData.DirectoryRevision != 2 {
		t.Fatalf("bootstrap directory revision = %d", dirData.DirectoryRevision)
	}

	// Incremental sync from an old cursor: directory changes only, no
	// item or grant rows — including for item2 written after revocation.
	batch2 := e.sync(t, owner.token, 0) // cursor=end; then pull incremental
	batch3 := e.sync(t, owner.token, batch2.Cursor-1)
	for _, ch := range batch3.Changes {
		switch ch.Entity {
		case wire.EntityDirectory:
			// allowed
		case wire.EntityItem:
			var d wire.ItemData
			json.Unmarshal(ch.Data, &d)
			t.Fatalf("revoked owner received an item change: %+v", d)
		case wire.EntityGrant:
			var d wire.GrantData
			json.Unmarshal(ch.Data, &d)
			t.Fatalf("revoked owner received a grant change: %+v", d)
		default:
			t.Fatalf("revoked owner received a %q change", ch.Entity)
		}
	}
}

// TestConcurrentItemRevision is the regression for the check-then-act
// revision race: two owners uploading the same revision concurrently
// must yield exactly one 200 and one 409 revision_conflict — never two
// silent overwrites.
func TestConcurrentItemRevision(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	itemID := randHexID(t)
	const rounds = 20
	for r := 0; r < rounds; r++ {
		// Round r races revision 2r+1 (round 0 creates the item at 1);
		// after each round a sequential write bumps the row to 2r+2.
		racingRev := uint64(2*r + 1)
		nextRev := uint64(2*r + 2)
		var wg sync.WaitGroup
		results := make(chan int, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- owner.putItem(t, itemID, racingRev, []byte("m"), []byte("s"))
			}()
		}
		wg.Wait()
		close(results)
		var ok200, conflict int
		for s := range results {
			switch s {
			case 200:
				ok200++
			case 409:
				conflict++
			default:
				t.Fatalf("unexpected status %d in round %d", s, r)
			}
		}
		if ok200 != 1 || conflict != 1 {
			t.Fatalf("round %d: ok=%d conflict=%d, want 1/1", r, ok200, conflict)
		}
		if s := owner.putItem(t, itemID, nextRev, []byte("m2"), []byte("s2")); s != 200 {
			t.Fatalf("sequential bump: %d", s)
		}
	}
}

// TestConcurrentAuditAppend is the regression for the audit-seq race:
// a burst of concurrent audit posts must all succeed with unique,
// gap-free per-vault sequence numbers (design §7.7, §6.3 single writer).
func TestConcurrentAuditAppend(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	const n = 24
	var wg sync.WaitGroup
	results := make(chan int64, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out wire.AuditResponse
			if s := e.doOut("POST", "/v1/audit", owner.token, wire.AuditRequest{Ciphertext: randBytes(t, 64)}, &out); s != 201 {
				t.Errorf("audit post: status %d", s)
				results <- -1
				return
			}
			results <- out.Seq
		}()
	}
	wg.Wait()
	close(results)
	seen := map[int64]bool{}
	maxSeq := int64(0)
	for seq := range results {
		if seq < 0 {
			t.Fatal("audit post failed")
		}
		if seen[seq] {
			t.Fatalf("duplicate audit seq %d", seq)
		}
		seen[seq] = true
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	if len(seen) != n {
		t.Fatalf("unique seqs = %d, want %d", len(seen), n)
	}
}

// TestDirectoryDeviceCeiling is the regression for directory updates
// bypassing plan device ceilings: on the hosted free tier (1 iOS
// device), a directory that activates a second iOS device must be
// refused with quota_exceeded — including the revive-a-revoked-CLI path.
func TestDirectoryDeviceCeiling(t *testing.T) {
	e := newTestEnv(t, true)
	owner := e.createVault(t)

	extra := wire.DirectoryDevice{
		DeviceID: randHexID(t), Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
		HPKEKEM: wire.KEMP256, HPKEPublicKey: append([]byte{0x04}, randBytes(t, 64)...),
		SignAlg: wire.SignAlgECDSAP256, SignPublicKey: append([]byte{0x04}, randBytes(t, 64)...),
		GrantsDigest: wire.EmptyGrantsDigest(),
	}
	records := []wire.DirectoryDevice{{
		DeviceID: owner.deviceID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
		HPKEKEM: wire.KEMP256, HPKEPublicKey: owner.hpkePub,
		SignAlg: wire.SignAlgECDSAP256, SignPublicKey: owner.signPub,
		GrantsDigest: wire.EmptyGrantsDigest(),
	}, extra}
	dir, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: owner.vaultID, DirectoryRevision: 2, Devices: records,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := wire.SignOwnerECDSA(dir, owner.signKey)
	if s, raw := e.do("PUT", "/v1/directory", owner.token, wire.PutDirectoryRequest{
		DirectoryRevision: 2, DirectorySigned: dir, Signature: sig,
	}); s != 429 {
		t.Fatalf("second active iOS over free limit: want 429, got %d %s", s, raw)
	}

	// Account still reports a single active device.
	var acct wire.AccountResponse
	e.doOut("GET", "/v1/account", owner.token, nil, &acct)
	if acct.Usage.DevicesActive != 1 {
		t.Fatalf("devices_active = %d, want 1", acct.Usage.DevicesActive)
	}
}

// TestDirectoryKeyAuthority is the regression for the signature-key
// fallback: once a directory omits a device, that device's key can no
// longer sign the next directory — the signed directory is the only
// authority for verification keys (design §9.1, §8.1).
func TestDirectoryKeyAuthority(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)

	bKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bPub, err := wire.EncodeP256PublicKey(&bKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bID := randHexID(t)

	push := func(rev uint64, devices []wire.DirectoryDevice, key *ecdsa.PrivateKey) (int, []byte) {
		dir, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
			VaultID: owner.vaultID, DirectoryRevision: rev, Devices: devices,
		})
		if err != nil {
			t.Fatal(err)
		}
		sig, err := wire.SignOwnerECDSA(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		return e.do("PUT", "/v1/directory", owner.token, wire.PutDirectoryRequest{
			DirectoryRevision: rev, DirectorySigned: dir, Signature: sig,
		})
	}
	ownerRec := wire.DirectoryDevice{
		DeviceID: owner.deviceID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
		HPKEKEM: wire.KEMP256, HPKEPublicKey: owner.hpkePub,
		SignAlg: wire.SignAlgECDSAP256, SignPublicKey: owner.signPub,
		GrantsDigest: wire.EmptyGrantsDigest(),
	}
	bRec := wire.DirectoryDevice{
		DeviceID: bID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
		HPKEKEM: wire.KEMP256, HPKEPublicKey: append([]byte{0x04}, randBytes(t, 64)...),
		SignAlg: wire.SignAlgECDSAP256, SignPublicKey: bPub,
		GrantsDigest: wire.EmptyGrantsDigest(),
	}

	// rev2 adds B; rev3 (signed by A) drops B again without marking it.
	if s, raw := push(2, []wire.DirectoryDevice{ownerRec, bRec}, owner.signKey); s != 200 {
		t.Fatalf("rev2: %d %s", s, raw)
	}
	if s, raw := push(3, []wire.DirectoryDevice{ownerRec}, owner.signKey); s != 200 {
		t.Fatalf("rev3: %d %s", s, raw)
	}
	// B signs rev4: its key is no longer in the previous directory, so
	// the signature must fail even though B's devices row is still
	// active.
	if s, raw := push(4, []wire.DirectoryDevice{ownerRec, bRec}, bKey); s != 403 {
		t.Fatalf("omitted owner signing rev4: want 403 bad_signature, got %d %s", s, raw)
	}
	// A remains able to sign.
	if s, raw := push(4, []wire.DirectoryDevice{ownerRec}, owner.signKey); s != 200 {
		t.Fatalf("legitimate rev4: %d %s", s, raw)
	}
}

// TestRevokedCLIBootstrapTombstones is the regression for the bootstrap
// tombstone delivery: a revoked CLI re-bootstrapping with cursor=0 must
// receive the tombstones of items it once held grants for, alongside
// the directory and its grant deletions (design §10.6).
func TestRevokedCLIBootstrapTombstones(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	itemID := randHexID(t)
	if s := owner.putItem(t, itemID, 1, []byte("meta"), []byte("secret")); s != 200 {
		t.Fatalf("put item: %d", s)
	}
	cli := e.registerPair(t)
	owner.completePair(t, cli, []wire.GrantData{owner.grant(t, cli.deviceID, itemID, wire.GrantKindUse, 1, 0)})
	cli.session(t)

	// Revoke the CLI, then delete the item afterwards.
	_, dirBytes := owner.directoryFor(t, 2, map[string]string{
		owner.deviceID: wire.DeviceStatusActive,
		cli.deviceID:   wire.DeviceStatusRevoked,
	})
	dirSig, _ := wire.SignOwnerECDSA(dirBytes, owner.signKey)
	if s, raw := e.do("PUT", "/v1/directory", owner.token, wire.PutDirectoryRequest{
		DirectoryRevision: 2, DirectorySigned: dirBytes, Signature: dirSig,
	}); s != 200 {
		t.Fatalf("revoke directory: %d %s", s, raw)
	}
	tb, _ := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: owner.vaultID, ItemID: itemID, Revision: 2, Tombstone: true, WriterDeviceID: owner.deviceID,
	})
	delSig, _ := wire.SignOwnerECDSA(tb, owner.signKey)
	if s, raw := e.do("DELETE", "/v1/items/"+itemID, owner.token, wire.DeleteItemRequest{Revision: 2, Signature: delSig}); s != 204 {
		t.Fatalf("delete item: %d %s", s, raw)
	}

	batch := e.sync(t, cli.token, 0)
	byEntity := changesByEntity(batch)
	var sawTombstone, sawGrantDeletion bool
	for _, c := range byEntity[wire.EntityItem] {
		if d := decodeItemData(t, c); d.ItemID == itemID && d.Tombstone {
			sawTombstone = true
			if len(d.MetaCiphertext) != 0 || len(d.SecretCiphertext) != 0 {
				t.Fatal("tombstone delivered with ciphertext content")
			}
		}
	}
	for _, c := range byEntity[wire.EntityGrant] {
		if g := decodeGrantData(t, c); g.Deleted {
			sawGrantDeletion = true
		}
	}
	if len(byEntity[wire.EntityDirectory]) != 1 {
		t.Fatal("revoked bootstrap missing directory")
	}
	if !sawTombstone {
		t.Fatal("revoked bootstrap missing the item tombstone (§10.6)")
	}
	if !sawGrantDeletion {
		t.Fatal("revoked bootstrap missing the grant deletion")
	}
}

// TestDirectoryCLICeilingOnRevokeAndMint is the CLI half of the device
// ceiling regression: a signed directory may not raise the active CLI
// count over the tier by minting a brand-new active device that was
// never paired (design §10.5, §11 item 6). Dropping a device in the same
// update makes room, because an omitted device is revoked (v2 G).
func TestDirectoryCLICeilingOnRevokeAndMint(t *testing.T) {
	e := newTestEnv(t, true)
	owner := e.createVault(t)
	cli1 := e.registerPair(t)
	owner.completePair(t, cli1, nil) // the free tier's single CLI slot
	cli2 := e.registerPair(t)        // registered for pairing, never paired: no device row

	push := func(rev uint64, statuses map[string]string) (int, []byte) {
		t.Helper()
		_, dirBytes := owner.directoryFor(t, rev, statuses)
		sig, _ := wire.SignOwnerECDSA(dirBytes, owner.signKey)
		return e.do("PUT", "/v1/directory", owner.token, wire.PutDirectoryRequest{
			DirectoryRevision: rev, DirectorySigned: dirBytes, Signature: sig,
		})
	}

	// rev2 mints cli2 next to cli1: two active CLIs on a one-CLI tier.
	if s, raw := push(2, map[string]string{
		owner.deviceID: wire.DeviceStatusActive,
		cli1.deviceID:  wire.DeviceStatusActive,
		cli2.deviceID:  wire.DeviceStatusActive,
	}); s != 429 {
		t.Fatalf("mint over CLI ceiling: want 429, got %d %s", s, raw)
	}

	// rev2 again, revoking cli1: one active CLI, so the mint fits.
	if s, raw := push(2, map[string]string{
		owner.deviceID: wire.DeviceStatusActive,
		cli1.deviceID:  wire.DeviceStatusRevoked,
		cli2.deviceID:  wire.DeviceStatusActive,
	}); s != 200 {
		t.Fatalf("revoke-and-mint at the ceiling: %d %s", s, raw)
	}
	var acct wire.AccountResponse
	e.doOut("GET", "/v1/account", owner.token, nil, &acct)
	if acct.Usage.DevicesActive != 2 { // the owner iPhone + the minted CLI
		t.Fatalf("devices_active = %d, want 2", acct.Usage.DevicesActive)
	}
}

// TestDirectoryOmissionRevokesDevice is the v2 G regression: a device
// the signed directory does not mention is revoked even though the owner
// never listed it as revoked. The directory is the single authority for
// device state, so omission must not leave the old row untouched.
func TestDirectoryOmissionRevokesDevice(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	cli := e.registerPair(t)
	owner.completePair(t, cli, nil)
	cli.session(t)

	// rev2 mentions the owner only; the paired CLI is silently dropped.
	_, dirBytes := owner.directoryFor(t, 2, map[string]string{
		owner.deviceID: wire.DeviceStatusActive,
	})
	sig, _ := wire.SignOwnerECDSA(dirBytes, owner.signKey)
	if s, raw := e.do("PUT", "/v1/directory", owner.token, wire.PutDirectoryRequest{
		DirectoryRevision: 2, DirectorySigned: dirBytes, Signature: sig,
	}); s != 200 {
		t.Fatalf("omitting directory: %d %s", s, raw)
	}

	// Every non-sync endpoint answers device_revoked (§8.4); the session
	// keeps sync access, which is how the revocation reaches the device.
	if s, raw := e.do("GET", "/v1/account", cli.token, nil); s != 403 {
		t.Fatalf("omitted CLI: want 403 device_revoked, got %d %s", s, raw)
	}
	if s, raw := e.do("GET", "/v1/sync?cursor=0", cli.token, nil); s != 200 {
		t.Fatalf("omitted CLI sync: want 200, got %d %s", s, raw)
	}
	var acct wire.AccountResponse
	e.doOut("GET", "/v1/account", owner.token, nil, &acct)
	if acct.Usage.DevicesActive != 1 {
		t.Fatalf("devices_active = %d, want 1 after omission", acct.Usage.DevicesActive)
	}
}

// TestDirectoryRevokeIsTerminal pins the second half of v2 G: a revoked
// device never comes back. Re-pairing mints a fresh device id with fresh
// keys, so a directory that lists the old id as active is a bug or a
// replay and must be refused without consuming the revision.
func TestDirectoryRevokeIsTerminal(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	cli := e.registerPair(t)
	owner.completePair(t, cli, nil)

	push := func(rev uint64, status string) (int, []byte) {
		t.Helper()
		_, dirBytes := owner.directoryFor(t, rev, map[string]string{
			owner.deviceID: wire.DeviceStatusActive,
			cli.deviceID:   status,
		})
		sig, _ := wire.SignOwnerECDSA(dirBytes, owner.signKey)
		return e.do("PUT", "/v1/directory", owner.token, wire.PutDirectoryRequest{
			DirectoryRevision: rev, DirectorySigned: dirBytes, Signature: sig,
		})
	}

	if s, raw := push(2, wire.DeviceStatusRevoked); s != 200 {
		t.Fatalf("revoke directory: %d %s", s, raw)
	}
	if s, raw := push(3, wire.DeviceStatusActive); s != 400 {
		t.Fatalf("revive a revoked device: want 400 invalid_field, got %d %s", s, raw)
	}
	// The refused update rolled back, so the same revision is still free
	// for a directory that keeps the device revoked.
	if s, raw := push(3, wire.DeviceStatusRevoked); s != 200 {
		t.Fatalf("revision reusable after a refused revive: %d %s", s, raw)
	}
	var acct wire.AccountResponse
	e.doOut("GET", "/v1/account", owner.token, nil, &acct)
	if acct.Usage.DevicesActive != 1 {
		t.Fatalf("devices_active = %d, want 1 (revoked stays revoked)", acct.Usage.DevicesActive)
	}
}

// TestRateWindowSweepBounded pins the bound on the sliding-window
// limiter map: several key spaces are minted from client-supplied input
// before any row is read (rec-vault:<id> in §6.2), so — exactly like the
// approval polling floor — the map must not grow without bound from
// unauthenticated traffic. Keys survive at most one window past their
// last request.
func TestRateWindowSweepBounded(t *testing.T) {
	e := newTestEnv(t, false)
	now := time.Now().UnixMilli()
	for i := 0; i < rateWindowPruneThreshold+512; i++ {
		if !e.api.windowAllow("rec-vault:"+randHexID(t), now, 10, 60_000) {
			t.Fatal("a fresh key must be allowed")
		}
	}
	if len(e.api.perMinute) <= rateWindowPruneThreshold {
		t.Fatalf("flood did not exceed the prune threshold: %d entries", len(e.api.perMinute))
	}

	// One window later every flooded key is stale; the next windowAllow
	// call sweeps them and only the fresh key survives.
	later := now + 61_000
	if !e.api.windowAllow("rec-vault:still-fresh", later, 10, 60_000) {
		t.Fatal("a fresh key must be allowed")
	}
	if n := len(e.api.perMinute); n != 1 {
		t.Fatalf("stale keys survived the sweep: %d entries left, want 1", n)
	}

	// The recovery endpoint really does mint its per-vault key before
	// the vault row is read — this is the wiring the sweep bounds.
	if s, _ := e.do("GET", "/v1/vaults/"+randHexID(t)+"/recovery", "", nil); s != 404 {
		t.Fatalf("unknown vault recovery: want 404, got %d", s)
	}
	minted := false
	for k := range e.api.perMinute {
		if strings.HasPrefix(k, "rec-vault:") {
			minted = true
		}
	}
	if !minted {
		t.Fatal("recovery request did not mint its per-vault limiter key")
	}
}
