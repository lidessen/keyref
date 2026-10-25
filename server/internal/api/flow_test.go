package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lidessen/keyref/proto/wire"
)

// TestFullFlowSelfHosted walks the ask's chain on an unlimited
// (self-hosted) server: create vault → pair CLI → session → items →
// grants with synthetic changes → sync visibility incl. revoked →
// recovery takeover.
func TestFullFlowSelfHosted(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	item1 := randHexID(t)
	item2 := randHexID(t)

	// --- items ---------------------------------------------------------
	if s := owner.putItem(t, item1, 1, []byte("meta-1"), []byte("secret-1")); s != 200 {
		t.Fatalf("put item rev1: %d", s)
	}
	if s := owner.putItem(t, item1, 1, []byte("meta-1b"), []byte("secret-1b")); s != 409 {
		t.Fatalf("put item replay: want 409, got %d", s)
	}
	if s := owner.putItem(t, item1, 2, []byte("meta-2"), []byte("secret-2")); s != 200 {
		t.Fatalf("put item rev2: %d", s)
	}
	if s := owner.putItem(t, item2, 1, []byte("meta-i2"), []byte("secret-i2")); s != 200 {
		t.Fatalf("put item2: %d", s)
	}

	// --- pairing -------------------------------------------------------
	cli := e.registerPair(t)
	var ps wire.PairStatusResponse
	if s := e.doOut("GET", "/v1/pair/status?nonce="+cli.nonce, "", nil, &ps); s != 200 || ps.Status != "pending" {
		t.Fatalf("pair status: %d %+v", s, ps)
	}
	viewGrant := owner.grant(t, cli.deviceID, item1, wire.GrantKindView, 1, 0)
	owner.completePair(t, cli, []wire.GrantData{viewGrant})
	if s := e.doOut("GET", "/v1/pair/status?nonce="+cli.nonce, "", nil, &ps); s != 200 || ps.Status != "complete" {
		t.Fatalf("pair status after complete: %d %+v", s, ps)
	}
	if !bytes.Equal(ps.OwnerSignPublicKey, owner.signPub) || len(ps.PairingSignature) == 0 {
		t.Fatal("pair status result missing owner key or signature")
	}
	cli.session(t)

	// --- CLI bootstrap: view grant only → meta, no secret, no wraps ----
	batch := e.sync(t, cli.token, 0)
	byEntity := changesByEntity(batch)
	if len(byEntity[wire.EntityDirectory]) != 1 {
		t.Fatalf("bootstrap directory changes = %d, want 1", len(byEntity[wire.EntityDirectory]))
	}
	dir := decodeDirectoryData(t, byEntity[wire.EntityDirectory][0])
	if dir.DirectoryRevision != 1 || len(dir.Signed) == 0 || len(dir.Signature) == 0 {
		t.Fatalf("bootstrap directory data: %+v", dir)
	}
	var itemChanges []wire.SyncChange
	for _, c := range byEntity[wire.EntityItem] {
		if d := decodeItemData(t, c); d.ItemID == item1 {
			itemChanges = append(itemChanges, c)
		}
	}
	if len(itemChanges) != 1 {
		t.Fatalf("bootstrap: item1 changes = %d, want 1", len(itemChanges))
	}
	d1 := decodeItemData(t, itemChanges[0])
	if len(d1.MetaCiphertext) == 0 || len(d1.SecretCiphertext) != 0 {
		t.Fatalf("view grant must expose meta only: %+v", d1)
	}
	if len(d1.VaultWrappedMetaKey) != 0 || len(d1.VaultWrappedItemKey) != 0 {
		t.Fatal("vault_wrapped_* leaked to CLI")
	}
	cursor := batch.Cursor

	// --- grant write appends synthetic item change (design §6.3) -------
	useGrant := owner.grant(t, cli.deviceID, item1, wire.GrantKindUse, 1, 1799999999999)
	var applied wire.PutGrantsResponse
	if s := e.doOut("PUT", "/v1/grants", owner.token, wire.PutGrantsRequest{Grants: []wire.GrantData{useGrant}}, &applied); s != 200 || applied.Applied != 1 {
		t.Fatalf("put grants: %d %+v", s, applied)
	}
	batch = e.sync(t, cli.token, cursor)
	byEntity = changesByEntity(batch)
	var sawUseGrant, sawSyntheticItem bool
	for _, c := range byEntity[wire.EntityGrant] {
		if g := decodeGrantData(t, c); g.Kind == wire.GrantKindUse && !g.Deleted {
			sawUseGrant = true
		}
	}
	for _, c := range byEntity[wire.EntityItem] {
		if d := decodeItemData(t, c); d.ItemID == item1 {
			sawSyntheticItem = true
		}
	}
	if !sawUseGrant || !sawSyntheticItem {
		t.Fatalf("grant write missed changes: use=%v synthetic=%v", sawUseGrant, sawSyntheticItem)
	}
	cursor = batch.Cursor

	// --- grants/self digest reconciliation (§6.14, §9.1) ---------------
	var self wire.GrantsSelfResponse
	if s := e.doOut("GET", "/v1/grants/self", cli.token, nil, &self); s != 200 {
		t.Fatalf("grants/self: %d", s)
	}
	if len(self.Grants) != 2 {
		t.Fatalf("grants/self rows = %d, want 2", len(self.Grants))
	}
	tbs := make([]wire.GrantTranscript, 0, len(self.Grants))
	for i := range self.Grants {
		tbs = append(tbs, self.Grants[i].Transcript(cli.vaultID))
	}
	wantDigest, err := wire.GrantsDigest(tbs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(self.GrantsDigest, wantDigest) {
		t.Fatal("grants/self digest mismatch")
	}
	if self.DirectoryRevision != 1 {
		t.Fatalf("grants/self directory_revision = %d", self.DirectoryRevision)
	}

	// --- single item fetch, role filtered (§6.9) ------------------------
	var cliItem wire.ItemData
	if s := e.doOut("GET", "/v1/items/"+item1, cli.token, nil, &cliItem); s != 200 {
		t.Fatalf("cli get item: %d", s)
	}
	if len(cliItem.SecretCiphertext) == 0 || len(cliItem.VaultWrappedMetaKey) != 0 {
		t.Fatalf("use grant must expose secret, never wraps: %+v", cliItem)
	}
	var ownerItem wire.ItemData
	if s := e.doOut("GET", "/v1/items/"+item1, owner.token, nil, &ownerItem); s != 200 {
		t.Fatalf("owner get item: %d", s)
	}
	if len(ownerItem.VaultWrappedItemKey) == 0 {
		t.Fatal("owner must see vault_wrapped_*")
	}
	// A CLI with no grant at all: forbidden.
	outsider := e.registerPair(t)
	owner.completePair(t, outsider, nil)
	outsider.session(t)
	if s, raw := e.do("GET", "/v1/items/"+item1, outsider.token, nil); s != 403 {
		t.Fatalf("no-grant item fetch: want 403, got %d %s", s, raw)
	}
	// CLI tokens cannot write items (§11).
	if s, raw := e.do("PUT", "/v1/items/"+item2, cli.token, wire.PutItemRequest{Revision: 2, WriterDeviceID: owner.deviceID}); s != 403 {
		t.Fatalf("cli put item: want 403, got %d %s", s, raw)
	}
	if s, raw := e.do("PUT", "/v1/directory", cli.token, wire.PutDirectoryRequest{DirectoryRevision: 9}); s != 403 {
		t.Fatalf("cli put directory: want 403, got %d %s", s, raw)
	}
	if s, raw := e.do("DELETE", "/v1/vaults/"+cli.vaultID, cli.token, nil); s != 403 {
		t.Fatalf("cli delete vault: want 403, got %d %s", s, raw)
	}

	// --- audit -----------------------------------------------------------
	if s, raw := e.do("POST", "/v1/audit", cli.token, wire.AuditRequest{Ciphertext: randBytes(t, 200)}); s != 201 {
		t.Fatalf("post audit: %d %s", s, raw)
	}
	var auditPage wire.AuditPageResponse
	if s := e.doOut("GET", "/v1/audit?cursor=0", owner.token, nil, &auditPage); s != 200 || len(auditPage.Events) != 1 {
		t.Fatalf("owner audit page: %d %+v", s, auditPage)
	}
	if auditPage.Events[0].DeviceID != cli.deviceID {
		t.Fatal("audit event device mismatch")
	}
	if s, _ := e.do("GET", "/v1/audit?cursor=0", cli.token, nil); s != 403 {
		t.Fatalf("cli audit read: want 403, got %d", s)
	}

	// --- grant deletion delivered to the device (§6.13, §10.6) ----------
	if s, raw := owner.deleteGrant(t, cli.deviceID, item1, wire.GrantKindView, 2); s != 204 {
		t.Fatalf("delete grant: %d %s", s, raw)
	}
	batch = e.sync(t, cli.token, cursor)
	var sawDeleted bool
	for _, c := range changesByEntity(batch)[wire.EntityGrant] {
		if g := decodeGrantData(t, c); g.Kind == wire.GrantKindView && g.Deleted && g.Revision == 2 {
			sawDeleted = true
		}
	}
	if !sawDeleted {
		t.Fatal("grant deletion not delivered")
	}
	cursor = batch.Cursor

	// --- item tombstone cascade (§6.11) ----------------------------------
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: owner.vaultID, ItemID: item1, Revision: 3, WriterDeviceID: owner.deviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	delSig, err := wire.SignOwnerECDSA(tb, owner.signKey)
	if err != nil {
		t.Fatal(err)
	}
	if s, raw := e.do("DELETE", "/v1/items/"+item1, owner.token, wire.DeleteItemRequest{Revision: 3, Signature: delSig}); s != 204 {
		t.Fatalf("delete item: %d %s", s, raw)
	}
	batch = e.sync(t, cli.token, cursor)
	byEntity = changesByEntity(batch)
	var sawTombstone, sawUseDeleted bool
	for _, c := range byEntity[wire.EntityItem] {
		if d := decodeItemData(t, c); d.ItemID == item1 && d.Tombstone {
			sawTombstone = true
		}
	}
	for _, c := range byEntity[wire.EntityGrant] {
		if g := decodeGrantData(t, c); g.Kind == wire.GrantKindUse && g.Deleted {
			sawUseDeleted = true
		}
	}
	if !sawTombstone || !sawUseDeleted {
		t.Fatalf("tombstone cascade: tombstone=%v useDeleted=%v", sawTombstone, sawUseDeleted)
	}
	cursor = batch.Cursor

	// --- revocation: delivery semantics (§8.4, §10.6) --------------------
	// Give the CLI a fresh use grant on item2, let it sync, then revoke
	// the device via a new directory.
	use2 := owner.grant(t, cli.deviceID, item2, wire.GrantKindUse, 1, 0)
	if s, _ := e.do("PUT", "/v1/grants", owner.token, wire.PutGrantsRequest{Grants: []wire.GrantData{use2}}); s != 200 {
		t.Fatalf("put grant item2: %d", s)
	}
	batch = e.sync(t, cli.token, cursor)
	cursor = batch.Cursor

	_, dirBytes := owner.directoryFor(t, 2, map[string]string{
		owner.deviceID: wire.DeviceStatusActive,
		cli.deviceID:   wire.DeviceStatusRevoked,
	})
	dirSig, err := wire.SignOwnerECDSA(dirBytes, owner.signKey)
	if err != nil {
		t.Fatal(err)
	}
	var dirResp wire.PutDirectoryResponse
	if s := e.doOut("PUT", "/v1/directory", owner.token, wire.PutDirectoryRequest{
		DirectoryRevision: 2, DirectorySigned: dirBytes, Signature: dirSig,
	}, &dirResp); s != 200 {
		t.Fatalf("put directory: status %d", s)
	}

	// Revoked: every non-sync endpoint is device_revoked (§8.4).
	if s, raw := e.do("GET", "/v1/account", cli.token, nil); s != 403 {
		t.Fatalf("revoked account: want 403, got %d %s", s, raw)
	}
	if s, raw := e.do("GET", "/v1/items/"+item2, cli.token, nil); s != 403 {
		t.Fatalf("revoked item fetch: want 403, got %d %s", s, raw)
	}
	// Revoked devices get no new tokens (§6.7).
	var chal wire.SessionChallengeResponse
	if s := e.doOut("POST", "/v1/session", "", wire.SessionRequest{DeviceID: cli.deviceID}, &chal); s != 403 {
		t.Fatalf("revoked session: want 403, got %d", s)
	}

	// The revoked session keeps sync access — that is the delivery
	// channel for the revocation itself (§8.4).
	batch = e.sync(t, cli.token, cursor)
	byEntity = changesByEntity(batch)
	if len(byEntity[wire.EntityDirectory]) != 1 {
		t.Fatalf("revoked sync must see the directory change, got %v", byEntity)
	}
	for _, c := range byEntity[wire.EntityItem] {
		t.Fatalf("revoked sync must not see item changes: %+v", c)
	}
	for _, c := range byEntity[wire.EntityGrant] {
		if g := decodeGrantData(t, c); !g.Deleted {
			t.Fatalf("revoked sync must only see grant deletions: %+v", g)
		}
	}

	// Grant deletion after revocation is still delivered (§8.4).
	if s, raw := owner.deleteGrant(t, cli.deviceID, item2, wire.GrantKindUse, 2); s != 204 {
		t.Fatalf("delete revoked grant: %d %s", s, raw)
	}
	batch = e.sync(t, cli.token, batch.Cursor)
	var sawRevokedDeletion bool
	for _, c := range changesByEntity(batch)[wire.EntityGrant] {
		if g := decodeGrantData(t, c); g.Deleted && g.DeviceID == cli.deviceID {
			sawRevokedDeletion = true
		}
	}
	if !sawRevokedDeletion {
		t.Fatal("grant deletion not delivered to revoked device")
	}

	// --- cursor_stale (§8.1) ----------------------------------------------
	if _, err := e.st.DB().Exec("DELETE FROM changes WHERE seq <= ?", cursor); err != nil {
		t.Fatal(err)
	}
	if s, raw := e.do("GET", "/v1/sync?cursor=1", owner.token, nil); s != 409 {
		t.Fatalf("cursor_stale: want 409, got %d %s", s, raw)
	}
	// Bootstrap still works and re-establishes the cursor.
	boot := e.sync(t, owner.token, 0)
	if len(changesByEntity(boot)[wire.EntityDirectory]) != 1 {
		t.Fatal("owner bootstrap missing directory")
	}

	var rec wire.RecoveryMaterialsResponse
	if s := e.doOut("GET", "/v1/vaults/"+owner.vaultID+"/recovery", "", nil, &rec); s != 200 {
		t.Fatalf("recovery materials: %d", s)
	}
	if rec.DirectoryRevision != 2 || !bytes.Equal(rec.RecoverySignPub, owner.recPub) {
		t.Fatalf("recovery materials mismatch: %+v", rec)
	}

	// --- recovery takeover (§6.3, §7.3) -------------------------------------
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub, err := wire.EncodeP256PublicKey(&newKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	takeoverDir, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: owner.vaultID, DirectoryRevision: 3,
		Devices: []wire.DirectoryDevice{
			{
				DeviceID: randHexID(t), Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMP256, HPKEPublicKey: append([]byte{0x04}, randBytes(t, 64)...),
				SignAlg: wire.SignAlgECDSAP256, SignPublicKey: newPub,
				GrantsDigest: wire.EmptyGrantsDigest(),
			},
			{
				DeviceID: owner.deviceID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusRevoked,
				HPKEKEM: wire.KEMP256, HPKEPublicKey: owner.hpkePub,
				SignAlg: wire.SignAlgECDSAP256, SignPublicKey: owner.signPub,
				GrantsDigest: wire.EmptyGrantsDigest(),
			},
			{
				DeviceID: cli.deviceID, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusRevoked,
				HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli.hpkePub,
				SignAlg: wire.SignAlgEd25519, SignPublicKey: cli.signPub,
				GrantsDigest: wire.EmptyGrantsDigest(),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	recSig, err := wire.SignEd25519(takeoverDir, owner.recPriv)
	if err != nil {
		t.Fatal(err)
	}
	ownerSig, err := wire.SignOwnerECDSA(takeoverDir, newKey)
	if err != nil {
		t.Fatal(err)
	}
	var takeover wire.SessionResponse
	if s := e.doOut("POST", "/v1/recovery/directory", "", wire.RecoveryDirectoryRequest{
		VaultID: owner.vaultID, DirectoryRevision: 3, DirectorySigned: takeoverDir,
		RecoverySignature: recSig, OwnerSignature: ownerSig,
	}, &takeover); s != 200 {
		t.Fatalf("takeover: status %d", s)
	}
	if takeover.Token == "" {
		t.Fatal("takeover did not issue a session")
	}
	// The old owner's session was killed with the takeover.
	if s, _ := e.do("GET", "/v1/account", owner.token, nil); s != 401 {
		t.Fatalf("old owner session survived takeover: %d", s)
	}
	// The new owner can work.
	var acct wire.AccountResponse
	if s := e.doOut("GET", "/v1/account", takeover.Token, nil, &acct); s != 200 {
		t.Fatalf("new owner account: %d", s)
	}
	if !e.enforce && acct.Plan != "unlimited" {
		t.Fatalf("self-hosted account plan = %q", acct.Plan)
	}

	// --- replace recovery material (§6.4) ------------------------------------
	newSeed := randBytes(t, 32)
	newRecPriv, newRecPub := recoveryKeys(t, newSeed)
	newWrap := randBytes(t, 60)
	kdfJSON := `{"v":1,"kdf":"hkdf-sha256","salt":"","kek_info":"recovery-kek","sign_info":"recovery-sign"}`
	recTB, err := wire.BuildVaultRecoveryTranscript(owner.vaultID, newWrap, kdfJSON, newRecPub)
	if err != nil {
		t.Fatal(err)
	}
	recRepSig, err := wire.SignOwnerECDSA(recTB, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if s, raw := e.do("PUT", "/v1/vault/recovery", takeover.Token, wire.PutVaultRecoveryRequest{
		RecoveryWrap: newWrap, RecoveryKDFJSON: kdfJSON, RecoverySignPub: newRecPub, Signature: recRepSig,
	}); s != 204 {
		t.Fatalf("put vault recovery: %d %s", s, raw)
	}
	var recAfter wire.RecoveryMaterialsResponse
	if s := e.doOut("GET", "/v1/vaults/"+owner.vaultID+"/recovery", "", nil, &recAfter); s != 200 {
		t.Fatalf("recovery materials after replace: %d", s)
	}
	if !bytes.Equal(recAfter.RecoverySignPub, newRecPub) {
		t.Fatal("recovery sign pub not replaced")
	}
	_ = newRecPriv
}

// --- smaller endpoint tests -------------------------------------------

func TestHealthz(t *testing.T) {
	e := newTestEnv(t, false)
	status, raw := e.do("GET", "/v1/healthz", "", nil)
	if status != 200 {
		t.Fatalf("healthz: %d", status)
	}
	var h struct {
		Status     string `json:"status"`
		Version    string `json:"version"`
		DBWritable bool   `json:"db_writable"`
		TLS        struct {
			Mode string `json:"mode"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if h.Status != "ok" || !h.DBWritable || h.Version != "test" || h.TLS.Mode != "plain" {
		t.Fatalf("healthz payload: %s", raw)
	}
}

func TestBodyLimitsAndStrictJSON(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	itemID := randHexID(t)

	// Item path ceiling: 256 KiB (§1.2).
	big := make([]byte, 300<<10)
	if s, raw := e.do("PUT", "/v1/items/"+itemID, owner.token, map[string]any{
		"revision": 1, "writer_device_id": owner.deviceID, "meta_ciphertext": big,
	}); s != 413 {
		t.Fatalf("oversized item: want 413, got %d %s", s, raw)
	}
	// Audit path ceiling: 4 KiB.
	if s, raw := e.do("POST", "/v1/audit", owner.token, wire.AuditRequest{Ciphertext: make([]byte, 5<<10)}); s != 413 {
		t.Fatalf("oversized audit: want 413, got %d %s", s, raw)
	}
	// Unknown fields rejected (§1.2).
	if s, raw := e.do("PUT", "/v1/items/"+itemID, owner.token, map[string]any{
		"revision": 1, "writer_device_id": owner.deviceID, "ref": "openai-prod",
	}); s != 400 {
		t.Fatalf("unknown field: want 400, got %d %s", s, raw)
	}
	// Broken JSON → invalid_json.
	req, _ := http.NewRequest("PUT", e.ts.URL+"/v1/items/"+itemID, bytes.NewReader([]byte("{nope")))
	req.Header.Set("Authorization", "Bearer "+owner.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var e2 struct {
		Error string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&e2)
	resp.Body.Close()
	if resp.StatusCode != 400 || e2.Error != "invalid_json" {
		t.Fatalf("broken json: %d %s", resp.StatusCode, e2.Error)
	}
	// Bad bearer token.
	if s, raw := e.do("GET", "/v1/sync?cursor=0", "deadbeef", nil); s != 401 {
		t.Fatalf("bad token: want 401, got %d %s", s, raw)
	}
}

func TestPairExpiryAndMismatch(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	cli := e.registerPair(t)

	// Unknown nonce → pair_expired, same code as expired (§6.18).
	if s, raw := e.do("GET", "/v1/pair/status?nonce="+randHexID(t), "", nil); s != 410 {
		t.Fatalf("unknown nonce: want 410, got %d %s", s, raw)
	}
	// Complete with a mismatched device key → bad_signature (§6.17).
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	g := owner.grant(t, cli.deviceID, randHexID(t), wire.GrantKindView, 1, 0)
	pairTB, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID: owner.vaultID, OwnerSignPublicKey: owner.signPub,
		Nonce: cli.nonce, DeviceID: cli.deviceID,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli.hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: cli.signPub,
		Label: "build-agent-1", Grants: []wire.GrantTranscript{g.Transcript(owner.vaultID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := wire.SignOwnerECDSA(pairTB, owner.signKey)
	status, raw := e.do("POST", "/v1/pair/complete", owner.token, wire.PairCompleteRequest{
		Nonce: cli.nonce,
		Device: wire.DeviceInput{
			DeviceID: cli.deviceID, Kind: wire.DeviceKindCLI,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: wire.Blob(otherPub), // not the registered key
			SignAlg: wire.SignAlgEd25519, SignPublicKey: cli.signPub, Label: "x",
		},
		Signature: sig,
	})
	if status != 403 {
		t.Fatalf("key mismatch: want 403, got %d %s", status, raw)
	}
}

func TestApprovalStubAndPollFloor(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	approvalID := "abcdef0123456789abcdef0123456789"

	// Unauthenticated polls never reach the limiter: they fail
	// authorization first, and forged tokens cannot mint limiter keys.
	if s, raw := e.do("GET", "/v1/approvals/"+approvalID, "", nil); s != 401 {
		t.Fatalf("unauthenticated approval poll: want 401, got %d %s", s, raw)
	}

	// The forged-token rotation exploit: ten rapid polls with ten fresh
	// forged tokens must all fail authorization and leave the polling
	// limiter map untouched — no per-token entries, no growth.
	before := len(e.api.pollLast)
	for i := 0; i < 10; i++ {
		forged := hex.EncodeToString(randBytes(t, 32))
		if s, _ := e.do("GET", "/v1/approvals/"+approvalID, forged, nil); s != 401 {
			t.Fatalf("forged poll %d: want 401, got %d", i, s)
		}
	}
	if len(e.api.pollLast) != before {
		t.Fatalf("forged tokens minted limiter keys: %d -> %d", before, len(e.api.pollLast))
	}

	// Ten rapid authenticated polls: exactly the first reaches the stub
	// (404, approval flow is Phase 2), the remaining nine hit the 2s
	// floor (protocol §1.3, §6.22).
	allowed, limited := 0, 0
	for i := 0; i < 10; i++ {
		s, _ := e.do("GET", "/v1/approvals/"+approvalID, owner.token, nil)
		switch s {
		case 404:
			allowed++
		case 429:
			limited++
		default:
			t.Fatalf("rapid poll %d: unexpected status %d", i, s)
		}
	}
	if allowed != 1 || limited != 9 {
		t.Fatalf("rapid poll burst: allowed=%d limited=%d, want 1/9", allowed, limited)
	}

	if s, raw := e.do("POST", "/v1/billing/apple", "", map[string]any{"transaction_id": "x"}); s != 404 {
		t.Fatalf("billing stub: want 404, got %d %s", s, raw)
	}
}

func TestDeleteVaultTwoStep(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)

	// Step one: challenge required (§6.5, D10).
	var chal struct {
		Error     string    `json:"error"`
		Challenge wire.Blob `json:"challenge"`
	}
	status, raw := e.do("DELETE", "/v1/vaults/"+owner.vaultID, owner.token, nil)
	if status != 401 {
		t.Fatalf("delete step 1: want 401, got %d %s", status, raw)
	}
	if err := json.Unmarshal(raw, &chal); err != nil || chal.Error != "delete_challenge_required" || len(chal.Challenge) != 32 {
		t.Fatalf("delete challenge payload: %s", raw)
	}
	// Step two with a wrong signature → bad_signature.
	tb, _ := wire.BuildVaultDeleteTranscript(owner.vaultID, chal.Challenge)
	badSig := randBytes(t, 70)
	if s, raw := e.do("DELETE", "/v1/vaults/"+owner.vaultID, owner.token, wire.DeleteVaultRequest{
		Challenge: &chal.Challenge, Signature: blobPtr(badSig),
	}); s != 403 {
		t.Fatalf("delete step 2 bad sig: want 403, got %d %s", s, raw)
	}
	// The consumed challenge cannot be retried → unauthorized.
	good, _ := wire.SignOwnerECDSA(tb, owner.signKey)
	if s, raw := e.do("DELETE", "/v1/vaults/"+owner.vaultID, owner.token, wire.DeleteVaultRequest{
		Challenge: &chal.Challenge, Signature: blobPtr(good),
	}); s != 401 {
		t.Fatalf("challenge reuse: want 401, got %d %s", s, raw)
	}

	// Fresh challenge, correct flow.
	status, raw = e.do("DELETE", "/v1/vaults/"+owner.vaultID, owner.token, nil)
	json.Unmarshal(raw, &chal)
	tb, _ = wire.BuildVaultDeleteTranscript(owner.vaultID, chal.Challenge)
	sig2, _ := wire.SignOwnerECDSA(tb, owner.signKey)
	if s, raw := e.do("DELETE", "/v1/vaults/"+owner.vaultID, owner.token, wire.DeleteVaultRequest{
		Challenge: &chal.Challenge, Signature: blobPtr(sig2),
	}); s != 204 {
		t.Fatalf("delete step 2: want 204, got %d %s", s, raw)
	}
	if s, _ := e.do("GET", "/v1/account", owner.token, nil); s != 401 {
		t.Fatal("session survived vault deletion")
	}
	if s, _ := e.do("GET", "/v1/vaults/"+owner.vaultID+"/recovery", "", nil); s != 404 {
		t.Fatal("vault still resolvable after deletion")
	}
}
