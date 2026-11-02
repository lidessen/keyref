// Receiver-role tests (design v0.8 §14.4): push targeting follows the
// directory's primary receiver, and a directory carrying more than one
// primary is rejected.
package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/lidessen/keyref/proto/wire"
)

func TestPushTargetsPrimaryReceiver(t *testing.T) {
	f := newPushFixture(t)
	tok := token64(t)
	if s, _ := f.e.do("PUT", "/v1/devices/push-token", f.owner.token, wire.PushTokenRequest{Token: tok, Env: "sandbox"}); s != 204 {
		t.Fatalf("register: %d", s)
	}

	// A second owner with its own token. Under no-primary targeting both
	// devices would receive the push.
	owner2 := "26262626262626262626262626262626"
	if _, err := f.e.st.DB().Exec(`INSERT INTO devices (device_id, vault_id, kind, status, hpke_kem, hpke_public_key,
sign_alg, sign_public_key, label, created_at, revoked_at, push_token, receiver_role) VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?,0)`,
		owner2, f.owner.vaultID, "ios", "active", "P-256", []byte{1}, "ed25519", []byte{2}, "iPhone 2", int64(1), strings.Repeat("ef", 32)); err != nil {
		t.Fatal(err)
	}

	// The signed directory is the authority for the role; mirror it into
	// the column the push fan-out reads (the directory PUT already
	// persists it end to end — covered by the store round-trip).
	if _, err := f.e.st.DB().Exec(`UPDATE devices SET receiver_role = 1 WHERE device_id = ?`, f.owner.deviceID); err != nil {
		t.Fatal(err)
	}

	status, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000)
	if status != 201 {
		t.Fatalf("approval create: %d %s", status, raw)
	}
	calls := f.push.wait(t, 1)
	if calls[0].Token != tok {
		t.Fatalf("push went to %q, want the primary receiver %q", calls[0].Token, tok)
	}
	if f.push.count() != 1 {
		t.Fatalf("push count = %d, want 1 (primary only)", f.push.count())
	}

	// Without a primary token the fan-out falls back to every owner.
	if _, err := f.e.st.DB().Exec(`UPDATE devices SET push_token = NULL WHERE device_id = ?`, f.owner.deviceID); err != nil {
		t.Fatal(err)
	}
	status, _ = f.submit(t, []byte("ct2"), f.clock.t.UnixMilli()+60_000)
	if status != 201 {
		t.Fatalf("approval create 2: %d", status)
	}
	f.push.wait(t, 1)
	if toks := f.push.callsAfter(1); len(toks) != 1 || toks[0] != strings.Repeat("ef", 32) {
		t.Fatalf("fallback audience = %v, want owner2 only", toks)
	}
}

func TestDirectoryRejectsTwoPrimaries(t *testing.T) {
	f := newApprovalFixture(t)

	put := func(rev uint64, ownerRole uint8, extraIOS bool) (int, []byte) {
		owner := wire.DirectoryDevice{
			DeviceID: f.owner.deviceID, Kind: wire.DeviceKindIOS,
			Status: wire.DeviceStatusActive,
			HPKEKEM: wire.KEMP256, HPKEPublicKey: f.owner.hpkePub,
			SignAlg: wire.SignAlgECDSAP256, SignPublicKey: f.owner.signPub,
			GrantsDigest: wire.EmptyGrantsDigest(),
			ReceiverRole: ownerRole,
		}
		devices := []wire.DirectoryDevice{owner}
		if extraIOS {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pub := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
			devices = append(devices, wire.DirectoryDevice{
				DeviceID: "29292929292929292929292929292929", Kind: wire.DeviceKindIOS,
				Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMP256, HPKEPublicKey: pub,
				SignAlg: wire.SignAlgECDSAP256, SignPublicKey: pub,
				GrantsDigest: wire.EmptyGrantsDigest(),
				ReceiverRole: wire.ReceiverRolePrimary,
			})
		}
		b, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
			VaultID: f.owner.vaultID, DirectoryRevision: rev, Devices: devices,
		})
		if err != nil {
			t.Fatal(err)
		}
		sig, err := wire.SignOwnerECDSA(b, f.owner.signKey)
		if err != nil {
			t.Fatal(err)
		}
		return f.e.do("PUT", "/v1/directory", f.owner.token,
			wire.PutDirectoryRequest{DirectoryRevision: rev, DirectorySigned: b, Signature: sig})
	}

	if s, raw := put(2, wire.ReceiverRolePrimary, false); s != 200 {
		t.Fatalf("single primary rejected: %d %s", s, raw)
	}
	if s, raw := put(3, wire.ReceiverRolePrimary, true); s != 400 || !strings.Contains(string(raw), "invalid_receiver_role") {
		t.Fatalf("two primaries: %d %s, want 400 invalid_receiver_role", s, raw)
	}
}
