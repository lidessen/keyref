// Package pair implements `keyref pair`: device-key generation is in
// internal/device; this package builds the QR payload
// (docs/protocol.md §9.1), registers the pairing session, polls
// pair/status, verifies the owner's pairing signature and pins the
// owner signing key (design.md §8.1).
package pair

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/qr"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/store"
)

// KV keys for the pinned owner key and directory state.
const (
	KVOwnerSignPub    = "owner_sign_public_key"
	KVDirectorySigned = "directory_signed"
	KVDirectorySig    = "directory_signature"
	KVDirectoryRev    = "directory_revision"
	KVLastSync        = "last_sync_at"
)

// syncCursorKV is the sync cursor key stored by the syncing package.
const syncCursorKV = "cursor"

// Options controls one pairing run.
type Options struct {
	// Kind declares the device kind on the QR (protocol §9.1 `t`):
	// "cli" (default) or "decider" (design v0.8 §14.8). The owner's
	// confirmation copy and the pair/complete device.kind follow it, and
	// it is a field of the pairing confirmation MAC (§3.13).
	Kind         string
	Name         string        // proposed device label (≤32 bytes)
	PrintPayload bool          // also print the raw payload line for tests
	PollTimeout  time.Duration // total wait for the human
	PollInterval time.Duration // ≥2s per protocol rate limit
	Stdout       io.Writer
}

// Payload builds the QR payload
//
//	keyref://pair?v=1&k=<b64 X25519 pub>&s=<b64 ed25519 pub>&n=<hex nonce>
//	  &name=..&u=<origin>[&t=<kind>]&c=<b64 32B pairing secret>
//
// with RFC 3986 percent-encoding of the base64 and UTF-8 fields
// (docs/protocol.md §9.1). `c` is the pairing confirmation secret
// (§3.13, v2 D): it travels only inside the QR — never to the server —
// so the owner can compute the MAC and this device can tell a real
// completion from one the server made up.
func Payload(origin string, hpkePub, signPub []byte, nonceHex, name string,
	confirmSecret []byte, kind ...string) string {
	v := url.Values{}
	v.Set("v", "1")
	// t is optional and defaults to cli; emit it only when it says
	// something (old QR compatibility, protocol §9.1).
	if len(kind) > 0 && kind[0] != "" && kind[0] != "cli" {
		v.Set("t", kind[0])
	}
	v.Set("k", base64.StdEncoding.EncodeToString(hpkePub))
	v.Set("s", base64.StdEncoding.EncodeToString(signPub))
	v.Set("n", nonceHex)
	v.Set("name", name)
	v.Set("u", origin)
	v.Set("c", base64.StdEncoding.EncodeToString(confirmSecret))
	return "keyref://pair?" + v.Encode()
}

// Run performs the pairing flow. On success the vault/device ids, the
// pinned owner signing key, the directory and the initial grants are in
// the local store.
func Run(st *store.Store, cl *client.Client, id *device.Identity, opts Options) error {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if len(opts.Name) > wire.LabelNameMaxBytes {
		return fmt.Errorf("pair: name longer than %d bytes", wire.LabelNameMaxBytes)
	}
	if opts.PollTimeout == 0 {
		opts.PollTimeout = 10 * time.Minute
	}
	if opts.PollInterval < 2*time.Second {
		opts.PollInterval = 2 * time.Second
	}
	if opts.Kind == "" {
		opts.Kind = wire.DeviceKindCLI
	}

	nonce := make([]byte, wire.SizePairNonce)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("pair: nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	// The pairing confirmation secret (§3.13, v2 D): generated here,
	// printed only inside the QR payload, never sent to the server. The
	// owner computes the MAC with it at pair/complete; without the
	// secret a malicious server cannot fabricate a completion this
	// device would accept.
	confirmSecret := make([]byte, wire.SizePairConfirmKey)
	if _, err := rand.Read(confirmSecret); err != nil {
		return fmt.Errorf("pair: pairing secret: %w", err)
	}

	// Register: sign the §3.5 transcript over the raw nonce.
	tb, err := wire.BuildPairRegisterTranscript(nonce, opts.Name)
	if err != nil {
		return err
	}
	sig, err := wire.SignEd25519(tb, id.SignPrivate)
	if err != nil {
		return err
	}
	reg := &wire.PairRegisterRequest{
		Nonce:         nonceHex,
		HPKEKEM:       wire.KEMX25519,
		HPKEPublicKey: id.HPKEPublic,
		SignAlg:       wire.SignAlgEd25519,
		SignPublicKey: id.SignPublic,
		ProposedName:  opts.Name,
		Signature:     sig,
	}
	if err := cl.PairRegister(reg); err != nil {
		return fmt.Errorf("pair: register: %w", err)
	}

	origin := cl.Origin()
	payload := Payload(origin, id.HPKEPublic, id.SignPublic, nonceHex, opts.Name,
		confirmSecret, opts.Kind)
	if err := qr.Print(opts.Stdout, payload); err != nil {
		return err
	}
	// Human-verifiable fallback text (design.md §8.1 step 2).
	fmt.Fprintf(opts.Stdout, "origin: %s\n", origin)
	fmt.Fprintf(opts.Stdout, "fingerprint: %s\n", id.Fingerprint())
	if opts.PrintPayload {
		fmt.Fprintf(opts.Stdout, "payload: %s\n", payload)
		fmt.Fprintf(opts.Stdout, "nonce: %s\n", nonceHex)
	}

	deadline := time.Now().Add(opts.PollTimeout)
	for {
		status, err := cl.PairStatus(nonceHex)
		if err != nil {
			return fmt.Errorf("pair: status: %w", err)
		}
		switch status.Status {
		case "complete":
			return complete(st, cl, id, opts, nonceHex, status, confirmSecret)
		case "pending":
			// keep waiting
		default:
			return fmt.Errorf("pair: unexpected status %q", status.Status)
		}
		if time.Now().After(deadline) {
			return errors.New("pair: timed out waiting for approval")
		}
		time.Sleep(opts.PollInterval)
	}
}

func complete(st *store.Store, cl *client.Client, id *device.Identity, opts Options,
	nonceHex string, status *wire.PairStatusResponse, confirmSecret []byte) error {
	if len(status.OwnerSignPublicKey) == 0 || len(status.PairingSignature) == 0 {
		return errors.New("pair: incomplete pairing response")
	}
	// Verify the owner's signature over the §3.4 pair transcript. The
	// transcript binds vault, owner key, our nonce, our device id and
	// our public keys; the owner key is pinned from here on
	// (design.md §8.1 step 7).
	label := opts.Name
	pt := wire.PairTranscript{
		VaultID:            status.VaultID,
		OwnerSignPublicKey: status.OwnerSignPublicKey,
		Nonce:              nonceHex,
		DeviceID:           status.DeviceID,
		HPKEKEM:            wire.KEMX25519,
		HPKEPublicKey:      id.HPKEPublic,
		SignAlg:            wire.SignAlgEd25519,
		SignPublicKey:      id.SignPublic,
		Label:              label,
		Grants:             grantTranscripts(status.VaultID, status.DeviceID, status.Grants),
	}
	tb, err := wire.BuildPairTranscript(pt)
	if err != nil {
		return err
	}
	if err := wire.VerifyOwnerSignature(tb, status.PairingSignature, status.OwnerSignPublicKey); err != nil {
		return fmt.Errorf("pair: pairing signature verification failed")
	}
	// Pairing confirmation MAC (§3.13, v2 D), checked before the owner
	// key is pinned and before ANY local state is written: the signature
	// above proves the transcript is self-consistent, but a malicious
	// server can mint a fresh owner key and sign the transcript itself —
	// it saw the registered keys and knows the nonce hash. The MAC is
	// the one thing it cannot forge: the secret never left the QR code.
	if !wire.VerifyPairConfirmMAC(status.PairingMAC, confirmSecret, opts.Kind, tb) {
		return errors.New("pair: pairing confirmation MAC does not verify — " +
			"the completion may not come from the device that scanned the QR code")
	}
	if len(status.DirectorySigned) > 0 {
		if err := wire.VerifyOwnerSignature(status.DirectorySigned, status.DirectorySignature, status.OwnerSignPublicKey); err != nil {
			return fmt.Errorf("pair: directory signature verification failed")
		}
	}
	if !wire.ValidID(status.VaultID) || !wire.ValidID(status.DeviceID) {
		return errors.New("pair: malformed ids in pairing response")
	}

	// Persist: ids, pinned owner key, directory, initial grants.
	// A pairing can be into a NEW vault (e.g. re-pairing after a
	// recovery takeover, design §8.5): the previous vault's session
	// token, cached grants and sync cursor must not leak into it
	// (§6.5 local cleanup) — a stale token would authenticate this CLI
	// against the old vault and poison every later check.
	if err := st.DeleteKV(session.KVToken); err != nil {
		return err
	}
	if err := st.DeleteKV(session.KVExpiresAt); err != nil {
		return err
	}
	if err := st.DeleteKV(syncCursorKV); err != nil {
		return err
	}
	if err := st.ClearGrants(); err != nil {
		return err
	}
	if err := st.ClearItems(); err != nil {
		return err
	}
	kvs := []struct {
		k string
		v []byte
	}{
		{session.KVVaultID, []byte(status.VaultID)},
		{session.KVDeviceID, []byte(status.DeviceID)},
		{KVOwnerSignPub, status.OwnerSignPublicKey},
		{KVDirectorySigned, status.DirectorySigned},
		{KVDirectorySig, status.DirectorySignature},
	}
	for _, kv := range kvs {
		if err := st.SetKV(kv.k, kv.v); err != nil {
			return err
		}
	}
	if status.DirectoryRevision > 0 {
		if err := st.SetKV(KVDirectoryRev, []byte(fmt.Sprintf("%d", status.DirectoryRevision))); err != nil {
			return err
		}
	}
	for i := range status.Grants {
		g := status.Grants[i]
		if err := verifyAndStoreGrant(st, status.VaultID, status.OwnerSignPublicKey, &g); err != nil {
			return err
		}
	}
	fmt.Fprintf(opts.Stdout, "paired: vault %s device %s (%d grants)\n",
		shortID(status.VaultID), shortID(status.DeviceID), len(status.Grants))
	return nil
}

// verifyAndStoreGrant checks the owner signature before caching
// (design.md §9.1: clients verify before decrypting).
func verifyAndStoreGrant(st *store.Store, vaultID string, ownerPub []byte, g *wire.GrantData) error {
	if g.DeviceID == "" {
		return nil // grant rows must address a device; ignore malformed
	}
	if err := g.VerifyOwnerSignature(vaultID, ownerPub); err != nil {
		return fmt.Errorf("pair: grant signature verification failed")
	}
	return st.PutGrant(g)
}

func grantTranscripts(vaultID, deviceID string, grants []wire.GrantData) []wire.GrantTranscript {
	out := make([]wire.GrantTranscript, 0, len(grants))
	for _, g := range grants {
		if g.DeviceID == "" {
			g.DeviceID = deviceID
		}
		out = append(out, g.Transcript(vaultID))
	}
	return out
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return strings.ToLower(id[:4]) + "…" + id[len(id)-4:]
}
