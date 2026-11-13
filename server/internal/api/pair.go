package api

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/quotas"
	"github.com/lidessen/keyref/server/internal/store"
)

// PairSessionTTL is the validity of a pairing registration
// (protocol §6.16: 10 minutes, one-shot).
const PairSessionTTL = 10 * time.Minute

// handlePairRegister implements POST /v1/pair/register (protocol §6.16).
// Unauthenticated — the 16-byte nonce is the credential (decision D14) —
// and IP rate limited. Only the nonce hash reaches the database.
func (s *Server) handlePairRegister(w http.ResponseWriter, r *http.Request) {
	now := s.cfg.Now()
	limit := int64(PairRegisterPerIPPerMinute)
	if s.cfg.PairRegisterPerMinute > 0 {
		limit = int64(s.cfg.PairRegisterPerMinute)
	}
	if !s.windowAllow("pair:"+clientIPKey(r), now.UnixMilli(), limit, 60_000) {
		writeError(w, "rate_limited")
		return
	}
	var req wire.PairRegisterRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil || len(nonce) != wire.SizePairNonce {
		writeError(w, "invalid_field")
		return
	}
	if err := validateDeviceInput(&wire.DeviceInput{
		Kind: wire.DeviceKindCLI, HPKEKEM: req.HPKEKEM, HPKEPublicKey: req.HPKEPublicKey,
		SignAlg: req.SignAlg, SignPublicKey: req.SignPublicKey, Label: req.ProposedName,
	}); err != nil {
		writeError(w, "invalid_field")
		return
	}
	// CLI pairing keys are X25519 + Ed25519 (design §9.1).
	if req.HPKEKEM != wire.KEMX25519 || req.SignAlg != wire.SignAlgEd25519 {
		writeError(w, "invalid_field")
		return
	}
	tb, err := wire.BuildPairRegisterTranscript(nonce, req.ProposedName)
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if err := wire.VerifyCLISignature(tb, req.Signature, req.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}
	sum := sha256.Sum256(nonce)
	ps := &store.PairSession{
		NonceHash:     hex.EncodeToString(sum[:]),
		HPKEPublicKey: req.HPKEPublicKey,
		SignPublicKey: req.SignPublicKey,
		ProposedName:  req.ProposedName,
		ExpiresAt:     now.Add(PairSessionTTL).UnixMilli(),
	}
	// Drop long-dead registrations so the table stays bounded.
	_ = s.st.DeleteExpiredPairSessions(r.Context(), now.Add(-time.Hour).UnixMilli())
	if err := s.st.PutPairSession(r.Context(), ps); errors.Is(err, store.ErrPairConsumed) {
		// A nonce is one-shot: re-registering a used one answers like any
		// other dead pairing (§6.18).
		writeError(w, "pair_expired")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	writeJSON(w, http.StatusCreated, wire.PairRegisterResponse{ExpiresAt: ps.ExpiresAt})
}

func validateDeviceInput(d *wire.DeviceInput) error {
	if d.HPKEKEM != wire.KEMX25519 && d.HPKEKEM != wire.KEMP256 {
		return errInvalidField
	}
	wantKEM := map[string]int{wire.KEMX25519: wire.SizeX25519Key, wire.KEMP256: wire.SizeP256Key}[d.HPKEKEM]
	if len(d.HPKEPublicKey) != wantKEM {
		return errInvalidField
	}
	if d.SignAlg != wire.SignAlgEd25519 && d.SignAlg != wire.SignAlgECDSAP256 {
		return errInvalidField
	}
	wantSign := map[string]int{wire.SignAlgEd25519: wire.SizeEd25519Key, wire.SignAlgECDSAP256: wire.SizeP256Key}[d.SignAlg]
	if len(d.SignPublicKey) != wantSign {
		return errInvalidField
	}
	if len(d.RenewalSignPublicKey) != 0 && len(d.RenewalSignPublicKey) != wire.SizeEd25519Key {
		return errInvalidField
	}
	if len(d.Label) > wire.LabelNameMaxBytes {
		return errInvalidField
	}
	return nil
}

// handlePairComplete implements POST /v1/pair/complete (protocol §6.17).
// The owner rebuilds the §3.4 pair transcript from the structured
// request and verifies its own signature over the rebuilt bytes; the
// initial grants ride inside the transcript as full §3.2 grant
// transcripts. The grant set is whatever the human selected on the phone
// — empty until then (design §15).
func (s *Server) handlePairComplete(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	now := s.cfg.Now()
	if code := s.gateWrite(ac, false); code != "" {
		writeError(w, code)
		return
	}
	var req wire.PairCompleteRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil || len(nonce) != wire.SizePairNonce || !wire.ValidID(req.Device.DeviceID) {
		writeError(w, "invalid_field")
		return
	}
	// Pairing admits cli devices (§6.17) plus the v0.8 kinds (design
	// §14.2/§14.8): source collectors and deciders never carry grants.
	switch req.Device.Kind {
	case wire.DeviceKindCLI, wire.DeviceKindSource, wire.DeviceKindDecider:
	default:
		writeError(w, "invalid_field")
		return
	}
	if req.Device.Kind != wire.DeviceKindCLI && len(req.Grants) > 0 {
		writeError(w, "invalid_field") // source/decider hold no grants, ever
		return
	}
	if err := validateDeviceInput(&req.Device); err != nil {
		writeError(w, "invalid_field")
		return
	}
	if req.Device.HPKEKEM != wire.KEMX25519 || req.Device.SignAlg != wire.SignAlgEd25519 {
		writeError(w, "invalid_field")
		return
	}
	// The §3.13 pairing confirmation MAC is a required field (v2 D): the
	// server stores it opaquely and hands it back through pair/status,
	// where the paired device re-computes it from the QR secret the
	// server never saw. Size is all the server can check.
	if len(req.PairingMAC) != wire.SizePairConfirmKey {
		writeError(w, "invalid_field")
		return
	}
	sum := sha256.Sum256(nonce)
	ps, err := s.st.GetPairSession(r.Context(), hex.EncodeToString(sum[:]))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, "pair_expired") // unknown nonce is indistinguishable (§6.18)
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	if ps.ConsumedAt.Valid || now.UnixMilli() > ps.ExpiresAt {
		writeError(w, "pair_expired")
		return
	}
	if !bytes.Equal(ps.HPKEPublicKey, req.Device.HPKEPublicKey) ||
		!bytes.Equal(ps.SignPublicKey, req.Device.SignPublicKey) {
		writeError(w, "bad_signature") // registered keys do not match (§6.17)
		return
	}

	// Plan device ceiling (design §10.5) before admitting the device.
	// Each kind draws from its own tier bucket (design §14.7).
	if s.cfg.EnforceQuotas {
		plan := quotas.EffectivePlan(ac.vault, now.UnixMilli())
		if plan != quotas.PlanUnlimited {
			limits := s.quota.LimitsFor(plan)
			var ceiling *int64
			switch req.Device.Kind {
			case wire.DeviceKindCLI:
				ceiling = limits.DevicesCLI
			case wire.DeviceKindSource:
				ceiling = limits.DevicesSource
			case wire.DeviceKindDecider:
				ceiling = limits.DevicesDecider
			}
			if ceiling != nil {
				n, err := s.st.CountActiveDevices(r.Context(), ac.vault.ID, req.Device.Kind)
				if err == nil && n >= *ceiling {
					writeError(w, "quota_exceeded")
					return
				}
			}
		}
	}

	// Rebuild grant transcripts with the new device id and verify each
	// grant signature, then the pair transcript itself.
	grants := make([]wire.GrantTranscript, 0, len(req.Grants))
	for i := range req.Grants {
		g := &req.Grants[i]
		g.DeviceID = req.Device.DeviceID
		if err := g.Validate(); err != nil {
			writeError(w, "invalid_field")
			return
		}
		if len(g.HPKEEnc) == 0 {
			writeError(w, "invalid_field") // pair grants are never deletions
			return
		}
		item, err := s.st.GetItem(r.Context(), ac.vault.ID, g.ItemID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && item.Tombstone) {
			writeError(w, "invalid_field")
			return
		} else if err != nil {
			writeError(w, "internal")
			return
		}
		// Storage-class invariant (design §6.6, v0.7): pairing grants
		// obey the same mutual exclusion as PUT /v1/grants — a local item
		// (SQL NULL secret_ciphertext) never takes a use grant.
		if g.Kind == wire.GrantKindUse && len(item.SecretCiphertext) == 0 {
			writeError(w, "local_item_grant_conflict")
			return
		}
		if err := g.VerifyOwnerSignature(ac.vault.ID, ac.device.SignPublicKey); err != nil {
			writeError(w, "bad_signature")
			return
		}
		grants = append(grants, g.Transcript(ac.vault.ID))
	}
	pairTB, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID:            ac.vault.ID,
		OwnerSignPublicKey: ac.device.SignPublicKey,
		Nonce:              req.Nonce,
		DeviceID:           req.Device.DeviceID,
		HPKEKEM:            req.Device.HPKEKEM,
		HPKEPublicKey:      req.Device.HPKEPublicKey,
		SignAlg:            req.Device.SignAlg,
		SignPublicKey:      req.Device.SignPublicKey,
		Label:              req.Device.Label,
		Grants:             grants,
	})
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if err := wire.VerifyOwnerSignature(pairTB, req.Signature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}

	// Persist: device row, grants with their own change entries plus
	// synthetic item changes (§6.3), consumed pair session, and the
	// §6.18 result document for pair/status.
	result := wire.PairStatusResponse{
		Status:             "complete",
		VaultID:            ac.vault.ID,
		DeviceID:           req.Device.DeviceID,
		OwnerSignPublicKey: ac.device.SignPublicKey,
		PairingSignature:   req.Signature,
		PairingMAC:         req.PairingMAC,
		DirectoryRevision:  uint64(ac.vault.DirectoryRevision),
		DirectorySigned:    ac.vault.DirectorySigned,
		DirectorySignature: ac.vault.DirectorySignature,
		Grants:             req.Grants,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		writeError(w, "internal")
		return
	}
	device := &store.Device{
		ID: req.Device.DeviceID, VaultID: ac.vault.ID, Kind: req.Device.Kind,
		Status:  wire.DeviceStatusActive,
		HPKEKEM: req.Device.HPKEKEM, HPKEPublicKey: req.Device.HPKEPublicKey,
		SignAlg: req.Device.SignAlg, SignPublicKey: req.Device.SignPublicKey,
		Label:     pickLabel(req.Device.Label, ps.ProposedName),
		CreatedAt: now.UnixMilli(),
	}
	storeGrants := make([]store.Grant, 0, len(req.Grants))
	for i := range req.Grants {
		g := &req.Grants[i]
		storeGrants = append(storeGrants, store.Grant{
			VaultID: ac.vault.ID, DeviceID: req.Device.DeviceID, ItemID: g.ItemID,
			Kind: g.Kind, HPKEEnc: g.HPKEEnc, WrappedKey: g.WrappedKey,
			ExpiresAt: expiresOrNull(g.ExpiresAt), Revision: int64(g.Revision),
			Signature: g.Signature,
		})
	}
	if err := s.st.CompletePairing(r.Context(), device, storeGrants,
		ps.NonceHash, string(resultJSON), now.UnixMilli()); err != nil {
		if errors.Is(err, store.ErrPairConsumed) {
			// Lost the consume race against a concurrent complete with the
			// same nonce: indistinguishable from expired (§6.18).
			writeError(w, "pair_expired")
			return
		}
		writeError(w, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func pickLabel(label, proposed string) string {
	if label != "" {
		return label
	}
	return proposed
}

// expiresOrNull converts the wire convention (0 = never) into the
// nullable column value.
func expiresOrNull(ms int64) sql.NullInt64 {
	if ms == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: ms, Valid: true}
}

// handlePairStatus implements GET /v1/pair/status (protocol §6.18).
// Unauthenticated; unknown, expired and consumed-and-expired nonces all
// answer pair_expired with the same code (§6.18).
func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	nonceHex := r.URL.Query().Get("nonce")
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != wire.SizePairNonce {
		writeError(w, "invalid_field")
		return
	}
	sum := sha256.Sum256(nonce)
	ps, err := s.st.GetPairSession(r.Context(), hex.EncodeToString(sum[:]))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, "pair_expired")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	now := s.cfg.Now()
	if now.UnixMilli() > ps.ExpiresAt {
		writeError(w, "pair_expired")
		return
	}
	if !ps.ConsumedAt.Valid || !ps.ResultJSON.Valid {
		writeJSON(w, http.StatusOK, wire.PairStatusResponse{Status: "pending"})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(ps.ResultJSON.String))
}
