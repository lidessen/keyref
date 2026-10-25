package api

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/quotas"
	"github.com/lidessen/keyref/server/internal/store"
)

// handleCreateVault implements POST /v1/vaults (protocol §6.1). The
// client-supplied plan is ignored: hosted writes free, self-hosted
// unlimited (design §6.3).
func (s *Server) handleCreateVault(w http.ResponseWriter, r *http.Request) {
	now := s.cfg.Now()
	ctx := r.Context()

	var req wire.CreateVaultRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}

	if s.cfg.EnforceQuotas {
		// PoW first (protocol §10.1), then the global free-tier budget
		// (design §10.5 item 2). The per-IP creation budget is only
		// spent on successful creates below (item 9 counts vaults
		// created, not attempts).
		if req.PoW == nil {
			challenge, expires := s.pow.Issue()
			writeError(w, "pow_required", map[string]any{
				"challenge":  challenge,
				"expires_at": expires,
			})
			return
		}
		vaultRaw, err := hex.DecodeString(req.VaultID)
		if err != nil || !wire.ValidID(req.VaultID) {
			writeError(w, "invalid_field")
			return
		}
		if !s.pow.Verify(string(req.PoW.Challenge), req.PoW.Nonce, vaultRaw) {
			writeError(w, "invalid_field")
			return
		}
		storage, requests, err := s.quota.BudgetUsage(ctx, now)
		if err == nil && (storage >= s.quota.GlobalStorageBytes || requests >= s.quota.GlobalDailyRequests) {
			writeError(w, "quota_exceeded")
			return
		}
	}

	if err := validateCreateVault(&req); err != nil {
		writeError(w, "invalid_field")
		return
	}

	// Rebuild the creation directory from the structured device fields
	// and compare with the submitted transcript bytes (protocol §1.5/D3):
	// a new vault has exactly one device and no grants, so the record's
	// grants digest is the SHA-256 of the empty concatenation.
	rebuilt, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID:           req.VaultID,
		DirectoryRevision: req.DirectoryRevision,
		Devices: []wire.DirectoryDevice{{
			DeviceID:             req.Device.DeviceID,
			Kind:                 req.Device.Kind,
			Status:               wire.DeviceStatusActive,
			HPKEKEM:              req.Device.HPKEKEM,
			HPKEPublicKey:        req.Device.HPKEPublicKey,
			SignAlg:              req.Device.SignAlg,
			SignPublicKey:        req.Device.SignPublicKey,
			RenewalSignPublicKey: req.Device.RenewalSignPublicKey,
			GrantsDigest:         wire.EmptyGrantsDigest(),
		}},
	})
	if err != nil || !bytes.Equal(rebuilt, req.DirectorySigned) {
		writeError(w, "invalid_field")
		return
	}
	if err := wire.VerifyOwnerSignature(rebuilt, req.Signature, req.Device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}

	if _, err := s.st.GetVault(ctx, req.VaultID); err == nil {
		writeError(w, "invalid_field") // vault id already taken
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeError(w, "internal")
		return
	}
	if s.cfg.EnforceQuotas {
		// Per-IP creation budget, charged only on success path
		// (design §10.5 item 9).
		ipKey := clientIPKey(r)
		day := now.UTC().Format("2006-01-02")
		if !s.windowAllow("reg:"+ipKey+":"+day, now.UnixMilli(), s.quota.RegistrationPerIPPerDay, 24*3600*1000) {
			writeError(w, "rate_limited")
			return
		}
	}

	plan := quotas.PlanUnlimited
	if s.cfg.EnforceQuotas {
		plan = quotas.PlanFree
	}
	vault := &store.Vault{
		ID:                 req.VaultID,
		CreatedAt:          now.UnixMilli(),
		RecoveryWrap:       req.RecoveryWrap,
		RecoveryKDFJSON:    req.RecoveryKDFJSON,
		RecoverySignPub:    req.RecoverySignPub,
		DirectoryRevision:  int64(req.DirectoryRevision),
		DirectorySigned:    req.DirectorySigned,
		DirectorySignature: req.Signature,
		Plan:               plan,
	}
	device := &store.Device{
		ID:            req.Device.DeviceID,
		VaultID:       req.VaultID,
		Kind:          req.Device.Kind,
		Status:        wire.DeviceStatusActive,
		HPKEKEM:       req.Device.HPKEKEM,
		HPKEPublicKey: req.Device.HPKEPublicKey,
		SignAlg:       req.Device.SignAlg,
		SignPublicKey: req.Device.SignPublicKey,
		Label:         req.Device.Label,
		CreatedAt:     now.UnixMilli(),
	}
	if err := s.st.CreateVault(ctx, vault, device); err != nil {
		writeError(w, "internal")
		return
	}
	writeJSON(w, http.StatusCreated, wire.CreateVaultResponse{VaultID: req.VaultID})
}

func validateCreateVault(req *wire.CreateVaultRequest) error {
	if !wire.ValidID(req.VaultID) || !wire.ValidID(req.Device.DeviceID) {
		return errInvalidField
	}
	if req.Device.Kind != wire.DeviceKindIOS {
		return errInvalidField // the vault-creating device is the owner iPhone
	}
	if req.Device.HPKEKEM != wire.KEMP256 {
		return errInvalidField // owners wrap with Secure Enclave P-256 (design §9.2)
	}
	if req.Device.SignAlg != wire.SignAlgECDSAP256 {
		return errInvalidField
	}
	if len(req.Device.HPKEPublicKey) != wire.SizeP256Key || len(req.Device.SignPublicKey) != wire.SizeP256Key {
		return errInvalidField
	}
	if len(req.Device.RenewalSignPublicKey) != 0 && len(req.Device.RenewalSignPublicKey) != wire.SizeEd25519Key {
		return errInvalidField
	}
	if len(req.Device.Label) > wire.LabelNameMaxBytes {
		return errInvalidField
	}
	if len(req.RecoverySignPub) != wire.SizeEd25519Key {
		return errInvalidField
	}
	if req.DirectoryRevision < 1 {
		return errInvalidField
	}
	return nil
}

// handleGetRecoveryMaterials implements GET /v1/vaults/:vault_id/recovery
// (protocol §6.2). Unauthenticated; rate limited per IP and per vault
// (design §8.5). Anyone may pull these ciphertexts — the recovery code
// itself is the secret.
func (s *Server) handleGetRecoveryMaterials(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault_id")
	if !wire.ValidID(vaultID) {
		writeError(w, "invalid_field")
		return
	}
	now := s.cfg.Now()
	if !s.windowAllow("rec-ip:"+clientIPKey(r), now.UnixMilli(), RecoveryPerKeyPerMinute, 60_000) ||
		!s.windowAllow("rec-vault:"+vaultID, now.UnixMilli(), RecoveryPerKeyPerMinute, 60_000) {
		writeError(w, "rate_limited")
		return
	}
	vault, err := s.st.GetVault(r.Context(), vaultID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, "not_found")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	writeJSON(w, http.StatusOK, wire.RecoveryMaterialsResponse{
		VaultID:            vault.ID,
		RecoveryWrap:       vault.RecoveryWrap,
		RecoveryKDFJSON:    vault.RecoveryKDFJSON,
		RecoverySignPub:    vault.RecoverySignPub,
		DirectoryRevision:  uint64(vault.DirectoryRevision),
		DirectorySigned:    vault.DirectorySigned,
		DirectorySignature: vault.DirectorySignature,
	})
}

// handleRecoveryTakeover implements POST /v1/recovery/directory
// (protocol §6.3, design §8.5). Both signatures cover the same §3.3
// directory bytes: recovery_signature under the stored
// recovery_sign_pub, owner_signature under an active owner key inside
// the new transcript.
func (s *Server) handleRecoveryTakeover(w http.ResponseWriter, r *http.Request) {
	now := s.cfg.Now()
	if !s.windowAllow("takeover-ip:"+clientIPKey(r), now.UnixMilli(), RecoveryPerKeyPerMinute, 60_000) {
		writeError(w, "rate_limited")
		return
	}
	var req wire.RecoveryDirectoryRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if !wire.ValidID(req.VaultID) || req.DirectoryRevision < 1 {
		writeError(w, "invalid_field")
		return
	}
	vault, err := s.st.GetVault(r.Context(), req.VaultID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, "not_found")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	if !s.windowAllow("takeover-vault:"+req.VaultID, now.UnixMilli(), RecoveryPerKeyPerMinute, 60_000) {
		writeError(w, "rate_limited")
		return
	}
	// Design §8.5: the takeover directory bumps the revision by one.
	if req.DirectoryRevision != uint64(vault.DirectoryRevision)+1 {
		writeError(w, "revision_conflict")
		return
	}
	if err := wire.VerifyRecoverySignature(req.DirectorySigned, req.RecoverySignature, vault.RecoverySignPub); err != nil {
		writeError(w, "bad_signature")
		return
	}
	parsed, err := wire.ParseDirectoryTranscript(req.DirectorySigned)
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	ownerKeys := parsed.ActiveOwnerSignPublicKeys()
	if len(ownerKeys) == 0 {
		writeError(w, "invalid_field") // no active owner to continue the chain
		return
	}
	verified := false
	for _, key := range ownerKeys {
		if wire.VerifyOwnerSignature(req.DirectorySigned, req.OwnerSignature, key) == nil {
			verified = true
			break
		}
	}
	if !verified {
		writeError(w, "bad_signature")
		return
	}

	// The device row of the new owner must exist for the session to
	// attach to; mirror every record into devices.
	recs := parsed.Devices
	newOwnerID := ""
	for _, rec := range recs {
		if rec.Kind != wire.DeviceKindIOS || rec.Status != wire.DeviceStatusActive {
			continue
		}
		for _, key := range ownerKeys {
			if bytes.Equal(key, rec.SignPublicKey) {
				newOwnerID = rec.DeviceID
				break
			}
		}
		if newOwnerID != "" {
			break
		}
	}
	if newOwnerID == "" {
		writeError(w, "invalid_field")
		return
	}
	token := randomBytes(32)
	expires := now.Add(SessionTTL).UnixMilli()
	sess := &store.Session{TokenHash: sha256Hex(token), DeviceID: newOwnerID, ExpiresAt: expires}
	if err := s.st.TakeoverDirectory(r.Context(), vault.ID, int64(req.DirectoryRevision),
		req.DirectorySigned, req.OwnerSignature, recs, sess, now.UnixMilli()); err != nil {
		if errors.Is(err, store.ErrRevisionConflict) {
			writeError(w, "revision_conflict") // lost a concurrent takeover race
			return
		}
		writeError(w, "internal")
		return
	}
	// Successful takeover thaws a frozen vault (§10.5 item 8: any
	// successful login unfreezes).
	_ = s.st.ClearVaultFrozen(r.Context(), vault.ID)
	writeJSON(w, http.StatusOK, s.sessionPayload(r, token, expires, vault))
}

// handlePutVaultRecovery implements PUT /v1/vault/recovery (protocol
// §6.4): the owner replaces recovery material after VMK rotation or a
// recovery-code change (design §8.4).
func (s *Server) handlePutVaultRecovery(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	if code := s.gateWrite(ac, false); code != "" {
		writeError(w, code)
		return
	}
	var req wire.PutVaultRecoveryRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	// The signature covers the §3.6 vault-recovery transcript rebuilt
	// from the request fields plus the session's vault id.
	tb, err := wire.BuildVaultRecoveryTranscript(ac.vault.ID, req.RecoveryWrap, req.RecoveryKDFJSON, req.RecoverySignPub)
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if err := wire.VerifyOwnerSignature(tb, req.Signature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}
	if err := s.st.UpdateVaultRecovery(r.Context(), ac.vault.ID, req.RecoveryWrap, req.RecoveryKDFJSON, req.RecoverySignPub); err != nil {
		writeError(w, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteVault implements the two-step DELETE /v1/vaults/:vault_id
// (protocol §6.5, decision D10): an unsigned request receives a 60-second
// single-use challenge; the retry carries the owner signature over the
// §3.6 vault-delete transcript.
func (s *Server) handleDeleteVault(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault_id")
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	if vaultID != ac.vault.ID {
		writeError(w, "not_found")
		return
	}
	now := s.cfg.Now()

	var req wire.DeleteVaultRequest
	if r.ContentLength != 0 {
		if err := decode(r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
	}
	if req.Challenge == nil && req.Signature == nil {
		// Deletion is always allowed, even over quota or frozen (design
		// §10.5 item 7).
		challenge := randomBytes(32)
		s.mu.Lock()
		s.deleteChal[vaultID] = pendingChallenge{challenge: challenge, expires: now.Add(ChallengeTTL)}
		s.mu.Unlock()
		writeError(w, "delete_challenge_required", map[string]any{
			"challenge":  wire.Blob(challenge),
			"expires_at": now.Add(ChallengeTTL).UnixMilli(),
		})
		return
	}
	if req.Challenge == nil || req.Signature == nil {
		writeError(w, "invalid_field")
		return
	}
	s.mu.Lock()
	pend, exists := s.deleteChal[vaultID]
	delete(s.deleteChal, vaultID) // single use
	s.mu.Unlock()
	if !exists || now.After(pend.expires) || !constantTimeEqual(pend.challenge, *req.Challenge) {
		writeError(w, "unauthorized")
		return
	}
	tb, err := wire.BuildVaultDeleteTranscript(vaultID, pend.challenge)
	if err != nil {
		writeError(w, "internal")
		return
	}
	if err := wire.VerifyOwnerSignature(tb, *req.Signature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}
	if err := s.st.DeleteVaultCascade(r.Context(), vaultID); err != nil {
		writeError(w, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
