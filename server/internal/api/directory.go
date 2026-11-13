package api

import (
	"errors"
	"log"
	"net/http"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/quotas"
	"github.com/lidessen/keyref/server/internal/store"
)

// handlePutDirectory implements PUT /v1/directory (protocol §6.15). The
// new revision must advance, the signature must verify under an owner
// key of the PREVIOUS directory, and device rows plus sessions follow
// the new statuses (revocation kills sessions immediately, §8.4).
// Directory updates stay available over quota: revoking a compromised
// CLI is composed of deletes and re-signing (design §10.5 item 7).
func (s *Server) handlePutDirectory(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	var req wire.PutDirectoryRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if req.DirectoryRevision <= uint64(ac.vault.DirectoryRevision) {
		writeError(w, "revision_conflict") // strictly increasing (§6.15)
		return
	}

	// The signature verifies under an owner key of the PREVIOUS
	// directory transcript only (design §9.1/§8.1: device public keys
	// are trusted exclusively from the signed directory — never from the
	// mutable devices table, so dropping a device from the directory
	// strips its signing authority even if its row lingers active).
	prevParsed, perr := wire.ParseDirectoryTranscript(ac.vault.DirectorySigned)
	verified := false
	if perr == nil {
		for _, key := range prevParsed.ActiveOwnerSignPublicKeys() {
			if wire.VerifyOwnerSignature(req.DirectorySigned, req.Signature, key) == nil {
				verified = true
				break
			}
		}
	}
	if !verified {
		writeError(w, "bad_signature")
		return
	}

	parsed, err := wire.ParseDirectoryTranscript(req.DirectorySigned)
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if parsed.VaultID != ac.vault.ID || parsed.DirectoryRevision != req.DirectoryRevision {
		writeError(w, "invalid_field") // structured fields must match the bytes
		return
	}
	if len(parsed.ActiveOwnerSignPublicKeys()) == 0 {
		writeError(w, "invalid_field") // never strand the vault without an owner
		return
	}
	// Receiver roles (design v0.8 §14.4): at most one primary receiver
	// per vault. Role values for non-ios devices are rejected by the
	// transcript validator itself.
	primaries := 0
	for _, d := range parsed.Devices {
		if d.ReceiverRole == wire.ReceiverRolePrimary {
			primaries++
		}
	}
	if primaries > 1 {
		writeError(w, "invalid_receiver_role")
		return
	}

	// Plan device ceilings apply to directory updates too (design §10.5,
	// §11 item 6): a directory may not raise the active device count
	// above the tier by minting a device that was never paired. The
	// directory is the whole device set (omission revokes, v2 G), so the
	// records alone project the post-update count.
	if s.cfg.EnforceQuotas {
		plan := quotas.EffectivePlan(ac.vault, s.cfg.Now().UnixMilli())
		if plan != quotas.PlanUnlimited {
			limits := s.quota.LimitsFor(plan)
			ios, cli := store.DirectoryDeviceCounts(parsed.Devices)
			if (limits.DevicesIOS != nil && ios > *limits.DevicesIOS) ||
				(limits.DevicesCLI != nil && cli > *limits.DevicesCLI) {
				writeError(w, "quota_exceeded")
				return
			}
		}
	}

	if _, err := s.st.UpdateVaultDirectory(r.Context(), ac.vault.ID,
		int64(req.DirectoryRevision), req.DirectorySigned, req.Signature,
		parsed.Devices, s.cfg.Now().UnixMilli()); err != nil {
		if err == store.ErrRevisionConflict {
			writeError(w, "revision_conflict") // lost a concurrent update race
			return
		}
		if errors.Is(err, store.ErrDeviceRevoked) {
			writeError(w, "invalid_field") // revoked is terminal (v2 G)
			return
		}
		log.Printf("api: directory update: %v", err)
		writeError(w, "internal")
		return
	}
	writeJSON(w, http.StatusOK, wire.PutDirectoryResponse{DirectoryRevision: req.DirectoryRevision})
}
