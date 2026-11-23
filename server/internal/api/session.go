package api

import (
	"errors"
	"net/http"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/quotas"
	"github.com/lidessen/keyref/server/internal/store"
)

// handleSession implements POST /v1/session (protocol §6.7, decision
// D11): one path, two steps. Without signature fields the server issues
// a 60-second single-use challenge; with them the device signs the §3.6
// session transcript and receives a 12-hour bearer token. Revoked
// devices never get new tokens (design §8.2). A successful login thaws
// a frozen vault (design §10.5 item 8).
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	var req wire.SessionRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if !wire.ValidID(req.DeviceID) {
		writeError(w, "invalid_field")
		return
	}
	now := s.cfg.Now()

	dev, err := s.st.GetDevice(r.Context(), req.DeviceID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, "unauthorized")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}

	// Step one: issue the challenge.
	if req.Challenge == nil && req.Signature == nil {
		if dev.Status == wire.DeviceStatusRevoked {
			writeError(w, "device_revoked")
			return
		}
		challenge := randomBytes(32)
		expires := now.Add(ChallengeTTL)
		if err := s.putChallenge(r.Context(), "session:", req.DeviceID, challenge, now, expires, s.sessionChal); err != nil {
			writeError(w, "internal")
			return
		}
		writeJSON(w, http.StatusOK, wire.SessionChallengeResponse{
			Challenge: challenge,
			ExpiresAt: expires.UnixMilli(),
		})
		return
	}

	// Step two: verify the signature over the §3.6 transcript.
	if req.Challenge == nil || req.Signature == nil {
		writeError(w, "invalid_field")
		return
	}
	if dev.Status == wire.DeviceStatusRevoked {
		writeError(w, "device_revoked")
		return
	}
	challenge, err := s.takeChallenge(r.Context(), "session:", req.DeviceID, now, s.sessionChal)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, "internal")
		return
	}
	if err != nil || !constantTimeEqual(challenge, *req.Challenge) {
		writeError(w, "unauthorized")
		return
	}
	tb, err := wire.BuildSessionTranscript(req.DeviceID, challenge)
	if err != nil {
		writeError(w, "internal")
		return
	}
	if err := wire.VerifyDeviceSignature(tb, *req.Signature, dev.SignAlg, dev.SignPublicKey); err != nil {
		writeError(w, "unauthorized") // §6.7 lists unauthorized for step two
		return
	}
	vault, err := s.st.GetVault(r.Context(), dev.VaultID)
	if err != nil {
		writeError(w, "unauthorized")
		return
	}
	token, expires, err := s.issueSession(r.Context(), req.DeviceID, now)
	if err != nil {
		writeError(w, "internal")
		return
	}
	if s.cfg.EnforceQuotas && vault.Plan == quotas.PlanFree {
		_ = s.st.ClearVaultFrozen(r.Context(), vault.ID) // login thaws (§10.5-8)
	}
	writeJSON(w, http.StatusOK, s.sessionPayload(r, token, expires, vault))
}
