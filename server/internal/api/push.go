package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/apns"
)

// Push notification surface (design §8.3, §13 Phase 2). The server is
// the courier here too: iOS devices register their APNs tokens, and a
// durable approval request is fanned out best-effort to the vault's
// owner devices. Push never gates anything: a deployment without APNs
// credentials (cfg.Push == nil) skips it entirely, and failures only log.

// apnsTokenLimits bound the registered token string. APNs device tokens
// are 32 bytes (64 hex chars); the range leaves room for older token
// lengths while rejecting junk.
const (
	apnsTokenMinChars = 32
	apnsTokenMaxChars = 200
)

// apsAlert is the alert object of the approval notification.
type apsAlert struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// apsPayload is the aps dictionary of the approval notification.
type apsPayload struct {
	Alert apsAlert `json:"alert"`
	Sound string   `json:"sound"`
}

// pushEnvelope is the full APNs payload: the aps dictionary plus the
// custom routing id the iOS app routes on (approval_id or message_id).
type pushEnvelope struct {
	Aps        apsPayload `json:"aps"`
	ApprovalID string     `json:"approval_id,omitempty"`
	MessageID  string     `json:"message_id,omitempty"`
}

// pushApprovalPayload renders the fixed approval notification payload
// (design §8.3). No request content — command lines stay inside the
// end-to-end encrypted approval ciphertext.
func pushApprovalPayload(approvalID string) []byte {
	b, err := json.Marshal(pushEnvelope{
		Aps: apsPayload{
			Alert: apsAlert{Title: "keyref 审批", Body: "有一条待审批的命令"},
			Sound: "default",
		},
		ApprovalID: approvalID,
	})
	if err != nil {
		return nil
	}
	return b
}

// pushMessagePayload renders the fixed new-message notification payload
// (design v0.8 §14.4): the body is the same fixed string for every
// message and carries no sender, no device label and no SMS content —
// the lock screen is a semi-public surface (B9).
func pushMessagePayload(messageID string) []byte {
	b, err := json.Marshal(pushEnvelope{
		Aps: apsPayload{
			Alert: apsAlert{Title: "keyref", Body: "收到新的验证码"},
			Sound: "default",
		},
		MessageID: messageID,
	})
	if err != nil {
		return nil
	}
	return b
}

// handlePutPushToken implements PUT /v1/devices/push-token. Only an
// active kind=ios device may register, and only for itself: the token is
// attached to the authenticated device row, so a stolen CLI or owner
// token cannot aim pushes at someone else's device. The env field is
// validated (sandbox | production) but not persisted — the single
// push_token column holds the token; re-registering overwrites.
func (s *Server) handlePutPushToken(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	var req wire.PushTokenRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	switch req.Env {
	case "sandbox", "production":
	default:
		writeError(w, "invalid_field")
		return
	}
	if !validAPNsToken(req.Token) {
		writeError(w, "invalid_field")
		return
	}
	if err := s.st.SetPushToken(r.Context(), ac.device.ID, req.Token); err != nil {
		writeError(w, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validAPNsToken checks the hex shape of a device token.
func validAPNsToken(token string) bool {
	if len(token) < apnsTokenMinChars || len(token) > apnsTokenMaxChars || len(token)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// pushApprovalCreated fans a new pending approval out to every active
// owner device with a registered APNs token (design §8.3). Called AFTER
// the approval row and its change are durable, and best effort by
// contract: no token lists, marshal errors or provider failures ever
// reach the approval creator — they are logged and dropped. Each push
// runs on its own goroutine bounded by the provider's client timeout;
// a token APNs rejected (410) is cleared from the store.
func (s *Server) pushApprovalCreated(vaultID, approvalID string) {
	s.pushToOwners(vaultID, pushApprovalPayload(approvalID), "approval", approvalID)
}

// pushMessageCreated fans a new message out to the owner devices'
// registered APNs tokens (design v0.8 §14.4). Same contract as
// pushApprovalCreated: durable row first, best-effort push, failures
// only log.
func (s *Server) pushMessageCreated(vaultID, messageID string) {
	s.pushToOwners(vaultID, pushMessagePayload(messageID), "message", messageID)
}

// pushToOwners is the shared fan-out of pushApprovalCreated and
// pushMessageCreated. payload may be nil (marshal failure): the push is
// then silently skipped. Targeting follows design v0.8 §14.4: the
// primary receiver gets the push alone; without a registered primary
// token every owner device with a token is fanned out as before.
func (s *Server) pushToOwners(vaultID string, payload []byte, kind, id string) {
	if s.cfg.Push == nil || payload == nil {
		return
	}
	primary, err := s.st.PrimaryReceiverToken(bgContext(), vaultID)
	if err != nil {
		log.Printf("api: push %s %s: primary receiver: %v", kind, id, err)
		return
	}
	tokens := []string(nil)
	if primary != "" {
		tokens = []string{primary}
	} else {
		tokens, err = s.st.ListPushTokens(bgContext(), vaultID)
		if err != nil {
			log.Printf("api: push %s %s: list tokens: %v", kind, id, err)
			return
		}
	}
	for _, token := range tokens {
		go func(token string) {
			if err := s.cfg.Push.Push(token, payload); err != nil {
				if errors.Is(err, apns.ErrTokenInvalid) {
					// APNs no longer knows this token: drop it so
					// future pushes stop hitting a dead device.
					if cerr := s.st.ClearPushToken(bgContext(), token); cerr != nil {
						log.Printf("api: push %s %s: clear token: %v", kind, id, cerr)
					}
					return
				}
				log.Printf("api: push %s %s: %v", kind, id, err)
			}
		}(token)
	}
}
