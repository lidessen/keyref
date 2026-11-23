package api

import (
	"context"
	"time"

	"github.com/lidessen/keyref/server/internal/store"
)

func (s *Server) putChallenge(ctx context.Context, scope, id string, value []byte, now, expiry time.Time, local map[string]pendingChallenge) error {
	if s.cfg.SharedState {
		return s.st.PutChallenge(ctx, scope+id, value, now.UnixMilli(), expiry.UnixMilli())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	local[id] = pendingChallenge{challenge: value, expires: expiry}
	return nil
}

func (s *Server) takeChallenge(ctx context.Context, scope, id string, now time.Time, local map[string]pendingChallenge) ([]byte, error) {
	if s.cfg.SharedState {
		return s.st.TakeChallenge(ctx, scope+id, now.UnixMilli())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge, exists := local[id]
	delete(local, id)
	if !exists || now.After(challenge.expires) {
		return nil, store.ErrNotFound
	}
	return challenge.challenge, nil
}
