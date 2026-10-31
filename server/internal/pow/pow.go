// Package pow implements the vault-creation proof of work
// (docs/protocol.md §10.1, design §10.5 item 9). It is only consulted
// when the hosted quota switch KEYREF_ENFORCE_QUOTAS=1 is set; self-hosted
// deployments never issue or verify challenges.
package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"sync"
	"time"
)

// ChallengeTTL is how long an issued challenge stays valid (§10.1: one
// hour; a challenge may be retried many times but never swapped for a
// different vault once issued).
const ChallengeTTL = time.Hour

// leadingZeroBits is the required number of leading zero bits of
// SHA-256(challenge ‖ vault_id raw ‖ u64be(nonce)) — about 2^21 hashes
// expected (§10.1).
const leadingZeroBits = 21

// Issuer tracks outstanding challenges in memory. Challenges are
// ephemeral anti-spam tokens, not persisted state.
type Issuer struct {
	mu         sync.Mutex
	challenges map[string]time.Time // b64 challenge -> expiry
	now        func() time.Time
}

func NewIssuer() *Issuer {
	return &Issuer{
		challenges: map[string]time.Time{},
		now:        time.Now,
	}
}

// Issue returns a fresh 32-byte challenge, base64 encoded, with its
// expiry (§6.1: the 401 pow_required response).
func (i *Issuer) Issue() (challenge string, expiresAt int64) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic("pow: entropy source failed: " + err.Error())
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	exp := i.now().Add(ChallengeTTL)
	i.mu.Lock()
	i.pruneLocked()
	i.challenges[b64] = exp
	i.mu.Unlock()
	return b64, exp.UnixMilli()
}

// Verify checks a solution for the given vault id. The challenge comes
// off the wire as a Blob (the raw 32 bytes; the JSON layer base64-decodes
// it) and the nonce is the 8-byte big-endian u64 from the request.
// Unknown or expired challenges fail; a solved challenge stays valid for
// retries against the same vault until it expires (§10.1).
func (i *Issuer) Verify(challengeRaw, nonce []byte, vaultID []byte) bool {
	if len(nonce) != 8 || len(vaultID) != 16 || len(challengeRaw) != 32 {
		return false
	}
	challengeB64 := base64.StdEncoding.EncodeToString(challengeRaw)
	i.mu.Lock()
	exp, ok := i.challenges[challengeB64]
	i.mu.Unlock()
	if !ok || i.now().After(exp) {
		return false
	}
	h := sha256.New()
	h.Write(challengeRaw)
	h.Write(vaultID)
	h.Write(nonce)
	return leadingZeros(h.Sum(nil)) >= leadingZeroBits
}

func (i *Issuer) pruneLocked() {
	now := i.now()
	for c, exp := range i.challenges {
		if now.After(exp) {
			delete(i.challenges, c)
		}
	}
}

func leadingZeros(b []byte) int {
	bits := 0
	for _, v := range b {
		if v == 0 {
			bits += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if v&mask != 0 {
				return bits
			}
			bits++
		}
	}
	return bits
}

// Solve searches for a nonce that satisfies Verify. It exists for tests
// and for honest clients; the server never calls it.
func Solve(challengeB64 string, vaultID []byte) []byte {
	challenge, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return nil
	}
	key := make([]byte, 0, len(challenge)+len(vaultID)+8)
	key = append(key, challenge...)
	key = append(key, vaultID...)
	var nonce uint64
	buf := make([]byte, 8)
	for {
		binary.BigEndian.PutUint64(buf, nonce)
		h := sha256.New()
		h.Write(key)
		h.Write(buf)
		if leadingZeros(h.Sum(nil)) >= leadingZeroBits {
			return buf
		}
		nonce++
	}
}
