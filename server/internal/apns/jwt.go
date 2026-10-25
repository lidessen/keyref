package apns

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The APNs provider token is a JWT signed with ES256 (RFC 7515 §3.4):
// ECDSA P-256 over the SHA-256 digest of the two base64url segments,
// ASN.1 DER signature, raw (unpadded) base64url encoding throughout.

// jwtHeader is the JOSE header: {"alg":"ES256","kid":<keyID>}.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// jwtClaims are the APNs provider-token claims: {"iss":<teamID>,"iat":<now>}.
// iat is Unix seconds.
type jwtClaims struct {
	Iss string `json:"iss"`
	Iat int64  `json:"iat"`
}

// signProviderToken builds and signs one provider token for the given
// issue time.
func signProviderToken(key *ecdsa.PrivateKey, keyID, teamID string, now time.Time) (string, error) {
	if key == nil {
		return "", fmt.Errorf("apns: signing key is nil")
	}
	header, err := json.Marshal(jwtHeader{Alg: "ES256", Kid: keyID})
	if err != nil {
		return "", fmt.Errorf("apns: jwt header: %w", err)
	}
	claims, err := json.Marshal(jwtClaims{Iss: teamID, Iat: now.Unix()})
	if err != nil {
		return "", fmt.Errorf("apns: jwt claims: %w", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return "", fmt.Errorf("apns: jwt sign: %w", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// decodeJWTProviderToken splits a provider token into its raw header and
// claims JSON plus the DER signature — the shape tests need to assert
// the exact header/claims bytes and re-verify the signature.
func decodeJWTProviderToken(token string) (header, claims json.RawMessage, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("apns: jwt has %d segments, want 3", len(parts))
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("apns: jwt header: %w", err)
	}
	c, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("apns: jwt claims: %w", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("apns: jwt signature: %w", err)
	}
	return json.RawMessage(h), json.RawMessage(c), sig, nil
}

// verifyProviderToken checks the ES256 signature of a provider token
// against pub — the test-side mirror of what APNs does on its side.
func verifyProviderToken(token string, pub *ecdsa.PublicKey) error {
	_, _, sig, err := decodeJWTProviderToken(token)
	if err != nil {
		return err
	}
	parts := strings.SplitN(token, ".", 2)
	sum := sha256.Sum256([]byte(parts[0] + "." + strings.SplitN(parts[1], ".", 2)[0]))
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return fmt.Errorf("apns: jwt signature does not verify")
	}
	return nil
}
