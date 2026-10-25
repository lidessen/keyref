// Package apns implements the APNs push provider that wakes the iOS app
// when a pending approval arrives (design §8.3, §13 Phase 2). The
// provider is a deployment concern only (§12.3): APNs credentials are
// environment variables, never part of any client-visible config, and a
// deployment without them runs with push disabled and nothing else
// changed.
//
// The implementation talks to APNs directly with the standard library:
// a token-based connection (ES256-signed JWT provider token, .p8 key)
// over HTTP/2, no third-party JWT dependency.
package apns

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Default hosts (Apple Token-Based Connection). The sandbox host serves
// development builds; production serves TestFlight / App Store builds.
const (
	ProductionURL = "https://api.push.apple.com"
	SandboxURL    = "https://api.sandbox.push.apple.com"
)

const (
	// jwtReuse bounds how long one provider token is reused. APNs
	// rejects provider tokens older than one hour; re-minting at 50
	// minutes keeps a comfortable margin.
	jwtReuse = 50 * time.Minute

	// DefaultPushTimeout bounds a single Push HTTP round trip. Approval
	// pushes run on fire-and-forget goroutines, so the client timeout is
	// what keeps a stuck APNs connection from piling up.
	DefaultPushTimeout = 10 * time.Second

	// ExpirationTTL is the apns-expiration horizon. The approval request
	// itself lives at most two minutes (design §8.3), so a push that
	// cannot be delivered within minutes must never arrive after the
	// approval has expired.
	ExpirationTTL = 5 * time.Minute
)

// Provider pushes one notification payload to one device token.
type Provider interface {
	Push(deviceToken string, payload []byte) error
}

// ErrTokenInvalid reports that APNs rejected the device token (HTTP 410,
// or the Unregistered / BadDeviceToken reasons). The stored push token
// is stale and the caller should clear it; the API layer's push
// dispatcher does exactly that.
var ErrTokenInvalid = errors.New("apns: device token invalid")

// ResponseError is a non-2xx APNs reply. Status carries the HTTP status
// code, Reason the APNs reason string from the JSON body ("" when absent
// or unparseable). ResponseError matches ErrTokenInvalid (errors.Is)
// whenever the reply indicates the token is no longer valid.
type ResponseError struct {
	Status int
	Reason string
}

func (e *ResponseError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("apns: unexpected status %d", e.Status)
	}
	return fmt.Sprintf("apns: status %d reason %q", e.Status, e.Reason)
}

// Is implements the errors.Is contract: token-rejection replies match
// ErrTokenInvalid so callers can distinguish "clear the token" from
// "log and move on" without string matching.
func (e *ResponseError) Is(target error) bool {
	if target != ErrTokenInvalid {
		return false
	}
	switch {
	case e.Status == http.StatusGone:
		return true
	case e.Reason == "Unregistered", e.Reason == "BadDeviceToken":
		return true
	}
	return false
}

// Config assembles a token provider. Key, KeyID, TeamID and Topic are
// required (NewTokenProvider refuses anything incomplete); BaseURL,
// Client, PushTimeout and Now are injectable for tests.
type Config struct {
	Key         *ecdsa.PrivateKey // .p8 signing key (ECDSA P-256)
	KeyID       string            // 10-character key id from the developer console
	TeamID      string            // 10-character team id ("iss" claim)
	Topic       string            // iOS app bundle id (apns-topic header)
	Sandbox     bool              // KEYREF_APN_ENV=sandbox
	BaseURL     string            // override for tests; empty → production/sandbox host
	Client      *http.Client      // optional; nil → client with PushTimeout
	PushTimeout time.Duration     // optional; default DefaultPushTimeout
	Now         func() time.Time  // injectable clock for tests
}

// TokenProvider is the token-based APNs provider: it signs each push
// with a .p8 ECDSA P-256 key, reusing one ES256 JWT provider token for
// jwtReuse, and POSTs over HTTP/2 to /3/device/<token>.
type TokenProvider struct {
	key    *ecdsa.PrivateKey
	keyID  string
	teamID string
	topic  string
	base   string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	jwt       string
	jwtIssued time.Time
}

// NewTokenProvider validates the config and returns the provider.
func NewTokenProvider(cfg Config) (*TokenProvider, error) {
	if cfg.Key == nil {
		return nil, errors.New("apns: signing key is required")
	}
	if cfg.KeyID == "" || cfg.TeamID == "" || cfg.Topic == "" {
		return nil, errors.New("apns: key id, team id and topic are required")
	}
	base := cfg.BaseURL
	if base == "" {
		base = ProductionURL
		if cfg.Sandbox {
			base = SandboxURL
		}
	}
	timeout := cfg.PushTimeout
	if timeout == 0 {
		timeout = DefaultPushTimeout
	}
	client := cfg.Client
	if client == nil {
		// ForceAttemptHTTP2 negotiates h2 over TLS via ALPN, which is
		// what APNs requires; plain-HTTP test servers keep h1.
		client = &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{ForceAttemptHTTP2: true},
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &TokenProvider{
		key: cfg.Key, keyID: cfg.KeyID, teamID: cfg.TeamID,
		topic: cfg.Topic, base: base, client: client, now: now,
	}, nil
}

// Push delivers payload to one device token and maps the APNs reply
// onto errors: 200 → nil, token rejections → ErrTokenInvalid (wrapped in
// *ResponseError), everything else → *ResponseError.
func (p *TokenProvider) Push(deviceToken string, payload []byte) error {
	if deviceToken == "" {
		return errors.New("apns: empty device token")
	}
	tok, err := p.providerToken()
	if err != nil {
		return fmt.Errorf("apns: provider token: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, p.base+"/3/device/"+deviceToken, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("apns: build request: %w", err)
	}
	req.Header.Set("authorization", "bearer "+tok)
	req.Header.Set("apns-topic", p.topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("apns-expiration", strconv.FormatInt(p.now().Add(ExpirationTTL).Unix(), 10))
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("apns: post: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	re := &ResponseError{Status: resp.StatusCode, Reason: parseReason(body)}
	return re
}

// providerToken returns the cached ES256 provider token, re-minting it
// once jwtReuse has passed (APNs caps provider tokens at one hour).
func (p *TokenProvider) providerToken() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.jwt != "" && now.Sub(p.jwtIssued) < jwtReuse {
		return p.jwt, nil
	}
	tok, err := signProviderToken(p.key, p.keyID, p.teamID, now)
	if err != nil {
		return "", err
	}
	p.jwt, p.jwtIssued = tok, now
	return tok, nil
}

// parseReason extracts the APNs reason field from an error body
// ({"reason":"Unregistered"}). Anything unparseable is "".
func parseReason(body []byte) string {
	var v struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	return v.Reason
}

// LoadFromEnv assembles a provider from the deployment environment
// (design §12.3: APNs credentials live only in the environment). The
// required variables are:
//
//	KEYREF_APN_KEY_PATH  path to the .p8 signing key file
//	KEYREF_APN_KEY_ID    key id from the Apple developer console
//	KEYREF_TEAM_ID       Apple team id
//	KEYREF_APN_TOPIC     the iOS app bundle id
//	KEYREF_APN_ENV       sandbox | production
//
// It never returns an error: when any variable is missing, or the key
// file cannot be read or parsed, the provider is nil with a one-line
// reason for the startup log — push is disabled and every other server
// function is unaffected.
func LoadFromEnv(getenv func(string) string) (Provider, string) {
	const prefix = "apns disabled: "
	path := getenv("KEYREF_APN_KEY_PATH")
	keyID := getenv("KEYREF_APN_KEY_ID")
	teamID := getenv("KEYREF_TEAM_ID")
	topic := getenv("KEYREF_APN_TOPIC")
	env := getenv("KEYREF_APN_ENV")
	if path == "" || keyID == "" || teamID == "" || topic == "" {
		return nil, prefix + "KEYREF_APN_KEY_PATH, KEYREF_APN_KEY_ID, KEYREF_TEAM_ID and KEYREF_APN_TOPIC must all be set"
	}
	if env != "sandbox" && env != "production" {
		return nil, prefix + "KEYREF_APN_ENV must be sandbox or production"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, prefix + "read KEYREF_APN_KEY_PATH: " + err.Error()
	}
	key, err := ParseP8Key(data)
	if err != nil {
		return nil, prefix + err.Error()
	}
	p, err := NewTokenProvider(Config{
		Key: key, KeyID: keyID, TeamID: teamID, Topic: topic,
		Sandbox: env == "sandbox",
	})
	if err != nil {
		return nil, prefix + err.Error()
	}
	return p, ""
}
