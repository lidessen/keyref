// Package client is the thin HTTP client for the keyref sync API
// (docs/protocol.md §5–§6). It adds the bearer token, decodes the fixed
// {"error":code} bodies, and never logs request or response fields
// (design.md §15). Request and response bodies use the canonical
// proto/wire types.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lidessen/keyref/proto/wire"
)

// APIError carries a protocol error code (docs/protocol.md §1.3).
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("client: server returned %d %s", e.Status, e.Code)
}

// Code returns the protocol error code of err, or "".
func Code(err error) string {
	var ae *APIError
	if errorsAs(err, &ae) {
		return ae.Code
	}
	return ""
}

func errorsAs(err error, target **APIError) bool {
	for err != nil {
		if ae, ok := err.(*APIError); ok {
			*target = ae
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Client talks to one sync-server origin.
type Client struct {
	origin string
	hc     *http.Client
	// token supplies the bearer token lazily (session package); nil
	// means unauthenticated requests (pairing endpoints).
	token func() (string, error)
}

// New returns a client for origin. token may be nil.
func New(origin string, token func() (string, error)) *Client {
	return &Client{
		origin: strings.TrimRight(origin, "/"),
		hc:     &http.Client{Timeout: 30 * time.Second},
		token:  token,
	}
}

// SetTokenSource swaps the bearer-token source.
func (c *Client) SetTokenSource(f func() (string, error)) { c.token = f }

// Origin returns the server origin this client talks to.
func (c *Client) Origin() string { return c.origin }

func (c *Client) do(method, path string, query url.Values, body any, out any) error {
	return c.doAuth(method, path, query, body, out, true)
}

// doAuth performs the request; authenticate=false serves the login and
// pairing endpoints, which must not trigger the token source (getting
// a token is itself a request — recursion hazard).
func (c *Client) doAuth(method, path string, query url.Values, body any, out any, authenticate bool) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("client: encode request: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	u := c.origin + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return fmt.Errorf("client: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	if authenticate && c.token != nil {
		tok, err := c.token()
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("client: request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("client: read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = "http_error"
		}
		return &APIError{Status: resp.StatusCode, Code: e.Error}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("client: decode response: %w", err)
		}
	}
	return nil
}

// PairRegister registers the device keys and nonce for pairing (§6.16).
func (c *Client) PairRegister(req *wire.PairRegisterRequest) error {
	var out wire.PairRegisterResponse
	return c.doAuth(http.MethodPost, "/v1/pair/register", nil, req, &out, false)
}

// PairStatus polls the pairing outcome for nonce (hex) (§6.18).
func (c *Client) PairStatus(nonceHex string) (*wire.PairStatusResponse, error) {
	q := url.Values{"nonce": []string{nonceHex}}
	var out wire.PairStatusResponse
	if err := c.doAuth(http.MethodGet, "/v1/pair/status", q, nil, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// SessionChallenge performs step 1 of §6.7.
func (c *Client) SessionChallenge(deviceID string) (challenge []byte, expiresAt int64, err error) {
	var out wire.SessionChallengeResponse
	body := wire.SessionRequest{DeviceID: deviceID}
	if err := c.doAuth(http.MethodPost, "/v1/session", nil, body, &out, false); err != nil {
		return nil, 0, err
	}
	return out.Challenge, out.ExpiresAt, nil
}

// SessionToken performs step 2 of §6.7: the signature covers the §3.6
// session transcript.
func (c *Client) SessionToken(deviceID string, challenge, signature []byte) (token string, expiresAt int64, err error) {
	var out wire.SessionResponse
	ch, sig := wire.Blob(challenge), wire.Blob(signature)
	body := wire.SessionRequest{DeviceID: deviceID, Challenge: &ch, Signature: &sig}
	if err := c.doAuth(http.MethodPost, "/v1/session", nil, body, &out, false); err != nil {
		return "", 0, err
	}
	return out.Token, out.ExpiresAt, nil
}

// Sync fetches the change batch after cursor (§8).
func (c *Client) Sync(cursor int64) (*wire.SyncResponse, error) {
	q := url.Values{"cursor": []string{fmt.Sprintf("%d", cursor)}}
	var out wire.SyncResponse
	if err := c.do(http.MethodGet, "/v1/sync", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GrantsSelf fetches this device's grants for reconciliation (§6.14).
func (c *Client) GrantsSelf() (*wire.GrantsSelfResponse, error) {
	var out wire.GrantsSelfResponse
	if err := c.do(http.MethodGet, "/v1/grants/self", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PostAudit uploads one encrypted audit envelope (§6.23), best effort.
func (c *Client) PostAudit(ciphertext []byte) error {
	body := wire.AuditRequest{Ciphertext: ciphertext}
	var out wire.AuditResponse
	return c.do(http.MethodPost, "/v1/audit", nil, &body, &out)
}
