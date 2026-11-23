package accountvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/remote"
	"github.com/lidessen/keyref/server/internal/store"
)

func TestBrowserAccountVault(t *testing.T) {
	var challenge, callback string
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			verifier := sha256.Sum256([]byte(r.FormValue("code_verifier")))
			if r.FormValue("client_secret") != "fixture-client-secret" || r.FormValue("code") != "fixture-code" ||
				r.FormValue("redirect_uri") != callback || base64.RawURLEncoding.EncodeToString(verifier[:]) != challenge {
				http.Error(w, "invalid token exchange", 400)
				return
			}
			io.WriteString(w, `{"access_token":"fixture-provider-token"}`)
		case "/user":
			io.WriteString(w, `{"id":42}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer github.Close()

	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	v, err := Open(ctx, st, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "fixture", "42")
	if err != nil {
		t.Fatal(err)
	}
	v.github.loginURL, v.github.apiURL = github.URL, github.URL
	srv := httptest.NewTLSServer(v.Handler())
	callback = srv.URL + OAuthCallbackPath
	if err := v.ConfigureBrowserOAuth("fixture-client-secret", callback); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	request := func(method, path, body, origin string, header bool) (int, []byte, http.Header) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if header {
			req.Header.Set("X-Keyref-Admin", "1")
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("browser response missing no-store")
		}
		return res.StatusCode, data, res.Header
	}
	check := func(status, want int, body []byte) {
		t.Helper()
		if status != want {
			t.Fatalf("status %d, want %d: %s", status, want, body)
		}
		if bytes.Contains(body, []byte("fixture-secret-value")) || bytes.Contains(body, []byte("fixture-device-code")) || bytes.Contains(body, []byte("fixture-provider-token")) {
			t.Fatal("response exposed a credential")
		}
	}
	status, body, _ := request("GET", "/manage/api/items", "", "", false)
	check(status, 401, body)
	start := "/manage/api/login/github"
	status, body, _ = request("POST", start, "", "https://attacker.example", true)
	check(status, 403, body)
	begin := func() string {
		t.Helper()
		status, body, headers := request("POST", start, "", srv.URL, true)
		check(status, 200, body)
		cookie := headers.Get("Set-Cookie")
		if !strings.Contains(cookie, "__Host-keyref_oauth=") || !strings.Contains(cookie, "SameSite=Lax") ||
			!strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "Secure") {
			t.Fatal("authorization cookie lacks expected protections")
		}
		var response map[string]string
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		authorize, err := url.Parse(response["authorization_url"])
		if err != nil {
			t.Fatal(err)
		}
		params := authorize.Query()
		if authorize.Path != "/login/oauth/authorize" || params.Get("redirect_uri") != callback ||
			params.Get("code_challenge_method") != "S256" || len(params.Get("state")) != 43 || params.Has("scope") {
			t.Fatal("unexpected GitHub authorization parameters")
		}
		challenge = params.Get("code_challenge")
		return params.Get("state")
	}
	begin()
	status, body, headers := request("GET", OAuthCallbackPath+"?state=wrong&code=fixture-code", "", "", false)
	check(status, 303, body)
	if headers.Get("Location") != "/manage/?login=failed" {
		t.Fatal("mismatched state was accepted")
	}
	state := begin()
	status, body, headers = request("GET", OAuthCallbackPath+"?state="+state+"&code=fixture-code", "", "", false)
	check(status, 303, body)
	if headers.Get("Location") != "/manage/" {
		t.Fatal("OAuth did not return to the vault")
	}
	status, body, _ = request("POST", "/manage/api/items", `{"ref":"api-key","value":"fixture-secret-value","description":"first"}`, "", true)
	check(status, 204, body)
	status, body, _ = request("POST", "/manage/api/items", `{"ref":"api-key","value":"replacement"}`, "", true)
	check(status, 409, body)
	status, body, _ = request("GET", "/manage/api/items", "", "", false)
	check(status, 200, body)
	var rows []struct {
		ID string `json:"id"`
		remote.Metadata
	}
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 1 || rows[0].Ref != "api-key" || rows[0].Mask != "***" || rows[0].Description != "first" {
		t.Fatalf("unexpected metadata: %s %v", body, err)
	}
	key, err := v.accountKey(t.Context(), 42)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	id := remote.ItemID(key, "api-key")
	if rows[0].ID != id {
		t.Fatal("browser item ID does not match CLI item ID")
	}
	itemPath := "/manage/api/items/" + id
	var encryptedBefore []byte
	if err := st.DB().QueryRowContext(ctx, "SELECT value FROM account_items WHERE account=? AND id=?", 42, id).Scan(&encryptedBefore); err != nil {
		t.Fatal(err)
	}
	cipherKey := remote.CipherKey(key)
	defer clear(cipherKey)
	plaintext, err := crypto.OpenBlob(cipherKey, remote.ItemAAD(id, "value"), encryptedBefore)
	if err != nil || string(plaintext) != "fixture-secret-value" {
		t.Fatal("CLI-compatible value decryption failed")
	}
	clear(plaintext)
	status, body, _ = request("PATCH", itemPath, `{"ref":"other-ref","value":"replacement"}`, "", true)
	check(status, 400, body)
	status, body, _ = request("DELETE", "/manage/api/items/api-key", "", "", true)
	check(status, 400, body)
	status, body, _ = request("PATCH", itemPath, `{"ref":"api-key","description":"updated"}`, "", true)
	check(status, 204, body)
	var encryptedAfter []byte
	if err := st.DB().QueryRowContext(ctx, "SELECT value FROM account_items WHERE account=? AND id=?", 42, id).Scan(&encryptedAfter); err != nil || !bytes.Equal(encryptedBefore, encryptedAfter) {
		t.Fatal("metadata-only edit changed the value")
	}
	status, body, _ = request("DELETE", itemPath, "", "https://attacker.example", true)
	check(status, 403, body)
	status, body, _ = request("DELETE", itemPath, "", "", false)
	check(status, 403, body)
	status, body, _ = request("DELETE", itemPath, "", "", true)
	check(status, 204, body)
	status, body, _ = request("PATCH", itemPath, `{"ref":"api-key","value":"new"}`, "", true)
	check(status, 404, body)
	status, body, _ = request("DELETE", "/manage/api/session", "", "", true)
	check(status, 204, body)
	status, body, _ = request("GET", "/manage/api/items", "", "", false)
	check(status, 401, body)
}
