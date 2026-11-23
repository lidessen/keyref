package accountvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/remote"
	"github.com/lidessen/keyref/server/internal/store"
)

func TestBrowserAccountVault(t *testing.T) {
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/device/code":
			io.WriteString(w, `{"device_code":"fixture-device-code","user_code":"ABCD-EFGH","verification_uri":"https://github.com/login/device","expires_in":30,"interval":1}`)
		case "/login/oauth/access_token":
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
	srv := httptest.NewServer(v.Handler())
	defer srv.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

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
	status, body, _ = request("POST", "/manage/api/login/device", "", "https://attacker.example", true)
	check(status, 403, body)
	status, body, headers := request("POST", "/manage/api/login/device", "", "", true)
	check(status, 200, body)
	if !strings.Contains(headers.Get("Set-Cookie"), "HttpOnly") || !strings.Contains(headers.Get("Set-Cookie"), "SameSite=Strict") {
		t.Fatal("device cookie lacks expected protection")
	}
	if !bytes.Contains(body, []byte("ABCD-EFGH")) {
		t.Fatal("device code was not provided")
	}
	status, body, _ = request("POST", "/manage/api/login/poll", "", "", true)
	check(status, 204, body)
	status, body, _ = request("POST", "/manage/api/items", `{"ref":"api-key","value":"fixture-secret-value","description":"first","allow_commands":["curl"]}`, "", true)
	check(status, 204, body)
	status, body, _ = request("POST", "/manage/api/items", `{"ref":"api-key","value":"replacement"}`, "", true)
	check(status, 409, body)
	status, body, _ = request("GET", "/manage/api/items", "", "", false)
	check(status, 200, body)
	var rows []remote.Metadata
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 1 || rows[0].Ref != "api-key" || rows[0].Mask != "***" || rows[0].Description != "first" {
		t.Fatalf("unexpected metadata: %s %v", body, err)
	}
	key, err := v.browserKey(httptest.NewRequest("GET", "/", nil), 42)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	id := remote.ItemID(key, "api-key")
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
	status, body, _ = request("PATCH", "/manage/api/items/api-key", `{"ref":"api-key","description":"updated","allow_commands":["git"]}`, "", true)
	check(status, 204, body)
	var encryptedAfter []byte
	if err := st.DB().QueryRowContext(ctx, "SELECT value FROM account_items WHERE account=? AND id=?", 42, id).Scan(&encryptedAfter); err != nil || !bytes.Equal(encryptedBefore, encryptedAfter) {
		t.Fatal("metadata-only edit changed the value")
	}
	status, body, _ = request("DELETE", "/manage/api/items/api-key", "", "https://attacker.example", true)
	check(status, 403, body)
	status, body, _ = request("DELETE", "/manage/api/items/api-key", "", "", false)
	check(status, 403, body)
	status, body, _ = request("DELETE", "/manage/api/items/api-key", "", "", true)
	check(status, 204, body)
	status, body, _ = request("PATCH", "/manage/api/items/api-key", `{"ref":"api-key","value":"new"}`, "", true)
	check(status, 404, body)
	status, body, _ = request("DELETE", "/manage/api/session", "", "", true)
	check(status, 204, body)
	status, body, _ = request("GET", "/manage/api/items", "", "", false)
	check(status, 401, body)
}
