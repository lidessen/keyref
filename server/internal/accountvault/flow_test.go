package accountvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/proto/remote"
	"github.com/lidessen/keyref/server/internal/store"
)

func TestRemoteCLIFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI binary")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "keyref")
	build := exec.Command("go", "build", "-C", "../../../cli", "-o", binary, "./cmd/keyref")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v: %s", err, output)
	}

	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/device/code":
			if r.Method != "POST" || r.FormValue("client_id") != "fixture" || r.FormValue("scope") != "" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"device_code":"fixture-device-code","user_code":"ABCD-EFGH","verification_uri":"https://github.com/login/device","expires_in":30,"interval":1}`)
		case "/login/oauth/access_token":
			if r.Method != "POST" || r.FormValue("device_code") != "fixture-device-code" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"access_token":"fixture-provider-token"}`)
		case "/user":
			if r.Header.Get("Authorization") != "Bearer fixture-provider-token" {
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, `{"id":42,"login":"fixture"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer github.Close()

	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	v, err := Open(ctx, st, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "fixture", "42,84")
	if err != nil {
		t.Fatal(err)
	}
	v.github.loginURL = github.URL
	v.github.apiURL = github.URL
	srv := httptest.NewServer(v.Handler())
	defer srv.Close()

	const value = "synthetic-test-token-never-print"
	run := func(home, stdin string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"remote"}, args...)...)
		cmd.Env = append(os.Environ(), "KEYREF_SERVER="+srv.URL, "KEYREF_HOME="+filepath.Join(dir, home), "KEYREF_KEYRING_DIR="+filepath.Join(dir, home+"-keys"))
		cmd.Stdin = strings.NewReader(stdin)
		output, err := cmd.CombinedOutput()
		if bytes.Contains(output, []byte(value)) {
			t.Fatal("CLI output leaked fixture secret")
		}
		if err == nil {
			return string(output), 0
		}
		if failure, ok := err.(*exec.ExitError); ok {
			return string(output), failure.ExitCode()
		}
		t.Fatal(err)
		return "", -1
	}
	ok := func(home, stdin string, args ...string) string {
		t.Helper()
		out, code := run(home, stdin, args...)
		if code != 0 {
			t.Fatalf("remote %s failed with %d: %s", args[0], code, out)
		}
		return out
	}
	ok("device-a", "", "login")
	cat := exec.Command("which", "printenv")
	path, err := cat.Output()
	if err != nil {
		t.Fatal(err)
	}
	printenv := strings.TrimSpace(string(path))
	ok("device-a", value+"\n", "set", "--allow-command", "printenv", "fixture")
	ok("device-b", "", "login")
	if out := ok("device-b", "", "get", "fixture"); !strings.Contains(out, "fixture") {
		t.Fatal("second device did not find the first device's entry")
	}
	if out := ok("device-b", "", "exec", "--env", "REMOTE_FIXTURE=fixture", "--", printenv, "REMOTE_FIXTURE"); !strings.Contains(out, "<redacted:fixture>") {
		t.Fatal("remote exec did not redact the fixture")
	}
	var metadata, secretCiphertext, wrapped []byte
	if err := st.DB().QueryRowContext(ctx, "SELECT metadata,value FROM account_items").Scan(&metadata, &secretCiphertext); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRowContext(ctx, "SELECT wrapped_key FROM account_vaults").Scan(&wrapped); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(metadata, []byte("fixture")) || bytes.Contains(secretCiphertext, []byte(value)) || len(wrapped) != 60 {
		t.Fatal("expected encrypted metadata, value and vault key")
	}
	other, err := v.issue(ctx, 84)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(other.VaultKey)
	var itemID string
	if err := st.DB().QueryRowContext(ctx, "SELECT id FROM account_items").Scan(&itemID); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", srv.URL+remote.Path+"items/"+itemID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+other.Token)
	foreign, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	foreign.Body.Close()
	if foreign.StatusCode != http.StatusNotFound {
		t.Fatal("another GitHub account could access the entry")
	}
	ok("device-b", "", "delete", "fixture")
	if out := ok("device-a", "", "list"); out != "" {
		t.Fatal("deletion did not synchronize")
	}
	ok("device-b", "", "logout")
	if _, code := run("device-b", "", "list"); code != 12 {
		t.Fatalf("logout did not lock the CLI: %d", code)
	}
	var count int
	if err := st.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM account_sessions").Scan(&count); err != nil || count != 2 {
		t.Fatalf("logout did not revoke only the current token: %v", err)
	}
	res, err := http.Get(srv.URL + "/v1/remote/items")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var failure struct {
		Error string `json:"error"`
	}
	if res.StatusCode != 401 || json.NewDecoder(res.Body).Decode(&failure) != nil || failure.Error != "unauthorized" {
		t.Fatal("remote server allowed unauthenticated access")
	}
}
