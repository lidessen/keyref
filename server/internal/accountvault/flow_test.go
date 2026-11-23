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
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
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
	env := func(home string) []string {
		return append(os.Environ(), "KEYREF_SERVER="+srv.URL, "KEYREF_HOME="+filepath.Join(dir, home), "KEYREF_KEYRING_DIR="+filepath.Join(dir, home+"-keys"))
	}
	run := func(home, stdin string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"remote"}, args...)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Env = env(home)
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
	command, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	ok("device-a", value+"\n", "set", "fixture")
	ok("device-b", "", "login")
	if out := ok("device-b", "", "get", "fixture"); !strings.Contains(out, "fixture") {
		t.Fatal("second device did not find the first device's entry")
	}
	if out, code := run("device-b", "yes\n", "exec", "--env", "REMOTE_FIXTURE=fixture", "--", command); code != 10 || !strings.Contains(out, "controlling terminal") {
		t.Fatal("remote exec accepted piped confirmation")
	}
	t.Run("terminal confirmation", func(t *testing.T) {
		script, err := exec.LookPath("script")
		if err != nil {
			t.Skip("script is required to allocate the controlling terminal")
		}
		awk, err := exec.LookPath("awk")
		if err != nil {
			t.Skip("awk is required to check the injected environment")
		}
		const checkEnv = `BEGIN { if (length(ENVIRON["REMOTE_FIXTURE"]) > 0) { print "injected"; print ENVIRON["REMOTE_FIXTURE"] } else { exit 1 } }`
		args := []string{"-q", "/dev/null", binary, "remote", "exec", "--env", "REMOTE_FIXTURE=fixture", "--", awk, checkEnv}
		if runtime.GOOS == "linux" {
			args = []string{"-q", "-e", "-c", `exec "$KEYREF_TEST_BIN" remote exec --env REMOTE_FIXTURE=fixture -- "$KEYREF_TEST_AWK" "$KEYREF_TEST_PROGRAM"`, "/dev/null"}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, script, args...)
		cmd.WaitDelay = time.Second
		cmd.Env = append(env("device-b"), "KEYREF_TEST_BIN="+binary, "KEYREF_TEST_AWK="+awk, "KEYREF_TEST_PROGRAM="+checkEnv)
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		cmd.Stdin = reader
		if _, err := io.WriteString(writer, "y\n"); err != nil {
			t.Fatal(err)
		}
		out, err := cmd.CombinedOutput()
		if bytes.Contains(out, []byte(value)) {
			t.Fatal("terminal execution leaked the fixture value")
		}
		if err != nil || !bytes.Contains(out, []byte("injected\r\n")) {
			t.Fatalf("terminal confirmation did not inject the credential: %v, output %q", err, out)
		}
	})
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

func TestRemoteCommandPolicyMigration(t *testing.T) {
	ctx := t.Context()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "metadata.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	wrapping := base64.StdEncoding.EncodeToString(make([]byte, 32))
	v, err := Open(ctx, db, wrapping, "fixture", "42")
	if err != nil {
		t.Fatal(err)
	}
	session, err := v.issue(ctx, 42)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(session.VaultKey)
	cipher := remote.CipherKey(session.VaultKey)
	defer clear(cipher)
	id := remote.ItemID(session.VaultKey, "fixture")
	aad := remote.ItemAAD(id, "meta")
	blob, err := crypto.SealBlob(cipher, aad, []byte(`{"ref":"fixture","description":"Keep this","allow_commands":["curl"]}`))
	if err != nil {
		t.Fatal(err)
	}
	value, err := crypto.SealBlob(cipher, remote.ItemAAD(id, "value"), []byte("synthetic-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, "INSERT INTO account_items VALUES (42,?,?,?)", id, blob, value); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, "DELETE FROM account_vault_migrations"); err != nil {
		t.Fatal(err)
	}
	v, err = Open(ctx, db, wrapping, "fixture", "42")
	if err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		var meta, after []byte
		if err := db.DB().QueryRowContext(ctx, "SELECT metadata,value FROM account_items WHERE account=42 AND id=?", id).Scan(&meta, &after); err != nil {
			t.Fatal(err)
		}
		raw, err := crypto.OpenBlob(cipher, aad, meta)
		if err != nil || bytes.Contains(raw, []byte("allow_commands")) || !bytes.Contains(raw, []byte("Keep this")) || !bytes.Equal(value, after) {
			t.Fatal("expected clean metadata with the original description and value ciphertext")
		}
	}
	check()

	body, err := json.Marshal(remote.Item{ID: id, Metadata: blob, Value: value})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, remote.Path+"items/"+id, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+session.Token)
	result := httptest.NewRecorder()
	v.Handler().ServeHTTP(result, req)
	if result.Code != http.StatusNoContent {
		t.Fatalf("legacy write returned %d", result.Code)
	}
	check()
}
