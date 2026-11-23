//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type importEnvStoredRow struct {
	id   string
	blob []byte
	meta []byte
}

func importEnvSnapshot(t *testing.T, path string) ([]importEnvStoredRow, int64) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal("could not open synthetic vault")
	}
	defer db.Close()
	var writes int64
	if err := db.QueryRow("SELECT writes FROM metadata").Scan(&writes); err != nil {
		t.Fatal("could not read the synthetic write counter")
	}
	rows, err := db.Query("SELECT id, blob, meta FROM entries ORDER BY id")
	if err != nil {
		t.Fatal("could not inspect synthetic ciphertext")
	}
	defer rows.Close()
	var result []importEnvStoredRow
	for rows.Next() {
		var r importEnvStoredRow
		if err := rows.Scan(&r.id, &r.blob, &r.meta); err != nil {
			t.Fatal("could not inspect synthetic row")
		}
		result = append(result, r)
	}
	if rows.Err() != nil {
		t.Fatal("could not finish inspecting synthetic rows")
	}
	return result, writes
}

func equalImportEnvSnapshots(a, b []importEnvStoredRow) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].id != b[i].id || !bytes.Equal(a[i].blob, b[i].blob) || !bytes.Equal(a[i].meta, b[i].meta) {
			return false
		}
	}
	return true
}

func assertImportEnvFilesClean(t *testing.T, roots, values []string) {
	t.Helper()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if os.IsNotExist(err) && path == root {
				return nil
			}
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, value := range values {
				assertProviderValueAbsent(t, value, string(data))
			}
			return nil
		})
		if err != nil {
			t.Fatal("could not scan synthetic vault and state files")
		}
	}
}

// This exercises the real Keyref CLI with a synthetic input file and an
// in-process loopback receiver, not the Neowind consumer.
func TestImportEnvWorkflow(t *testing.T) {
	first, second, unselected, replacement := rand.Text(), rand.Text(), rand.Text(), rand.Text()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal("could not generate a synthetic master key")
	}
	defer clear(master)
	home, keyringDir, _ := localHome(t)
	configDir, stateDir := t.TempDir(), t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "synthetic.env")
	env := localEnv(home, keyringDir,
		"KEYREF_LOCAL_MASTER="+base64.StdEncoding.EncodeToString(master),
		"XDG_CONFIG_HOME="+configDir, "NEOWIND_STATE_DIR="+stateDir)
	if r := localRun(t, env, "", "init", "--vault", "local"); r.code != 0 {
		t.Fatalf("synthetic vault initialization failed: exit %d", r.code)
	}
	input := "# synthetic input\nexport FIRST='" + first + "'\nSECOND=\"" + second + "\" # comment\nUNSELECTED=" + unselected + "\n"
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatal("could not write synthetic input")
	}
	args := []string{"import-env", "--vault", "local", "--file", inputPath,
		"--map", "FIRST=first", "--map", "SECOND=second"}
	created := localRun(t, env, "", args...)
	for _, value := range []string{first, second, unselected, replacement} {
		assertProviderValueAbsent(t, value, created.stdout, created.stderr)
	}
	if created.code != 0 || created.stderr != "" || created.stdout != "FIRST\tfirst\tcreated\nSECOND\tsecond\tcreated\n" {
		t.Fatalf("synthetic import did not report two creates: exit %d", created.code)
	}
	if r := localRun(t, env, "", "get", "unselected", "--vault", "local"); r.code != 11 {
		t.Fatalf("unselected variable unexpectedly created an entry: exit %d", r.code)
	}

	// The child can use the original value, and captured output is redacted.
	// The receiver reports only an accepted-request count, never the header.
	var accepted atomic.Int32
	var expected atomic.Value
	expected.Store(first)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || r.Method != http.MethodPost || string(body) != `{"probe":true}` ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+expected.Load().(string))) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		accepted.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	run := localRun(t, env, "", "exec", "--vault", "local", "--env", "JEV_API_KEY=first",
		"--pass", "XDG_CONFIG_HOME", "--pass", "NEOWIND_STATE_DIR", "--",
		helperBin, "provider-env", server.URL, "JEV_API_KEY", filepath.Join(stateDir, "started"))
	assertProviderValueAbsent(t, first, run.stdout, run.stderr)
	if run.code != 0 || accepted.Load() != 1 || !strings.Contains(run.stdout, "credential=<redacted:first>") ||
		!strings.Contains(run.stderr, "credential-base64=<redacted:first>") {
		t.Fatalf("imported value did not reach the synthetic receiver with redacted output: exit %d", run.code)
	}

	vaultPath := filepath.Join(home, "local.db")
	before, writesBefore := importEnvSnapshot(t, vaultPath)
	unchanged := localRun(t, env, "", args...)
	for _, value := range []string{first, second, unselected, replacement} {
		assertProviderValueAbsent(t, value, unchanged.stdout, unchanged.stderr)
	}
	if unchanged.code != 0 || unchanged.stdout != "FIRST\tfirst\tunchanged\nSECOND\tsecond\tunchanged\n" {
		t.Fatalf("repeat import did not report unchanged: exit %d", unchanged.code)
	}
	after, writesAfter := importEnvSnapshot(t, vaultPath)
	if writesBefore != writesAfter || !equalImportEnvSnapshots(before, after) {
		t.Fatal("repeat import rewrote ciphertext or advanced the write counter")
	}

	// A later malformed line must reject the whole file, before the new
	// value can replace the first entry.
	if err := os.WriteFile(inputPath, []byte("FIRST="+replacement+"\nnot-an-assignment\nSECOND="+second+"\n"), 0o600); err != nil {
		t.Fatal("could not write invalid synthetic input")
	}
	invalid := localRun(t, env, "", args...)
	for _, value := range []string{first, second, unselected, replacement} {
		assertProviderValueAbsent(t, value, invalid.stdout, invalid.stderr)
	}
	if invalid.code == 0 || invalid.stdout != "" || !strings.Contains(invalid.stderr, "line 2: INVALID_ASSIGNMENT") {
		t.Fatalf("invalid input did not fail safely: exit %d", invalid.code)
	}
	after, writesAfter = importEnvSnapshot(t, vaultPath)
	if writesBefore != writesAfter || !equalImportEnvSnapshots(before, after) {
		t.Fatal("invalid input changed the vault")
	}

	// A replacement retains the existing host restrictions.
	set := localRun(t, env, first, "set", "first", "--vault", "local",
		"--allow-host", "127.0.0.1")
	assertProviderValueAbsent(t, first, set.stdout, set.stderr)
	if set.code != 0 {
		t.Fatalf("could not set synthetic policy: exit %d", set.code)
	}
	if err := os.WriteFile(inputPath, []byte("FIRST="+replacement+"\nSECOND="+second+"\n"), 0o600); err != nil {
		t.Fatal("could not write replacement input")
	}
	before, writesBefore = importEnvSnapshot(t, vaultPath)
	replaced := localRun(t, env, "", args...)
	for _, value := range []string{first, second, unselected, replacement} {
		assertProviderValueAbsent(t, value, replaced.stdout, replaced.stderr)
	}
	if replaced.code != 0 || replaced.stdout != "FIRST\tfirst\treplaced\nSECOND\tsecond\tunchanged\n" {
		t.Fatalf("replacement did not report the expected statuses: exit %d", replaced.code)
	}
	after, writesAfter = importEnvSnapshot(t, vaultPath)
	changed := 0
	if len(before) != len(after) {
		t.Fatal("replacement changed the number of rows")
	}
	for i := range before {
		if !equalImportEnvSnapshots(before[i:i+1], after[i:i+1]) {
			changed++
		}
	}
	if changed != 1 || writesAfter != writesBefore+1 {
		t.Fatal("replacement did not update exactly one row")
	}

	expected.Store(replacement)
	run = localRun(t, env, "", "exec", "--vault", "local", "--env", "JEV_API_KEY=first",
		"--pass", "XDG_CONFIG_HOME", "--pass", "NEOWIND_STATE_DIR", "--",
		helperBin, "provider-env", server.URL, "JEV_API_KEY", filepath.Join(stateDir, "started"))
	assertProviderValueAbsent(t, replacement, run.stdout, run.stderr)
	if run.code != 0 || accepted.Load() != 2 || !strings.Contains(run.stdout, "credential=<redacted:first>") {
		t.Fatalf("replacement was not delivered safely: exit %d", run.code)
	}
	wrongHostMarker := filepath.Join(stateDir, "wrong-host-started")
	wrongHost := localRun(t, env, "", "exec", "--vault", "local", "--env", "JEV_API_KEY=first",
		"--pass", "XDG_CONFIG_HOME", "--pass", "NEOWIND_STATE_DIR", "--",
		helperBin, "provider-env", "http://example.invalid/", "JEV_API_KEY", wrongHostMarker)
	assertProviderValueAbsent(t, replacement, wrongHost.stdout, wrongHost.stderr)
	if wrongHost.code != 10 {
		t.Fatalf("replacement lost the host restriction: exit %d", wrongHost.code)
	}
	if _, err := os.Stat(wrongHostMarker); !os.IsNotExist(err) {
		t.Fatal("consumer started for a disallowed host")
	}
	assertImportEnvFilesClean(t, []string{home, keyringDir, configDir, stateDir},
		[]string{first, second, unselected, replacement})
}
