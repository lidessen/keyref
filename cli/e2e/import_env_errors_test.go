//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportEnvOutputCollisions(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal("could not generate a synthetic master key")
	}
	defer clear(master)
	home, keyringDir, _ := localHome(t)
	env := localEnv(home, keyringDir, "KEYREF_LOCAL_MASTER="+base64.StdEncoding.EncodeToString(master))
	if r := localRun(t, env, "", "init", "--source", "local"); r.code != 0 {
		t.Fatalf("synthetic vault initialization failed: exit %d", r.code)
	}
	path := filepath.Join(t.TempDir(), "synthetic.env")
	vaultPath := filepath.Join(home, "local.db")
	before, writesBefore := importEnvSnapshot(t, vaultPath)
	name := "V_" + rand.Text()
	ref := "r" + strings.ToLower(rand.Text())
	other := rand.Text()
	status := strings.Join([]string{"cre", "ated"}, "")
	conflictCode := strings.Join([]string{"OUTPUT", "CONFLICT"}, "_")
	sourceCode := strings.Join([]string{"SOURCE", "ERROR"}, "_")
	assignmentCode := strings.Join([]string{"INVALID", "ASSIGNMENT"}, "_")
	for _, tc := range []struct {
		name    string
		input   string
		maps    []string
		source  string
		values  []string
		code    int
		message string
	}{
		{"selected name", "TOKEN=" + name + "\n" + name + "=" + other + "\n", []string{"TOKEN=first", name + "=second"}, "local", []string{name, other}, 2, "OUTPUT_CONFLICT"},
		{"unselected value", name + "=" + other + "\nUNSELECTED=" + name + "\n", []string{name + "=first"}, "local", []string{name, other}, 2, "OUTPUT_CONFLICT"},
		{"ref", "TOKEN=" + ref + "\n", []string{"TOKEN=" + ref}, "local", []string{ref}, 2, "OUTPUT_CONFLICT"},
		{"status", "TOKEN=" + status + "\n", []string{"TOKEN=first"}, "local", []string{status}, 2, "OUTPUT_CONFLICT"},
		{"conflict diagnostic", "TOKEN=" + conflictCode + "\n" + conflictCode + "=" + other + "\n", []string{"TOKEN=first", conflictCode + "=second"}, "local", []string{conflictCode, other}, 2, ""},
		{"source diagnostic", "TOKEN=" + other + "\nUNSELECTED=" + sourceCode + "\n", []string{"TOKEN=first"}, "missing-source", []string{sourceCode, other}, 1, ""},
		{"later value in diagnostic", "invalid line\nUNSELECTED=" + assignmentCode + "\nTOKEN=" + other + "\n", []string{"TOKEN=first"}, "local", []string{assignmentCode, other}, 2, ""},
		{"malformed quoted value", "TOKEN=\"" + other + `\"$BAD` + "\n", []string{"TOKEN=first"}, "local", []string{other}, 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.input), 0o600); err != nil {
				t.Fatal("could not write synthetic input")
			}
			args := []string{"import-env", "--source", tc.source, "--file", path}
			for _, mapping := range tc.maps {
				args = append(args, "--map", mapping)
			}
			r := localRun(t, env, "", args...)
			for _, value := range tc.values {
				assertProviderValueAbsent(t, value, r.stdout, r.stderr)
			}
			if r.code != tc.code || r.stdout != "" || (tc.message == "" && r.stderr != "") ||
				(tc.message != "" && !strings.Contains(r.stderr, tc.message)) {
				t.Fatalf("collision did not fail safely: exit %d", r.code)
			}
			after, writesAfter := importEnvSnapshot(t, vaultPath)
			if writesBefore != writesAfter || !equalImportEnvSnapshots(before, after) {
				t.Fatal("rejected import changed the vault")
			}
		})
	}
}

func TestImportEnvPreReadDiagnosticIsFixed(t *testing.T) {
	// The command rejects missing mappings before it reads the file. Its
	// fixed diagnostic can therefore coincide with a value in that file.
	value := strings.Join([]string{"INVALID", "MAPPING", "COUNT"}, "_")
	path := filepath.Join(t.TempDir(), "synthetic.env")
	if err := os.WriteFile(path, []byte("TOKEN="+value+"\n"), 0o600); err != nil {
		t.Fatal("could not write synthetic input")
	}
	_, _, env := localHome(t)
	r := localRun(t, env, "", "import-env", "--file", path)
	if r.code != 2 || r.stdout != "" || r.stderr != "keyref: import-env: "+value+"\n" {
		t.Fatalf("pre-read diagnostic changed: exit %d", r.code)
	}
}

func TestImportEnvRejectsBareFinalCarriageReturn(t *testing.T) {
	original, replacement, unselected := rand.Text(), rand.Text(), rand.Text()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal("could not generate a synthetic master key")
	}
	defer clear(master)
	home, keyringDir, _ := localHome(t)
	env := localEnv(home, keyringDir, "KEYREF_LOCAL_MASTER="+base64.StdEncoding.EncodeToString(master))
	if r := localRun(t, env, "", "init", "--source", "local"); r.code != 0 {
		t.Fatalf("synthetic vault initialization failed: exit %d", r.code)
	}
	path := filepath.Join(t.TempDir(), "synthetic.env")
	args := []string{"import-env", "--source", "local", "--file", path, "--map", "TOKEN=token"}
	if err := os.WriteFile(path, []byte("TOKEN="+original+"\r\n"), 0o600); err != nil {
		t.Fatal("could not write synthetic input")
	}
	seed := localRun(t, env, "", args...)
	assertProviderValueAbsent(t, original, seed.stdout, seed.stderr)
	if seed.code != 0 || seed.stdout != "TOKEN\ttoken\tcreated\n" || seed.stderr != "" {
		t.Fatalf("CRLF import failed: exit %d", seed.code)
	}
	vaultPath := filepath.Join(home, "local.db")
	before, writesBefore := importEnvSnapshot(t, vaultPath)
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"selected", "TOKEN=" + replacement + "\r"},
		{"unselected", "TOKEN=" + replacement + "\nOTHER=" + unselected + "\r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.input), 0o600); err != nil {
				t.Fatal("could not write synthetic input")
			}
			r := localRun(t, env, "", args...)
			for _, value := range []string{original, replacement, unselected} {
				assertProviderValueAbsent(t, value, r.stdout, r.stderr)
			}
			if r.code != 2 || r.stdout != "" || r.stderr != "" {
				t.Fatalf("bare carriage return was not rejected safely: exit %d", r.code)
			}
			after, writesAfter := importEnvSnapshot(t, vaultPath)
			if writesBefore != writesAfter || !equalImportEnvSnapshots(before, after) {
				t.Fatal("rejected import changed the vault")
			}
		})
	}
}

func TestImportEnvKeyringErrorDoesNotExposePath(t *testing.T) {
	value := rand.Text()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal("could not generate a synthetic master key")
	}
	defer clear(master)
	home, keyringDir, _ := localHome(t)
	masterEnv := "KEYREF_LOCAL_MASTER=" + base64.StdEncoding.EncodeToString(master)
	env := localEnv(home, keyringDir, masterEnv)
	if r := localRun(t, env, "", "init", "--source", "local"); r.code != 0 {
		t.Fatalf("synthetic vault initialization failed: exit %d", r.code)
	}
	root := t.TempDir()
	parent := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(parent, nil, 0o600); err != nil {
		t.Fatal("could not create a synthetic path obstacle")
	}
	badKeyringDir := filepath.Join(parent, value)
	inputPath := filepath.Join(t.TempDir(), "synthetic.env")
	if err := os.WriteFile(inputPath, []byte("TOKEN="+value+"\n"), 0o600); err != nil {
		t.Fatal("could not create synthetic input")
	}
	vaultPath := filepath.Join(home, "local.db")
	before, writesBefore := importEnvSnapshot(t, vaultPath)
	badEnv := localEnv(home, badKeyringDir, masterEnv)
	r := localRun(t, badEnv, "", "import-env", "--source", "local", "--file", inputPath, "--map", "TOKEN=first")
	assertProviderValueAbsent(t, value, r.stdout, r.stderr)
	if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, "SOURCE_ERROR") || strings.Contains(r.stderr, parent) {
		t.Fatalf("keyring failure did not return a safe diagnostic: exit %d", r.code)
	}
	after, writesAfter := importEnvSnapshot(t, vaultPath)
	if writesBefore != writesAfter || !equalImportEnvSnapshots(before, after) {
		t.Fatal("keyring failure changed the vault")
	}
}

func TestImportEnvRejectsInvalidArgumentsAndSources(t *testing.T) {
	value := rand.Text()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal("could not generate a synthetic master key")
	}
	defer clear(master)
	home, keyringDir, _ := localHome(t)
	env := localEnv(home, keyringDir, "KEYREF_LOCAL_MASTER="+base64.StdEncoding.EncodeToString(master))
	if r := localRun(t, env, "", "init", "--source", "local"); r.code != 0 {
		t.Fatalf("synthetic vault initialization failed: exit %d", r.code)
	}
	path := filepath.Join(t.TempDir(), "synthetic.env")
	if err := os.WriteFile(path, []byte("TOKEN="+value+"\n"), 0o600); err != nil {
		t.Fatal("could not create synthetic input")
	}
	before, writesBefore := importEnvSnapshot(t, filepath.Join(home, "local.db"))
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"missing mapping", []string{"--source", "local", "--file", path}, 2, "INVALID_MAPPING_COUNT"},
		{"invalid mapping", []string{"--source", "local", "--file", path, "--map", "TOKEN=" + value}, 2, "INVALID_MAPPING"},
		{"duplicate ref", []string{"--source", "local", "--file", path, "--map", "TOKEN=tok", "--map", "OTHER=tok"}, 2, "DUPLICATE_MAPPING"},
		{"missing name", []string{"--source", "local", "--file", path, "--map", "OTHER=tok"}, 2, "MISSING_VARIABLE"},
		{"unknown flag", []string{"--source", "local", "--file", path, "--map", "TOKEN=tok", "--unexpected=" + value}, 2, "INVALID_ARGUMENTS"},
		{"sync source", []string{"--source", "sync", "--file", path, "--map", "TOKEN=tok"}, 2, "SOURCE_READ_ONLY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := localRun(t, env, "", append([]string{"import-env"}, tc.args...)...)
			assertProviderValueAbsent(t, value, r.stdout, r.stderr)
			if r.code != tc.code || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("invalid import did not fail safely: exit %d", r.code)
			}
		})
	}
	if r := localRun(t, env, "", "lock"); r.code != 0 {
		t.Fatalf("could not lock synthetic vault: exit %d", r.code)
	}
	locked := localRun(t, env, "", "import-env", "--source", "local", "--file", path, "--map", "TOKEN=tok")
	assertProviderValueAbsent(t, value, locked.stdout, locked.stderr)
	if locked.code != 12 || locked.stdout != "" || !strings.Contains(locked.stderr, "SOURCE_LOCKED") {
		t.Fatalf("locked import was not rejected: exit %d", locked.code)
	}
	after, writesAfter := importEnvSnapshot(t, filepath.Join(home, "local.db"))
	if writesBefore != writesAfter || !equalImportEnvSnapshots(before, after) {
		t.Fatal("rejected imports changed the vault")
	}
}
