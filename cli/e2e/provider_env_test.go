//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestProviderEnvironmentContract verifies Keyref's half of the Neowind
// contract with a transport fixture. It does not claim to test Neowind's
// consumer or persistence behavior. All credentials are generated in memory.
func TestProviderEnvironmentContract(t *testing.T) {
	for _, envName := range []string{"JEV_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"} {
		t.Run(envName, func(t *testing.T) {
			providerContractCase(t, envName, "allowed", 0)
		})
	}
	for _, tc := range []struct {
		name string
		code int
	}{
		{"missing-ref", 11},
		{"locked", 12},
		{"wrong-consumer", 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			providerContractCase(t, "JEV_API_KEY", tc.name, tc.code)
		})
	}
}

func providerContractCase(t *testing.T, envName, scenario string, wantCode int) {
	t.Helper()
	const ref = "neowind-provider"
	value := "synthetic-provider-" + rand.Text()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal("could not generate a synthetic master key")
	}
	defer clear(master)
	home, keyringDir, _ := localHome(t)
	configDir := t.TempDir()
	stateDir := t.TempDir()
	marker := filepath.Join(stateDir, "consumer-started")
	env := localEnv(home, keyringDir,
		"KEYREF_LOCAL_MASTER="+base64.StdEncoding.EncodeToString(master),
		"XDG_CONFIG_HOME="+configDir,
		"NEOWIND_STATE_DIR="+stateDir,
		envName+"=synthetic-parent-decoy",
		"UNRELATED_PROVIDER_KEY=synthetic-unrelated-value")
	initialized := localRun(t, env, "", "init", "--source", "local")
	if initialized.code != 0 {
		t.Fatalf("fixture initialization exit %d", initialized.code)
	}
	assertProviderValueAbsent(t, value, initialized.stdout, initialized.stderr)
	consumer := filepath.Base(helperBin)
	if scenario == "wrong-consumer" {
		consumer = "another-consumer"
	}
	stored := localRun(t, env, value, "set", ref, "--source", "local", "--allow-command", consumer)
	if stored.code != 0 {
		t.Fatalf("fixture set exit %d", stored.code)
	}
	assertProviderValueAbsent(t, value, stored.stdout, stored.stderr)
	for _, args := range [][]string{{"get", ref, "--source", "local"}, {"list", "--source", "local", "--format", "json"}} {
		r := localRun(t, env, "", args...)
		if r.code != 0 {
			t.Fatalf("metadata read exit %d", r.code)
		}
		assertProviderValueAbsent(t, value, r.stdout, r.stderr)
	}
	if scenario == "locked" {
		r := localRun(t, env, "", "lock")
		if r.code != 0 {
			t.Fatalf("fixture lock exit %d", r.code)
		}
	}
	var requests, authenticated atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 || r.Method != http.MethodPost ||
			string(body) != `{"probe":true}` || bytes.Contains(body, []byte(value)) ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+value)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		authenticated.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	selected := ref
	if scenario == "missing-ref" {
		selected = "missing-provider"
	}
	r := localRun(t, env, "", "exec", "--source", "local", "--env", envName+"="+selected,
		"--pass", "XDG_CONFIG_HOME", "--pass", "NEOWIND_STATE_DIR", "--",
		helperBin, "provider-env", server.URL, envName, marker)
	assertProviderValueAbsent(t, value, r.stdout, r.stderr)
	if r.code != wantCode {
		t.Fatalf("provider exec exit %d, want %d", r.code, wantCode)
	}
	if wantCode == 0 {
		if requests.Load() != 1 || authenticated.Load() != 1 {
			t.Fatal("receiver did not accept exactly one request with the injected credential")
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatal("successful consumer did not write its start marker")
		}
		if !strings.Contains(r.stdout, "provider-ok\ncredential=<redacted:"+ref+">") ||
			!strings.Contains(r.stderr, "credential-base64=<redacted:"+ref+">") {
			t.Fatal("captured raw stdout or encoded stderr was not redacted")
		}
	} else {
		if requests.Load() != 0 {
			t.Fatal("rejected execution contacted the provider")
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("rejected execution started the consumer")
		}
	}

	// This covers only files produced by this Keyref fixture. Neowind's
	// own journals, receipts and plans require the separate consumer run.
	for _, root := range []string{home, keyringDir, configDir, stateDir} {
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
			assertProviderValueAbsent(t, value, string(data))
			return nil
		})
		if err != nil {
			t.Fatal("could not scan the isolated fixture files")
		}
	}
}

func assertProviderValueAbsent(t *testing.T, value string, outputs ...string) {
	t.Helper()
	data := []byte(value)
	for _, variant := range []string{
		value,
		base64.StdEncoding.EncodeToString(data), base64.RawStdEncoding.EncodeToString(data),
		base64.URLEncoding.EncodeToString(data), base64.RawURLEncoding.EncodeToString(data),
		hex.EncodeToString(data), strings.ToUpper(hex.EncodeToString(data)),
	} {
		for _, output := range outputs {
			if strings.Contains(output, variant) {
				t.Fatal("synthetic provider credential appeared in a captured output or fixture file")
			}
		}
	}
}
