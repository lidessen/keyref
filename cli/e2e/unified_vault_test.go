//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/proto/remote"
)

func TestUnifiedLocalAndRemoteVaults(t *testing.T) {
	home, ringDir, env := localHome(t)
	var mu sync.Mutex
	var stored remote.Item
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, remote.Path+"items/"):
			if err := json.NewDecoder(r.Body).Decode(&stored); err != nil {
				http.Error(w, "bad item", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == remote.Path+"items":
			item := stored
			item.Value = nil
			_ = json.NewEncoder(w).Encode([]remote.Item{item})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	env = append(env, "KEYREF_SERVER="+server.URL)
	store, err := keyring.NewDirStore(ringDir)
	if err != nil {
		t.Fatal(err)
	}
	session, err := json.Marshal(remote.Session{Token: strings.Repeat("ab", 32), VaultKey: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("keyref-remote", server.URL+"|"+home, string(session)); err != nil {
		t.Fatal(err)
	}

	run := func(stdin string, args ...string) string {
		t.Helper()
		result := localRun(t, env, stdin, args...)
		if result.code != 0 {
			t.Fatalf("%v exited %d: %s", args, result.code, result.stderr)
		}
		assertNoLocalLeak(t, strings.Join(args, " "), result.stdout, result.stderr)
		return result.stdout
	}
	list := func(args ...string) []struct{ Ref, Source, Description string } {
		t.Helper()
		raw := run("", append([]string{"list", "--format", "json"}, args...)...)
		var entries []struct{ Ref, Source, Description string }
		if err := json.Unmarshal([]byte(raw), &entries); err != nil {
			t.Fatal(err)
		}
		return entries
	}

	run(localSecret, "set", "same-ref", "--description", "account entry")
	if rows := list(); len(rows) != 1 || rows[0].Source != "remote" || rows[0].Description != "account entry" {
		t.Fatalf("unexpected remote-only list: %+v", rows)
	}

	run("", "init")
	if ambiguous := localRun(t, env, localSecret, "set", "same-ref"); ambiguous.code != 2 || !strings.Contains(ambiguous.stderr, "--source NAME") {
		t.Fatalf("ambiguous write: exit %d, %s", ambiguous.code, ambiguous.stderr)
	}
	run(localSecret, "set", "same-ref", "--source", "local")
	if rows := list(); len(rows) != 2 || rows[0].Source != "local" || rows[1].Source != "remote" || rows[0].Ref != rows[1].Ref {
		t.Fatalf("unexpected combined list: %+v", rows)
	}
	run(localSecret, "set", "same-ref", "--source", "remote", "--description", "updated")
	if rows := list("--source", "remote"); len(rows) != 1 || rows[0].Description != "updated" {
		t.Fatalf("unexpected filtered list: %+v", rows)
	}
}
