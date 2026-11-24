package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/source"
	"github.com/lidessen/keyref/lib/local"
)

func doctorFixture(t *testing.T) config.Paths {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYREF_HOME", dir)
	t.Setenv("KEYREF_SOURCE", "")
	key := bytes.Repeat([]byte{7}, 32)
	t.Setenv("KEYREF_LOCAL_MASTER", base64.StdEncoding.EncodeToString(key))
	vault, err := local.Create(filepath.Join(dir, "local.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = vault.Put(context.Background(), "sample", []byte("synthetic-value-not-for-output"), local.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = vault.Close(); err != nil {
		t.Fatal(err)
	}
	return config.Paths{Dir: dir, CacheFile: filepath.Join(dir, "cache.sqlite"), LockFile: filepath.Join(dir, "locked")}
}

func TestDoctorLocalMetadataAndPermissions(t *testing.T) {
	p := doctorFixture(t)
	report, err := inspectDoctor(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if report.Source != "local" || report.SourceReason != "built-in local default" || report.Schema != "ok (metadata only; key not verified)" || report.KeyAvailable == nil || !*report.KeyAvailable {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.DirectoryPermissions != "ok" || report.StorePermissions != "ok" {
		t.Fatalf("unexpected permissions: %+v", report)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(os.Getenv("KEYREF_LOCAL_MASTER"))) || bytes.Contains(data, []byte("synthetic-value-not-for-output")) {
		t.Fatal("report contains sensitive material")
	}
	if err := os.Chmod(p.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(p.Dir, "local.db"), 0644); err != nil {
		t.Fatal(err)
	}
	report, err = inspectDoctor(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(report.DirectoryPermissions, "insecure") || !strings.HasPrefix(report.StorePermissions, "insecure") {
		t.Fatalf("missing warning: %+v", report)
	}
	info, _ := os.Stat(p.Dir)
	if info.Mode().Perm() != 0755 {
		t.Fatal("doctor changed directory mode")
	}
	if _, err := os.Stat(source.Path(p)); !os.IsNotExist(err) {
		t.Fatalf("doctor created config: %v", err)
	}
}

func TestDoctorResolutionPrecedenceAndMissing(t *testing.T) {
	p := doctorFixture(t)
	if err := os.WriteFile(source.Path(p), []byte(`{"default":"sync"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ env, override, name, reason string }{{"", "", "sync", "sources.json"}, {"local", "", "local", "KEYREF_SOURCE"}, {"local", "sync", "sync", "--vault"}} {
		t.Setenv("KEYREF_SOURCE", tc.env)
		spec, reason, err := doctorSource(p, tc.override)
		if err != nil || spec.Name != tc.name || reason != tc.reason {
			t.Fatalf("got %s %s %v", spec.Name, reason, err)
		}
	}
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("KEYREF_HOME", missing)
	t.Setenv("KEYREF_SOURCE", "")
	t.Setenv("KEYREF_LOCAL_MASTER", "invalid")
	paths, err := readOnlyPaths()
	if err != nil {
		t.Fatal(err)
	}
	report, err := inspectDoctor(paths, "")
	if err != nil {
		t.Fatal(err)
	}
	if report.DirectoryPermissions != "missing" || report.StorePermissions != "missing" || report.KeyAvailable == nil || *report.KeyAvailable {
		t.Fatalf("unexpected report: %+v", report)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("doctor created missing directory")
	}
}

func TestDoctorLegacyPairingAndActiveWAL(t *testing.T) {
	p := doctorFixture(t)
	db, err := sql.Open("sqlite", p.CacheFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE kv(k TEXT PRIMARY KEY, v BLOB NOT NULL); INSERT INTO kv VALUES ('vault_id', x'01')"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	spec, reason, err := doctorSource(p, "")
	if err != nil || spec.Name != "sync" || reason != "legacy paired vault migration" {
		t.Fatalf("legacy source: %+v %s %v", spec, reason, err)
	}
	if _, err = os.Stat(source.Path(p)); !os.IsNotExist(err) {
		t.Fatal("legacy source inspection wrote configuration")
	}
	if err = os.WriteFile(p.CacheFile+"-wal", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = doctorSource(p, ""); err == nil {
		t.Fatal("active WAL was silently ignored")
	}
}

func TestExecDryRunDoesNotSpawnOrExposeValues(t *testing.T) {
	p := doctorFixture(t)
	spec := source.Spec{Name: "local", Kind: source.KindLocal, Path: filepath.Join(p.Dir, "local.db")}
	marker := filepath.Join(p.Dir, "spawned")
	for _, tc := range []struct {
		name string
		argv []string
		ref  string
		want int
	}{
		{"allowed", []string{"/usr/bin/touch", marker}, "sample", 0},
		{"denied", []string{"/bin/sh", "-c", "exit 0"}, "sample", 10},
		{"missing", []string{"/usr/bin/touch", marker}, "absent", 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			opts := execOptions{DryRun: true, EnvRefs: []string{"TOKEN=" + tc.ref}, Argv: tc.argv, Stdout: &out, Stderr: &stderr}
			code := runLocalExec(p, opts, spec)
			if code != tc.want {
				t.Fatalf("exit %d; stderr %s", code, stderr.String())
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("child spawned")
			}
			if strings.Contains(out.String()+stderr.String(), "synthetic-value-not-for-output") {
				t.Fatal("secret exposed")
			}
			if code == 0 && (!strings.Contains(out.String(), "sample") || !strings.Contains(out.String(), "TOKEN") || !strings.Contains(out.String(), "environment scrubbed")) {
				t.Fatalf("incomplete plan: %s", out.String())
			}
		})
	}
}

func TestDoctorJSONAndExecDryRunCLI(t *testing.T) {
	p := doctorFixture(t)
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()
	code := dispatch("doctor", []string{"--json"})
	w.Close()
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil || code != 0 {
		t.Fatalf("doctor: exit %d, read error %v", code, err)
	}
	var report doctorReport
	if err := json.Unmarshal(data, &report); err != nil || report.Source != "local" {
		t.Fatalf("invalid doctor JSON: %v", err)
	}
	marker := filepath.Join(p.Dir, "cli-spawned")
	r, w, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code = dispatch("exec", []string{"--dry-run", "--env", "TOKEN=sample", "--", "/usr/bin/touch", marker})
	w.Close()
	data, err = io.ReadAll(r)
	r.Close()
	if err != nil || code != 0 || !bytes.Contains(data, []byte("command policy: allowed")) {
		t.Fatalf("dry run: exit %d, read error %v, output %s", code, err, data)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("CLI dry run spawned a child")
	}
}
