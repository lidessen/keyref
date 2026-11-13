package source

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidessen/keyref/cli/internal/config"
)

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	return config.Paths{Dir: t.TempDir()}
}

func TestDefaultIsTheLocalVault(t *testing.T) {
	p := testPaths(t)
	spec, err := Resolve(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != LocalName || spec.Kind != KindLocal {
		t.Fatalf("default source = %+v, want local", spec)
	}
	if spec.Path != filepath.Join(p.Dir, "local.db") {
		t.Fatalf("local path = %q", spec.Path)
	}
}

func TestFlagBeatsEnvBeatsConfiguredDefault(t *testing.T) {
	p := testPaths(t)
	if err := SetDefault(p, SyncName); err != nil {
		t.Fatal(err)
	}
	spec, err := Resolve(p, "")
	if err != nil || spec.Name != SyncName {
		t.Fatalf("configured default = %+v, %v", spec, err)
	}
	t.Setenv(EnvSource, LocalName)
	if spec, _ = Resolve(p, ""); spec.Name != LocalName {
		t.Fatalf("environment should win over the configured default, got %+v", spec)
	}
	if spec, _ = Resolve(p, SyncName); spec.Name != SyncName {
		t.Fatalf("--source should win over the environment, got %+v", spec)
	}
}

// A data directory that already holds a paired vault keeps its old
// behaviour: the commands used to mean the paired vault and nothing else.
func TestEnsureMigratesAPairedVaultToSync(t *testing.T) {
	p := testPaths(t)
	if err := Ensure(p, true); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Default != SyncName {
		t.Fatalf("migrated default = %q, want sync", cfg.Default)
	}
	// A later run must not flip it back.
	if err := Ensure(p, false); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = Load(p); cfg.Default != SyncName {
		t.Fatalf("Ensure overwrote an existing configuration: %q", cfg.Default)
	}
}

func TestFreshDirectoryDefaultsToLocal(t *testing.T) {
	p := testPaths(t)
	if err := Ensure(p, false); err != nil {
		t.Fatal(err)
	}
	if cfg, err := Load(p); err != nil || cfg.Default != LocalName {
		t.Fatalf("fresh default = %+v, %v", cfg, err)
	}
}

func TestAddResolveAndRemove(t *testing.T) {
	p := testPaths(t)
	spec, err := Add(p, "work", "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Kind != KindLocal || spec.Path != filepath.Join(p.Dir, "work.db") {
		t.Fatalf("added source = %+v", spec)
	}
	if got, err := Resolve(p, "work"); err != nil || got.Path != spec.Path {
		t.Fatalf("resolve added source = %+v, %v", got, err)
	}
	// Adding a source must not change which one is the default.
	if got, _ := Resolve(p, ""); got.Name != LocalName {
		t.Fatalf("default moved to %q", got.Name)
	}
	if err := Remove(p, "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(p, "work"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("removed source still resolves: %v", err)
	}
}

func TestAddCustomAbsolutePath(t *testing.T) {
	p := testPaths(t)
	path := filepath.Join(t.TempDir(), "elsewhere.db")
	spec, err := Add(p, "work", path)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Path != path {
		t.Fatalf("path = %q, want %q", spec.Path, path)
	}
	if _, err := Add(p, "work", path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate add = %v", err)
	}
}

func TestBuiltinsCannotBeAddedOrRemoved(t *testing.T) {
	p := testPaths(t)
	for _, name := range []string{LocalName, SyncName} {
		if _, err := Add(p, name, ""); !errors.Is(err, ErrBuiltIn) {
			t.Fatalf("add built-in %q = %v", name, err)
		}
		if err := Remove(p, name); !errors.Is(err, ErrBuiltIn) {
			t.Fatalf("remove built-in %q = %v", name, err)
		}
	}
}

func TestInvalidSourceNames(t *testing.T) {
	p := testPaths(t)
	for _, name := range []string{"", "../escape", "Local", "has space", "slash/name", "a-very-long-source-name-over-32-chars"} {
		if _, err := Add(p, name, ""); !errors.Is(err, ErrInvalid) {
			t.Fatalf("name %q accepted: %v", name, err)
		}
	}
}

func TestRelativeVaultPathIsRejected(t *testing.T) {
	p := testPaths(t)
	if _, err := Add(p, "work", "relative.db"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative path accepted: %v", err)
	}
}

func TestUnknownSourceIsAnError(t *testing.T) {
	p := testPaths(t)
	if _, err := Resolve(p, "nope"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown source = %v", err)
	}
	if err := SetDefault(p, "nope"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown default = %v", err)
	}
}

// The configuration is a security-relevant knob: unknown fields and
// unsupported kinds are errors, never something to ignore.
func TestLoadIsStrict(t *testing.T) {
	p := testPaths(t)
	cases := []string{
		`{"default":"local","bogus":true}`,
		`{"default":"nope"}`,
		`{"sources":{"x":{"kind":"cloud","path":"/tmp/x.db"}}}`,
		`{"sources":{"x":{"kind":"local","path":"relative.db"}}}`,
		`{"sources":{"local":{"kind":"local","path":"/tmp/x.db"}}}`,
		`{not json`,
	}
	for _, body := range cases {
		if err := os.WriteFile(Path(p), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("configuration %q was accepted", body)
		}
	}
}

func TestRemoveResetsTheDefault(t *testing.T) {
	p := testPaths(t)
	if _, err := Add(p, "work", ""); err != nil {
		t.Fatal(err)
	}
	if err := SetDefault(p, "work"); err != nil {
		t.Fatal(err)
	}
	if err := Remove(p, "work"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Default != LocalName {
		t.Fatalf("default after removing the default source = %q", cfg.Default)
	}
}

func TestSpecsAreSortedAndIncludeBuiltins(t *testing.T) {
	p := testPaths(t)
	if _, err := Add(p, "work", ""); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	specs := cfg.Specs()
	if len(specs) != 3 {
		t.Fatalf("specs = %+v", specs)
	}
	if specs[0].Name != LocalName || specs[1].Name != SyncName || specs[2].Name != "work" {
		t.Fatalf("order = %+v", specs)
	}
}
