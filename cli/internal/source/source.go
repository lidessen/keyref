// Package source selects which credential source a keyref command
// operates on: the standalone local vault (the default) or the paired,
// synchronized vault. One command surface covers both — there is no
// separate "local" subcommand.
//
// Precedence is --source, then the KEYREF_SOURCE environment variable,
// then the configured default, then the built-in local vault.
package source

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lidessen/keyref/cli/internal/config"
)

// Kind is the backend behind a source name.
type Kind string

const (
	// KindLocal is an offline, explicitly provisioned SQLite vault.
	KindLocal Kind = "local"
	// KindSync is the paired iOS vault. It is read-only for the CLI:
	// only an owner device may create, edit or delete items.
	KindSync Kind = "sync"
)

const (
	// LocalName is the built-in standalone vault.
	LocalName = "local"
	// SyncName is the built-in paired vault.
	SyncName = "sync"
	// EnvSource overrides the configured default source.
	EnvSource = "KEYREF_SOURCE"
	// FileName is the sources configuration inside the 0700 data directory.
	FileName = "sources.json"
)

var (
	ErrUnknown = errors.New("unknown source")
	ErrInvalid = errors.New("invalid source")
	ErrBuiltIn = errors.New("built-in source")
)

// Spec is the resolved source of one command.
type Spec struct {
	Name string
	Kind Kind
	// Path is the local vault file; empty for the paired vault.
	Path string
}

// Entry is one configured source.
type Entry struct {
	Kind Kind   `json:"kind"`
	Path string `json:"path,omitempty"`
}

// Config is the resolved sources configuration, built-ins included.
type Config struct {
	Default string
	Sources map[string]Entry
}

// document is the on-disk shape. Only non-built-in sources are stored.
type document struct {
	Default string           `json:"default"`
	Sources map[string]Entry `json:"sources"`
}

// Path is the configuration file location.
func Path(p config.Paths) string { return filepath.Join(p.Dir, FileName) }

func builtins(p config.Paths) map[string]Entry {
	return map[string]Entry{
		LocalName: {Kind: KindLocal, Path: filepath.Join(p.Dir, "local.db")},
		SyncName:  {Kind: KindSync},
	}
}

func defaults(p config.Paths, paired bool) *Config {
	cfg := &Config{Default: LocalName, Sources: builtins(p)}
	if paired {
		// A vault paired before sources existed must keep working:
		// its commands used to be the only behaviour there was.
		cfg.Default = SyncName
	}
	return cfg
}

// Load reads sources.json, falling back to the built-in defaults when
// the file does not exist. Unknown fields and unknown kinds are errors
// rather than things to ignore.
func Load(p config.Paths) (*Config, error) {
	cfg := &Config{Default: LocalName, Sources: builtins(p)}
	raw, err := os.ReadFile(Path(p))
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	var doc document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	for name, entry := range doc.Sources {
		if _, built := cfg.Sources[name]; built {
			return nil, fmt.Errorf("%w: %q is built in", ErrBuiltIn, name)
		}
		e, err := normalize(p, name, entry)
		if err != nil {
			return nil, err
		}
		cfg.Sources[name] = e
	}
	if doc.Default != "" {
		if _, ok := cfg.Sources[doc.Default]; !ok {
			return nil, fmt.Errorf("%w: default %q", ErrUnknown, doc.Default)
		}
		cfg.Default = doc.Default
	}
	return cfg, nil
}

// Save persists the default and the non-built-in sources.
func Save(p config.Paths, cfg *Config) error {
	doc := document{Default: cfg.Default, Sources: map[string]Entry{}}
	for name, entry := range cfg.Sources {
		if _, built := builtins(p)[name]; built {
			continue
		}
		doc.Sources[name] = entry
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(Path(p), append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(Path(p), 0o600)
}

// Ensure writes the initial configuration once. A data directory that
// already holds a paired vault defaults to it, so upgrading the CLI does
// not silently move existing commands onto an empty local vault.
func Ensure(p config.Paths, paired bool) error {
	if _, err := os.Stat(Path(p)); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return Save(p, defaults(p, paired))
}

// Resolve picks the source for one command.
func Resolve(p config.Paths, override string) (Spec, error) {
	name := strings.TrimSpace(override)
	if name == "" {
		name = strings.TrimSpace(os.Getenv(EnvSource))
	}
	cfg, err := Load(p)
	if err != nil {
		return Spec{}, err
	}
	if name == "" {
		name = cfg.Default
	}
	entry, ok := cfg.Sources[name]
	if !ok {
		return Spec{}, fmt.Errorf("%w: %q (see keyref source list)", ErrUnknown, name)
	}
	return Spec{Name: name, Kind: entry.Kind, Path: entry.Path}, nil
}

// Specs lists every source, sorted by name.
func (c *Config) Specs() []Spec {
	out := make([]Spec, 0, len(c.Sources))
	for name, entry := range c.Sources {
		out = append(out, Spec{Name: name, Kind: entry.Kind, Path: entry.Path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SetDefault persists the source used when neither --source nor
// KEYREF_SOURCE is given.
func SetDefault(p config.Paths, name string) error {
	cfg, err := Load(p)
	if err != nil {
		return err
	}
	if _, ok := cfg.Sources[name]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknown, name)
	}
	cfg.Default = name
	return Save(p, cfg)
}

// Add registers another local vault under its own name.
func Add(p config.Paths, name, path string) (Spec, error) {
	if !validName(name) {
		return Spec{}, fmt.Errorf("%w: a source name is 1 to 32 characters of a-z, 0-9, '-' or '_'", ErrInvalid)
	}
	if _, built := builtins(p)[name]; built {
		return Spec{}, fmt.Errorf("%w: %q", ErrBuiltIn, name)
	}
	cfg, err := Load(p)
	if err != nil {
		return Spec{}, err
	}
	if _, exists := cfg.Sources[name]; exists {
		return Spec{}, fmt.Errorf("%w: source %q already exists", ErrInvalid, name)
	}
	entry, err := normalize(p, name, Entry{Kind: KindLocal, Path: path})
	if err != nil {
		return Spec{}, err
	}
	cfg.Sources[name] = entry
	if err := Save(p, cfg); err != nil {
		return Spec{}, err
	}
	return Spec{Name: name, Kind: entry.Kind, Path: entry.Path}, nil
}

// Remove drops a registered source. The vault file itself is left alone.
func Remove(p config.Paths, name string) error {
	if _, built := builtins(p)[name]; built {
		return fmt.Errorf("%w: %q cannot be removed", ErrBuiltIn, name)
	}
	cfg, err := Load(p)
	if err != nil {
		return err
	}
	if _, ok := cfg.Sources[name]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknown, name)
	}
	delete(cfg.Sources, name)
	if cfg.Default == name {
		cfg.Default = LocalName
	}
	return Save(p, cfg)
}

func normalize(p config.Paths, name string, entry Entry) (Entry, error) {
	if !validName(name) {
		return Entry{}, fmt.Errorf("%w: source name %q", ErrInvalid, name)
	}
	switch entry.Kind {
	case KindLocal:
		if entry.Path == "" {
			entry.Path = filepath.Join(p.Dir, name+".db")
		}
		if !filepath.IsAbs(entry.Path) {
			return Entry{}, fmt.Errorf("%w: source %q needs an absolute vault path", ErrInvalid, name)
		}
		return entry, nil
	default:
		return Entry{}, fmt.Errorf("%w: source %q has unsupported kind %q", ErrInvalid, name, entry.Kind)
	}
}

func validName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
