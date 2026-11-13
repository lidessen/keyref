// Package config resolves the CLI data directory and the sync-server
// origin (design.md §12.2: `keyref server`, KEYREF_SERVER override,
// config in a 0700 directory, compiled-in default origin).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/lidessen/keyref/cli/internal/atomicfile"
)

// DefaultOrigin is the compiled-in official hosted origin. It is still
// the placeholder of design.md §14.12; changing the domain later is a
// one-line change here (docs/protocol.md §13.5).
const DefaultOrigin = "https://sync.example"

// EnvServer overrides the configured origin (agent install scripts
// point it at a self-hosted server, design.md §12.2).
const EnvServer = "KEYREF_SERVER"

// EnvHome overrides the data directory (tests and e2e runs; not a
// secret-related knob).
const EnvHome = "KEYREF_HOME"

// serverFile holds the origin inside the data directory.
const serverFile = "server.conf"

// Paths bundles the resolved CLI locations.
type Paths struct {
	Dir        string // 0700 data directory
	ServerFile string // origin config file (0600)
	CacheFile  string // cache.sqlite path (0600, handled by store)
}

// Resolve returns the data-directory layout, creating the directory
// with mode 0700.
func Resolve() (Paths, error) {
	dir := os.Getenv(EnvHome)
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("config: no home directory: %w", err)
		}
		dir = filepath.Join(base, "keyref")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Paths{}, fmt.Errorf("config: create data directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return Paths{}, fmt.Errorf("config: enforce directory mode: %w", err)
	}
	return Paths{
		Dir:        dir,
		ServerFile: filepath.Join(dir, serverFile),
		CacheFile:  filepath.Join(dir, "cache.sqlite"),
	}, nil
}

// Origin returns the effective origin: KEYREF_SERVER wins over the
// config file, which wins over the compiled default.
func Origin(p Paths) string {
	if v := strings.TrimSpace(os.Getenv(EnvServer)); v != "" {
		return v
	}
	if b, err := os.ReadFile(p.ServerFile); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	return DefaultOrigin
}

// SetOrigin persists origin to the config file with mode 0600.
func SetOrigin(p Paths, origin string) error {
	if !validOrigin(origin) {
		return errors.New("config: origin must be an https:// (or http://127.0.0.1 debug) URL")
	}
	// Atomic replace: a reader must never see a truncated server.conf
	// (issue #6).
	if err := atomicfile.Write(p.ServerFile, []byte(origin+"\n")); err != nil {
		return fmt.Errorf("config: write origin: %w", err)
	}
	return nil
}

// validOrigin accepts https origins, and http only for loopback
// development servers (design.md §10.4: local debugging listens on
// 127.0.0.1; production builds only trust HTTPS).
func validOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "127.0.0.1" || host == "localhost"
	}
	return false
}
