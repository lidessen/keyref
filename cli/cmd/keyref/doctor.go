package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/source"
	"golang.org/x/term"
)

type doctorReport struct {
	Source               string `json:"source"`
	SourceReason         string `json:"source_reason"`
	Directory            string `json:"directory"`
	DirectoryPermissions string `json:"directory_permissions"`
	Store                string `json:"store"`
	StorePermissions     string `json:"store_permissions"`
	KeyAvailable         *bool  `json:"key_available"`
	KeySource            string `json:"key_source"`
	TTYAvailable         bool   `json:"tty_available"`
	Schema               string `json:"schema"`
}

// readOnlyPaths deliberately avoids config.Resolve, which creates and chmods directories.
func readOnlyPaths() (config.Paths, error) {
	dir := os.Getenv(config.EnvHome)
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return config.Paths{}, err
		}
		dir = filepath.Join(base, "keyref")
	}
	return config.Paths{Dir: dir, CacheFile: filepath.Join(dir, "cache.sqlite")}, nil
}

func readOnlyDB(path string) (*sql.DB, error) {
	if _, err := os.Stat(path + "-wal"); err == nil {
		return nil, errors.New("active WAL requires a live database check")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	u := &url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func doctorSource(p config.Paths, override string) (source.Spec, string, error) {
	reason := "built-in local default"
	selected := strings.TrimSpace(override)
	if selected != "" {
		reason = "--vault"
	} else if selected = strings.TrimSpace(os.Getenv(source.EnvSource)); selected != "" {
		reason = source.EnvSource
	} else {
		raw, err := os.ReadFile(source.Path(p))
		if err == nil {
			var doc struct {
				Default string `json:"default"`
			}
			if json.Unmarshal(raw, &doc) == nil && doc.Default != "" {
				reason = "sources.json"
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if _, err := os.Stat(p.CacheFile); err == nil {
				db, err := readOnlyDB(p.CacheFile)
				if err != nil {
					return source.Spec{}, "", err
				}
				var n int
				err = db.QueryRow("SELECT length(v) FROM kv WHERE k = 'vault_id'").Scan(&n)
				db.Close()
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return source.Spec{}, "", err
				}
				if n > 0 {
					selected, reason = source.SyncName, "legacy paired vault migration"
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return source.Spec{}, "", err
			}
		} else {
			return source.Spec{}, "", err
		}
	}
	spec, err := source.Resolve(p, selected)
	return spec, reason, err
}

func doctorMode(path string, mode os.FileMode, dir bool) string {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "missing"
	}
	if err != nil {
		return "unavailable"
	}
	if (dir && !info.IsDir()) || (!dir && !info.Mode().IsRegular()) {
		return "invalid type"
	}
	if info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Sprintf("insecure (%04o; expected %04o)", info.Mode().Perm(), mode)
	}
	return "ok"
}

func doctorSchema(path string, kind source.Kind) (string, string) {
	db, err := readOnlyDB(path)
	if err != nil {
		return "unavailable (missing, unreadable, or active WAL)", ""
	}
	defer db.Close()
	if kind == source.KindSync {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('kv','items','grants')").Scan(&n); err != nil || n != 3 {
			return "invalid sync schema", ""
		}
		return "ok (sync schema; key not verified)", ""
	}
	var id string
	var blobLen, writes, version int
	err = db.QueryRow("SELECT id, length(check_blob), writes FROM metadata").Scan(&id, &blobLen, &writes)
	if err != nil || len(id) != 32 || blobLen < 28 || blobLen > 128 || writes < 1 {
		return "invalid local schema or metadata", ""
	}
	if _, err := hex.DecodeString(id); err != nil || strings.ToLower(id) != id {
		return "invalid local metadata", ""
	}
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return "invalid local schema", ""
	}
	rows, err := db.Query("SELECT id, meta, blob FROM entries LIMIT 0")
	if err != nil {
		return "invalid or legacy local schema", id
	}
	rows.Close()
	if version != 1 {
		return fmt.Sprintf("unsupported schema version %d", version), id
	}
	return "ok (metadata only; key not verified)", id
}

func doctorKey(id string) (*bool, string) {
	available := false
	if value, ok := os.LookupEnv("KEYREF_LOCAL_MASTER"); ok {
		key, err := base64.StdEncoding.Strict().DecodeString(value)
		available = err == nil && len(key) == 32
		for i := range key {
			key[i] = 0
		}
		return &available, "KEYREF_LOCAL_MASTER"
	}
	if id == "" {
		return nil, "unknown (store metadata unavailable)"
	}
	var encoded string
	var err error
	if dir := os.Getenv("KEYREF_KEYRING_DIR"); dir != "" {
		digest := sha256.Sum256([]byte("keyref\x00local-master-" + id))
		var data []byte
		data, err = os.ReadFile(filepath.Join(dir, hex.EncodeToString(digest[:])))
		encoded = string(data)
		for i := range data {
			data[i] = 0
		}
	} else {
		encoded, err = (keyring.OSKeyring{}).Get("keyref", "local-master-"+id)
	}
	if err == nil {
		key, e := base64.StdEncoding.Strict().DecodeString(encoded)
		available = e == nil && len(key) == 32
		for i := range key {
			key[i] = 0
		}
	}
	return &available, "keyring"
}

func inspectDoctor(p config.Paths, override string) (doctorReport, error) {
	var report doctorReport
	spec, reason, err := doctorSource(p, override)
	if err != nil {
		return report, err
	}
	report.Source, report.SourceReason = spec.Name, reason
	report.Store = spec.Path
	if spec.Kind == source.KindSync {
		report.Store = p.CacheFile
	}
	report.Directory = filepath.Dir(report.Store)
	report.DirectoryPermissions = doctorMode(report.Directory, 0700, true)
	report.StorePermissions = doctorMode(report.Store, 0600, false)
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		report.TTYAvailable = term.IsTerminal(int(tty.Fd()))
		tty.Close()
	}
	var id string
	report.Schema, id = doctorSchema(report.Store, spec.Kind)
	report.KeySource = "not checked for sync source"
	if spec.Kind == source.KindLocal {
		report.KeyAvailable, report.KeySource = doctorKey(id)
	}
	return report, nil
}

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print JSON")
	vault := fs.String("vault", "", "vault to inspect")
	prepareHelp(fs, args)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseExit(err)
	}
	if len(rest) != 0 {
		return fatalf(2, "usage: keyref doctor [--vault NAME] [--json]")
	}
	p, err := readOnlyPaths()
	if err != nil {
		return fatalf(1, "cannot resolve data directory")
	}
	report, err := inspectDoctor(p, *vault)
	if err != nil {
		return fatalf(1, "cannot resolve source: %v", err)
	}
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return fatalf(1, "cannot write report")
		}
		return 0
	}
	key := "unknown"
	if report.KeyAvailable != nil {
		key = yesNo(*report.KeyAvailable)
	}
	fmt.Printf("source: %s (%s)\ndirectory: %s (%s)\nstore: %s (%s)\nkey available: %s (%s)\n/dev/tty: %s\nschema: %s\n", report.Source, report.SourceReason, report.Directory, report.DirectoryPermissions, report.Store, report.StorePermissions, key, report.KeySource, yesNo(report.TTYAvailable), report.Schema)
	return 0
}
