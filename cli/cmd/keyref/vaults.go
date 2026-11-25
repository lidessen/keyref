package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/meta"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/source"
)

func selectedSource(flagName string) string {
	if name := strings.TrimSpace(flagName); name != "" {
		return name
	}
	return strings.TrimSpace(os.Getenv(source.EnvSource))
}

// Unlike the built-in names, an initialized vault or a signed-in account
// represents an actual storage location.
func activeDiskSources(p config.Paths, includeSync bool) ([]source.Spec, error) {
	cfg, err := source.Load(p)
	if err != nil {
		return nil, err
	}
	var active []source.Spec
	for _, spec := range cfg.Specs() {
		switch spec.Kind {
		case source.KindLocal:
			if _, err := os.Stat(spec.Path); err == nil {
				active = append(active, spec)
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("source %q: %w", spec.Name, err)
			}
		case source.KindSync:
			if !includeSync {
				continue
			}
			paired, err := pairedSourceExists(p)
			if err != nil {
				return nil, err
			}
			if paired {
				active = append(active, spec)
			}
		}
	}
	return active, nil
}

func pairedSourceExists(p config.Paths) (bool, error) {
	st, err := existingStore(p)
	if errors.Is(err, errNotPaired) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer st.Close()
	value, ok, err := st.GetKV(session.KVVaultID)
	return ok && len(value) > 0, err
}

func loadRemoteSource(p config.Paths) (*remoteClient, error) {
	c, err := newRemoteClient(p)
	if err != nil {
		return nil, err
	}
	ks, err := secretStoreOrError()
	if err != nil {
		return nil, err
	}
	if err := c.loadSession(p, ks); err != nil {
		return nil, err
	}
	return c, nil
}

func activeRemote(p config.Paths) (*remoteClient, error) {
	if config.Origin(p) == config.DefaultOrigin {
		return nil, nil
	}
	c, err := loadRemoteSource(p)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("source %q: %w", source.RemoteName, err)
	}
	return c, nil
}

func writableSource(p config.Paths, override string) (source.Spec, *remoteClient, error) {
	if name := selectedSource(override); name != "" {
		if name == source.RemoteName {
			c, err := loadRemoteSource(p)
			if errors.Is(err, keyring.ErrNotFound) {
				err = errors.New("sign in with keyref remote login")
			}
			return source.Spec{}, c, err
		}
		spec, err := resolveSource(p, name)
		return spec, nil, err
	}
	specs, err := activeDiskSources(p, false)
	if err != nil {
		return source.Spec{}, nil, err
	}
	c, err := activeRemote(p)
	if err != nil {
		return source.Spec{}, nil, err
	}
	if len(specs) == 0 && c != nil {
		return source.Spec{}, c, nil
	}
	if c != nil {
		clear(c.session.VaultKey)
		specs = append(specs, source.Spec{Name: source.RemoteName, Kind: source.KindRemote})
	}
	switch len(specs) {
	case 0:
		spec, err := resolveSource(p, "")
		return spec, nil, err
	case 1:
		return specs[0], nil, nil
	default:
		names := make([]string, 0, len(specs))
		for _, spec := range specs {
			names = append(names, spec.Name)
		}
		return source.Spec{}, nil, fmt.Errorf("multiple writable sources (%s); choose one with --vault NAME", strings.Join(names, ", "))
	}
}

func listSources(p config.Paths, override, format string, filter listFilter) int {
	var specs []source.Spec
	var c *remoteClient
	var err error
	switch name := selectedSource(override); name {
	case source.RemoteName:
		c, err = loadRemoteSource(p)
		if err != nil {
			return remoteSessionError(err)
		}
	case "":
		specs, err = activeDiskSources(p, true)
		if err == nil {
			c, err = activeRemote(p)
		}
	default:
		var spec source.Spec
		spec, err = resolveSource(p, name)
		specs = []source.Spec{spec}
	}
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if len(specs) == 0 && c == nil {
		return fatalf(1, "no credential source is configured; run keyref init or keyref remote login")
	}
	var entries []meta.Entry
	if c != nil {
		defer clear(c.session.VaultKey)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		metas, err := c.listMetadata(ctx)
		if err != nil {
			return remoteFail(err)
		}
		for _, m := range metas {
			entries = append(entries, meta.Entry{
				Ref: m.Ref, Name: m.Ref, Type: "remote", Source: source.RemoteName,
				Masked: m.Mask, Description: m.Description, Sensitivity: "standard",
				Injectable: true,
			})
		}
	}
	for _, spec := range specs {
		var rows []meta.Entry
		var code int
		if spec.Kind == source.KindLocal {
			rows, code = localList(p, spec)
		} else {
			rows, code = syncList(p)
		}
		if code != 0 {
			return code
		}
		for i := range rows {
			rows[i].Source = spec.Name
		}
		entries = append(entries, rows...)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Ref == entries[j].Ref {
			return entries[i].Source < entries[j].Source
		}
		return entries[i].Ref < entries[j].Ref
	})
	return printEntries(filterEntries(entries, filter), format)
}
