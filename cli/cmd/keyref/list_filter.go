package main

import (
	"net/url"
	"strings"

	"github.com/lidessen/keyref/cli/internal/meta"
)

type listFilter struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// listHost parses a URL or a bare host, preserving an explicitly given port.
func listHost(value string) (host, port string, ok bool) {
	isURL := strings.Contains(value, "://")
	if !isURL {
		value = "//" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") ||
		(!isURL && (u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "")) {
		return "", "", false
	}
	return u.Hostname(), u.Port(), true
}

// filterEntries operates only on already-decrypted metadata.
func filterEntries(entries []meta.Entry, filter listFilter) []meta.Entry {
	var host, port string
	if filter.URL != "" {
		var ok bool
		host, port, ok = listHost(filter.URL)
		if !ok {
			return nil
		}
	}
	var out []meta.Entry
	for _, e := range entries {
		if filter.Type != "" && !strings.EqualFold(e.Type, filter.Type) {
			continue
		}
		if filter.URL != "" {
			entryHost, entryPort, ok := listHost(e.URL)
			if !ok || !strings.EqualFold(host, entryHost) || (port != "" && port != entryPort) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}
