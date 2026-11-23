package update

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func TestIsNewer(t *testing.T) {
	for _, tt := range []struct {
		tag, current string
		want         bool
	}{
		{"v1.10.0", "v1.9.0", true},
		{"v1.9.0", "v1.10.0", false},
		{"v1.2.4", "v1.2.3", true},
		{"v1.2.4", "v1.2.4", false},
		{"v2.0.0", "v1.999.999", true},
		{"v1.0.0", "dev", true},
		{"v1.0.0", "590bec0", true},
		{"v1.0.0-rc.1", "v0.9.0", false},
		{"v01.0.0", "dev", false},
	} {
		if got := IsNewer(tt.tag, tt.current); got != tt.want {
			t.Errorf("IsNewer(%q, %q) = %t, want %t", tt.tag, tt.current, got, tt.want)
		}
	}
}

func TestLatest(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"stable", 200, `{"tag_name":"v1.2.3"}`, "v1.2.3"},
		{"draft", 200, `{"tag_name":"v1.2.3","draft":true}`, ""},
		{"prerelease", 200, `{"tag_name":"v1.2.3","prerelease":true}`, ""},
		{"invalid tag", 200, `{"tag_name":"../v1.2.3"}`, ""},
		{"no releases", 404, "not found", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.String() != latestURL {
					t.Fatalf("unexpected request %s %s", req.Method, req.URL)
				}
				return response(tt.status, tt.body), nil
			})}
			got, err := Latest(t.Context(), client)
			if got != tt.want || (err == nil) != (tt.want != "") {
				t.Fatalf("Latest = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestInstall(t *testing.T) {
	const original = "current executable"
	const newer = "new executable"
	const tag = "v1.2.3"
	name := "keyref-" + runtime.GOOS + "-" + runtime.GOARCH
	checksum := fmt.Sprintf("%x  %s\n", sha256.Sum256([]byte(newer)), name)

	for _, tt := range []struct {
		name, manifest, binary, want, wantError string
		replace                                 bool
	}{
		{name: "verified", manifest: checksum, binary: newer, want: newer},
		{name: "wrong binary", manifest: checksum, binary: "corrupt", want: original, wantError: "checksum"},
		{name: "missing platform", manifest: "another asset", want: original, wantError: "no SHA-256 entry"},
		{name: "duplicate entries", manifest: checksum + checksum, want: original, wantError: "invalid SHA-256 entry"},
		{name: "another update won", manifest: checksum, binary: newer, want: "concurrent executable", wantError: "changed during update", replace: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "keyref")
			if err := os.WriteFile(path, []byte(original), 0o700); err != nil {
				t.Fatal(err)
			}
			expected, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case assetBase + tag + "/SHA256SUMS":
					return response(http.StatusOK, tt.manifest), nil
				case assetBase + tag + "/" + name:
					if tt.replace {
						other := filepath.Join(dir, "concurrent")
						if err := os.WriteFile(other, []byte(tt.want), 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(other, path); err != nil {
							t.Fatal(err)
						}
					}
					return response(http.StatusOK, tt.binary), nil
				default:
					return nil, fmt.Errorf("unexpected asset request: %s", req.URL)
				}
			})}
			err = Install(context.Background(), client, tag, path, expected)
			if tt.wantError == "" && err != nil || tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("Install error = %v, want %q", err, tt.wantError)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != tt.want {
				t.Fatalf("installed executable = %q, %v; want %q", data, err, tt.want)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("executable mode changed: %v, %v", info, err)
			}
			if files, err := filepath.Glob(filepath.Join(dir, ".keyref-update-*")); err != nil || len(files) != 0 {
				t.Fatalf("staging files remain after update: %v, %v", files, err)
			}
		})
	}
}
