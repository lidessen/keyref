// Package update installs the CLI binaries published in Keyref's GitHub releases.
package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/lidessen/keyref/cli/internal/atomicfile"
)

const (
	repository   = "lidessen/keyref"
	latestURL    = "https://api.github.com/repos/" + repository + "/releases/latest"
	webLatestURL = "https://github.com/" + repository + "/releases/latest"
	assetBase    = "https://github.com/" + repository + "/releases/download/"
	maxBinary    = 64 << 20
)

var stableTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func HTTPClient() *http.Client {
	return &http.Client{
		Timeout: 90 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) >= 10 {
				return errors.New("invalid release download redirect")
			}
			return nil
		},
	}
}

func Latest(ctx context.Context, client *http.Client) (string, error) {
	data, err := getSmall(ctx, client, latestURL, 1<<20)
	if err != nil {
		var statusErr *httpStatusError
		if errors.As(err, &statusErr) && (statusErr.code == http.StatusForbidden || statusErr.code == http.StatusTooManyRequests) {
			tag, fallbackErr := latestFromWeb(ctx, client)
			if fallbackErr != nil {
				return "", fmt.Errorf("check for a release: %w", fallbackErr)
			}
			return tag, nil
		}
		return "", fmt.Errorf("check for a release: %w", err)
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(data, &release); err != nil || release.Draft || release.Prerelease || !stableTag.MatchString(release.Tag) {
		return "", errors.New("GitHub did not return a published stable Keyref version")
	}
	return release.Tag, nil
}

func latestFromWeb(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, webLatestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "keyref-updater")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", &httpStatusError{code: res.StatusCode}
	}
	if res.Request == nil || res.Request.URL == nil {
		return "", errors.New("GitHub did not return a final release URL")
	}
	u := res.Request.URL
	prefix := "/" + repository + "/releases/tag/"
	tag, ok := strings.CutPrefix(u.Path, prefix)
	if u.Scheme != "https" || u.Host != "github.com" || !ok || !stableTag.MatchString(tag) {
		return "", errors.New("GitHub did not redirect to a stable Keyref release")
	}
	return tag, nil
}

// IsNewer allows a checkout build to move to a stable release. Stable
// releases are compared by numeric component, so they never downgrade.
func IsNewer(tag, current string) bool {
	next := stableTag.FindStringSubmatch(tag)
	if next == nil {
		return false
	}
	previous := stableTag.FindStringSubmatch(current)
	if previous == nil {
		return true
	}
	for i := 1; i < len(next); i++ {
		if len(next[i]) != len(previous[i]) {
			return len(next[i]) > len(previous[i])
		}
		if next[i] != previous[i] {
			return next[i] > previous[i]
		}
	}
	return false
}

// Install verifies the platform binary before replacing the executable.
// expected describes the running executable before the release lookup. If
// another update replaced it, the caller must rerun the new executable.
func Install(ctx context.Context, client *http.Client, tag, path string, expected os.FileInfo) error {
	return InstallWithProgress(ctx, client, tag, path, expected, nil, nil)
}

// InstallWithProgress reports downloaded bytes and the total size, or -1 when
// the size is unknown. beforeVerify runs after the download completes.
func InstallWithProgress(ctx context.Context, client *http.Client, tag, path string, expected os.FileInfo, progress func(downloaded, total int64), beforeVerify func()) error {
	if !stableTag.MatchString(tag) {
		return errors.New("invalid stable release tag")
	}
	if (runtime.GOOS != "darwin" && runtime.GOOS != "linux") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return errors.New("no release binary for this platform")
	}
	if !expected.Mode().IsRegular() {
		return errors.New("the running executable is not a regular file")
	}
	name := "keyref-" + runtime.GOOS + "-" + runtime.GOARCH
	base := assetBase + tag + "/"
	data, err := getSmall(ctx, client, base+"SHA256SUMS", 64<<10)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	checksum, err := assetChecksum(data, name)
	if err != nil {
		return err
	}

	f, err := os.CreateTemp(filepath.Dir(path), ".keyref-update-*")
	if err != nil {
		return fmt.Errorf("stage executable beside %s: %w", path, err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	res, err := get(ctx, client, base+name)
	if err != nil {
		return fmt.Errorf("download %s: %w", name, err)
	}
	defer res.Body.Close()
	hash := sha256.New()
	total := res.ContentLength
	if total <= 0 {
		total = -1
	}
	w := &progressWriter{writer: io.MultiWriter(f, hash), total: total, report: progress}
	size, err := io.Copy(w, io.LimitReader(res.Body, maxBinary+1))
	if err != nil {
		return fmt.Errorf("stage release binary: %w", err)
	}
	if beforeVerify != nil {
		beforeVerify()
	}
	if size == 0 || size > maxBinary || !bytes.Equal(hash.Sum(nil), checksum) {
		return errors.New("release binary size or SHA-256 checksum is invalid")
	}
	if err := f.Chmod(expected.Mode().Perm()); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return atomicfile.WithLock(path, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !os.SameFile(current, expected) {
			return errors.New("the executable changed during update; rerun keyref update")
		}
		return os.Rename(f.Name(), path)
	})
}

type progressWriter struct {
	writer         io.Writer
	written, total int64
	report         func(int64, int64)
}

func (w *progressWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.written += int64(n)
	if n > 0 && w.report != nil {
		w.report(w.written, w.total)
	}
	return n, err
}

func assetChecksum(data []byte, name string) ([]byte, error) {
	var checksum []byte
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != name {
			continue
		}
		sum, err := hex.DecodeString(fields[0])
		if checksum != nil || err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 entry for %s", name)
		}
		checksum = sum
	}
	if checksum == nil {
		return nil, fmt.Errorf("release has no SHA-256 entry for %s", name)
	}
	return checksum, nil
}

func getSmall(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	res, err := get(ctx, client, url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = errors.New("release response is too large")
	}
	return data, err
}

func get(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "keyref-updater")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, &httpStatusError{code: res.StatusCode}
	}
	return res, nil
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("GitHub returned HTTP %d", e.code) }
