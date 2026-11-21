//go:build linux

package exec

import (
	"io"
	"testing"
)

// memfd staging never touches the directory: a missing directory is not
// an error and the payload still arrives intact (issue #4).
func TestMemfdStagingIgnoresTheDirectory(t *testing.T) {
	if _, ok := memfdFile(); !ok {
		t.Skip("memfd_create unavailable on this kernel")
	}
	f, ok := stageFdFile("/nonexistent-staging-dir-xyz", 3, []byte("payload-bytes"))
	if !ok {
		t.Fatal("memfd staging failed without a directory")
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "payload-bytes" {
		t.Fatalf("fd payload %q", b)
	}
}
