//go:build darwin

package exec

import "os"

// memfdFile: macOS has no memfd_create; the unlinked-tempfile fallback
// in fdstage_unix.go is the designed landing (design.md §7.1 option 2).
func memfdFile() (*os.File, bool) { return nil, false }
