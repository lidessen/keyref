//go:build darwin || linux

package exec

import (
	"sync"
	"syscall"
)

// coreOnce guards the one-shot RLIMIT_CORE=0: the CLI lowers its own
// limit before spawning, and children inherit it across fork+exec
// (design.md §7.2). Failure is ignored (debug counter only).
var coreOnce sync.Once

// DisableCoreDumps lowers RLIMIT_CORE to zero for this process and all
// future children (design.md §7.5: turn off core dumps).
func DisableCoreDumps() {
	coreOnce.Do(func() {
		_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	})
}

// childSysProcAttr puts the child in its own process group so that a
// redaction failure can kill the whole tree (design.md §7.4). The
// process never goes through a shell (design.md §15).
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
