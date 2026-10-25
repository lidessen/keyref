// Package e2e holds end-to-end tests that build and drive the real
// keyref binary against a real keyref-server (docs/protocol.md §11).
// Every test file except this one carries the `e2e` build tag; run them
// with: go test -C cli -tags=e2e ./e2e
package e2e
