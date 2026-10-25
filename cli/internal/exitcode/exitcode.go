// Package exitcode pins the CLI exit-code table of design.md §7.6.
// The subprocess's own code is passed through when policy passed and
// redaction completed.
package exitcode

const (
	// PolicyRejection: denied command or interpreter, --allow-argv
	// without item consent, --reply gates, invalid --env/--pass names.
	PolicyRejection = 10
	// UnknownRef: unknown ref, or no view grant for this device.
	UnknownRef = 11
	// SessionLocked: local session locked, no usable device key.
	SessionLocked = 12
	// ApprovalDenied: approval refused or timed out (Phase 2 flow).
	ApprovalDenied = 13
	// RedactionFailed: redactor error, raw output discarded.
	RedactionFailed = 14
	// InjectionInvalid: item not injectable, or rendered fd template
	// violates its declared format.
	InjectionInvalid = 15
	// UnwrapFailed: stale grant (rotated key), corrupted ciphertext,
	// item key unavailable. Distinct from SessionLocked.
	UnwrapFailed = 16
	// DeviceRevoked: this device is revoked in the directory; local
	// cleanup ran first.
	DeviceRevoked = 17
	// CannotStart: argv0 unresolvable, unreadable, setuid/setgid, not
	// executable.
	CannotStart = 18
)
