package wire

// Delegation policy (docs/protocol.md §3.10, design v0.8 §14.8).
//
// The policy is the plaintext JSON inside the owner-signed delegation
// transcript. The server only verifies the signature and relays the bytes;
// the decider is the only party that reads it. An empty delegation —
// `{"v":1}` — revokes: no sender allowlist, so nothing can ever be
// auto-approved.
//
// The decider may only narrow: every field is an additional constraint,
// and an unknown field is a parse error rather than something to ignore
// (a policy the decider half-understands must never be treated as wider
// than it is).
import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DelegationPolicy is the decoded policy_json.
type DelegationPolicy struct {
	V int `json:"v"`
	// Senders is the allowlist of SMS senders. Empty = nothing matches.
	Senders []string `json:"senders,omitempty"`
	// MaxAgeMin bounds the message age by the SERVER's created_at.
	MaxAgeMin int64 `json:"max_age_min,omitempty"`
	// PerCLIHourly / PerCLIDaily cap auto-approvals per CLI device.
	PerCLIHourly int64 `json:"per_cli_hourly,omitempty"`
	PerCLIDaily  int64 `json:"per_cli_daily,omitempty"`
	// CLIDevices restricts which CLI devices may be auto-approved.
	CLIDevices []string `json:"cli_devices,omitempty"`
}

// IsEmpty reports whether this is the revocation policy (`{"v":1}`): no
// sender allowlist, so no auto-approval is possible.
func (p DelegationPolicy) IsEmpty() bool { return len(p.Senders) == 0 }

// ParseDelegationPolicy decodes and validates policy_json. Unknown fields
// are rejected (the §1.2 habit, and the only safe default for a policy the
// decider will act on).
func ParseDelegationPolicy(raw string) (DelegationPolicy, error) {
	var p DelegationPolicy
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return DelegationPolicy{}, fmt.Errorf("%w: policy_json: %v", ErrInvalidField, err)
	}
	if p.V != 1 {
		return DelegationPolicy{}, fmt.Errorf("%w: policy_json v must be 1", ErrInvalidField)
	}
	for _, s := range p.Senders {
		if s == "" || len(s) > 64 {
			return DelegationPolicy{}, fmt.Errorf("%w: policy sender must be 1..64 bytes", ErrInvalidField)
		}
	}
	for _, d := range p.CLIDevices {
		if !ValidID(d) {
			return DelegationPolicy{}, fmt.Errorf("%w: policy cli_devices must be 32 lowercase hex", ErrInvalidField)
		}
	}
	if p.MaxAgeMin < 0 || p.PerCLIHourly < 0 || p.PerCLIDaily < 0 {
		return DelegationPolicy{}, fmt.Errorf("%w: policy limits must not be negative", ErrInvalidField)
	}
	return p, nil
}

// AllowsSender reports whether the sender allowlist
// contains this exact sender. Comparison is byte-exact: a policy that
// lists "10086" does not cover "+8610086" (design §14.8: the decider may
// narrow, never broaden).
func (p DelegationPolicy) AllowsSender(sender string) bool {
	for _, s := range p.Senders {
		if s == sender {
			return true
		}
	}
	return false
}

// AllowsCLI reports whether the CLI device may be
// auto-approved. An empty list means no restriction.
func (p DelegationPolicy) AllowsCLI(deviceID string) bool {
	if len(p.CLIDevices) == 0 {
		return true
	}
	for _, d := range p.CLIDevices {
		if d == deviceID {
			return true
		}
	}
	return false
}
