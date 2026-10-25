// Package approval implements the CLI side of the approval flow for
// `sensitivity = approval` items (design.md §8.3, docs/protocol.md
// §6.19–§6.22, §7.1): per exec, a one-time X25519 ephemeral key is
// generated, the request transcript (child argv in placeholder form,
// refs, injection modes, allowed hosts, reply patterns, ephemeral public
// key, timestamp, cli_device_id) is HPKE-encrypted to an owner device
// and signed with the CLI device's Ed25519 key, submitted, and then
// polled at a floor of 2 seconds (polling never counts against the
// daily request quota). The owner's one-time wrap — bound by HPKE info
// to the item, the approval id and the request digest — is unwrapped
// into guarded memory and the ephemeral private key is wiped: the item
// key exists only for this single exec.
package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/audit"
	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/itemcrypt"
	"github.com/lidessen/keyref/cli/internal/secret"
)

// PollInterval is the polling floor of design §5/§8.3: requests faster
// than this are rejected by the server (429 rate_limited). Tests may
// shorten it; production keeps the 2-second floor.
var PollInterval = 2 * time.Second

// DefaultTimeout is the default approval wait (design §8.3: 2 minutes).
const DefaultTimeout = 2 * time.Minute

// MaxTimeoutMs mirrors the server-side window check (protocol §6.19:
// expires_at − now ≤ 120000).
const MaxTimeoutMs = 120_000

// ErrDenied maps to exit code 13 (design §7.6): the owner refused, the
// request expired, or the wait timed out.
var ErrDenied = errors.New("approval: denied or timed out")

// request is the §6.19 approval request plaintext. It is decrypted only
// by the owner; the server never sees it. The wire contract fixes the
// field set; `reply` carries the full --reply patterns that design §7.1
// requires the approval screen to display (see the segment report: this
// field is the one addition beyond protocol §6.19's JSON).
type request struct {
	V                  int       `json:"v"`
	CLIDeviceID        string    `json:"cli_device_id"`
	ItemID             string    `json:"item_id"`
	Argv               []string  `json:"argv"`
	Refs               []string  `json:"refs"`
	Injection          string    `json:"injection"`
	Hosts              []string  `json:"hosts"`
	Reply              []string  `json:"reply,omitempty"`
	EphemeralKEM       string    `json:"ephemeral_kem"`
	EphemeralPublicKey wire.Blob `json:"ephemeral_public_key"`
	CreatedAt          int64     `json:"created_at"`
}

// Options describes one approval request for one item of one exec.
type Options struct {
	VaultID   string
	DeviceID  string
	Identity  *device.Identity
	Owners    []audit.OwnerRecipient // active owner devices; the first is used
	ItemID    string
	Ref       string
	Argv      []string // child argv in placeholder form (never secrets)
	Refs      []string // every ref of the exec, sorted
	Injection []string // injection modes (env/fd/stdin/argv/pty/reply)
	Hosts     []string // the item's allowedHosts
	Reply     []string // full --reply specs (REGEX=REF)
	Timeout   time.Duration
	Client    *client.Client
	Stderr    io.Writer // progress notices, never secrets
}

// RequestItemKey runs one approval round and returns the unwrapped item
// key in guarded memory. The caller must Destroy the key after the
// single exec (design §8.3 step 5). The returned exit code and deny
// state follow the exec convention (13 for denied/expired/timeout).
func RequestItemKey(opts *Options) (key *secret.Key, exitCode int, state string) {
	if len(opts.Owners) == 0 {
		fmt.Fprintln(opts.Stderr, "keyref: approval needs an active owner device; run keyref sync")
		return nil, 1, "internal"
	}
	owner := opts.Owners[0]

	// One-time X25519 key, wiped on every path out of this function
	// (design §8.3 step 1: used once, never persisted).
	_, ephPrivate, err := crypto.GenerateHPKEKeyPair(wire.KEMX25519)
	if err != nil {
		fmt.Fprintln(opts.Stderr, "keyref: approval key generation failed")
		return nil, 1, "internal"
	}
	defer secret.Wipe(ephPrivate)
	ephPublic, err := crypto.PublicKeyOf(wire.KEMX25519, ephPrivate)
	if err != nil {
		fmt.Fprintln(opts.Stderr, "keyref: approval key generation failed")
		return nil, 1, "internal"
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	nowMs := time.Now().UnixMilli()
	req := request{
		V: 1, CLIDeviceID: opts.DeviceID, ItemID: opts.ItemID,
		Argv: opts.Argv, Refs: sortedCopy(opts.Refs),
		Injection: strings.Join(sortedCopy(opts.Injection), ","),
		Hosts:     opts.Hosts, Reply: opts.Reply,
		EphemeralKEM:       wire.KEMX25519,
		EphemeralPublicKey: wire.Blob(ephPublic),
		CreatedAt:          nowMs,
	}
	plaintext, err := json.Marshal(req)
	if err != nil {
		fmt.Fprintln(opts.Stderr, "keyref: approval request encoding failed")
		return nil, 1, "internal"
	}

	// HPKE to the owner device (purpose=approval-request), then the
	// ciphertext layout enc ‖ ct ‖ tag of protocol §6.19.
	info, err := crypto.Info(crypto.PurposeApprovalRequest, opts.VaultID, owner.DeviceID)
	if err != nil {
		fmt.Fprintln(opts.Stderr, "keyref: approval request encoding failed")
		return nil, 1, "internal"
	}
	enc, ct, err := crypto.WrapKey(owner.HPKEKEM, owner.HPKEPublicKey, info, plaintext)
	if err != nil {
		fmt.Fprintln(opts.Stderr, "keyref: approval request encryption failed")
		return nil, 1, "internal"
	}
	requestCiphertext := make([]byte, 0, len(enc)+len(ct))
	requestCiphertext = append(requestCiphertext, enc...)
	requestCiphertext = append(requestCiphertext, ct...)

	// The CLI device signs the raw ciphertext bytes (protocol D7).
	signature, err := wire.SignEd25519(requestCiphertext, opts.Identity.SignPrivate)
	if err != nil {
		fmt.Fprintln(opts.Stderr, "keyref: approval request signing failed")
		return nil, 1, "internal"
	}

	created, err := opts.Client.ApprovalCreate(&wire.ApprovalCreateRequest{
		ItemID:            opts.ItemID,
		RequestCiphertext: requestCiphertext,
		RequestSignature:  signature,
		ExpiresAt:         nowMs + timeout.Milliseconds(),
	})
	if err != nil {
		if client.Code(err) == "quota_exceeded" {
			fmt.Fprintln(opts.Stderr, "keyref: approval queue is full (10 pending); try again later")
			return nil, 13, "approval-queue-full"
		}
		fmt.Fprintln(opts.Stderr, "keyref: cannot submit approval request")
		return nil, 1, "approval-submit"
	}
	fmt.Fprintf(opts.Stderr, "keyref: approval requested for %s (waiting up to %s)\n", opts.Ref, timeout.Truncate(time.Second))

	return pollAndWait(opts, created.ApprovalID, requestCiphertext, ephPrivate, timeout)
}

// pollAndWait polls the approval at the 2-second floor until the wrap
// arrives, the owner denies, the request expires or the caller's
// deadline passes (exit 13 on all of those, design §7.6).
func pollAndWait(opts *Options, approvalID string, requestCiphertext, ephPrivate []byte, timeout time.Duration) (*secret.Key, int, string) {
	deadline := time.Now().Add(timeout)
	// The first poll may run immediately; every later poll waits out the
	// server's 2-second floor.
	first := true
	for {
		if !first {
			if time.Now().Add(PollInterval).After(deadline) {
				fmt.Fprintln(opts.Stderr, "keyref: approval timed out")
				return nil, 13, "approval-timeout"
			}
			time.Sleep(PollInterval)
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(opts.Stderr, "keyref: approval timed out")
			return nil, 13, "approval-timeout"
		}
		first = false

		resp, err := opts.Client.ApprovalPoll(approvalID)
		if err != nil {
			if client.Code(err) == "rate_limited" {
				continue // clock skew: back off and stay within the contract
			}
			if time.Now().After(deadline) {
				fmt.Fprintln(opts.Stderr, "keyref: approval timed out")
				return nil, 13, "approval-timeout"
			}
			continue // transient network errors retry until the deadline
		}
		switch resp.Status {
		case wire.ApprovalStatusPending:
			continue
		case wire.ApprovalStatusDenied:
			fmt.Fprintln(opts.Stderr, "keyref: approval denied on the phone")
			return nil, 13, "approval-denied"
		case wire.ApprovalStatusExpired:
			fmt.Fprintln(opts.Stderr, "keyref: approval expired")
			return nil, 13, "approval-expired"
		case wire.ApprovalStatusConsumed:
			// Someone already picked this wrap up; it cannot be reused.
			fmt.Fprintln(opts.Stderr, "keyref: approval wrap already consumed")
			return nil, 13, "approval-consumed"
		case wire.ApprovalStatusApproved:
			key, err := itemcrypt.UnwrapOneTimeItemKey(
				opts.VaultID, opts.DeviceID, opts.ItemID, approvalID,
				requestCiphertext, resp.OneTimeEnc, resp.OneTimeWrappedKey, ephPrivate)
			if err != nil {
				fmt.Fprintln(opts.Stderr, "keyref: one-time wrap did not open (request or item mismatch)")
				return nil, 13, "approval-unwrap"
			}
			return key, 0, ""
		default:
			fmt.Fprintln(opts.Stderr, "keyref: unexpected approval status")
			return nil, 1, "approval-status"
		}
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
