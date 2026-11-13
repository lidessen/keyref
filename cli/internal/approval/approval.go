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
// into guarded memory and the ephemeral private key is wiped.
//
// The wrap carries one of two payloads, chosen by the caller from the
// local cache (design §6.6, v0.7): for SYNCED approval items the 32-byte
// one-time item key (RequestItemKey), for LOCAL items (server row has
// secret_ciphertext NULL, so the CLI cache holds none) the secret value
// itself, up to 64 KiB (RequestSecret). The server is a blind relay for
// either; both unwrap under the same D4 info binding.
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
// field is the one addition beyond protocol §6.19's JSON). For a message
// consumption (design §14.5) MessageID is set and ItemID empty; the
// server-side subject becomes message:<id> (protocol D16).
type request struct {
	V                  int       `json:"v"`
	CLIDeviceID        string    `json:"cli_device_id"`
	ItemID             string    `json:"item_id,omitempty"`
	MessageID          string    `json:"message_id,omitempty"`
	Argv               []string  `json:"argv"`
	Refs               []string  `json:"refs"`
	Injection          string    `json:"injection"`
	Hosts              []string  `json:"hosts"`
	Reply              []string  `json:"reply,omitempty"`
	EphemeralKEM       string    `json:"ephemeral_kem"`
	EphemeralPublicKey wire.Blob `json:"ephemeral_public_key"`
	CreatedAt          int64     `json:"created_at"`

	// Execution context (review 2026-11): the approver must see what the
	// argv alone does not say — where the command runs, which file
	// actually executes, which ambient variables are forwarded, which
	// names hold the injected secret and where the fd payload goes.
	// Names, paths and templates only: no secret value ever appears here.
	// All eight fields are always present; unused ones are empty.
	CWD              string   `json:"cwd"`
	Executable       string   `json:"executable"`
	ExecutableReal   string   `json:"executable_real"`
	ExecutableLayers []string `json:"executable_layers"`
	PassNames        []string `json:"pass_names"`
	EnvNames         []string `json:"env_names"`
	FDTargets        []int    `json:"fd_targets"`
	FDTemplate       string   `json:"fd_template"`
}

// Options describes one approval request for one item of one exec.
type Options struct {
	VaultID   string
	DeviceID  string
	Identity  *device.Identity
	Owners    []audit.OwnerRecipient // active owner devices; the first is used
	ItemID    string
	MessageID string // set for sms:<id> consumption (§14.5); ItemID empty then
	Ref       string
	Argv      []string // child argv in placeholder form (never secrets)
	Refs      []string // every ref of the exec, sorted
	Injection []string // injection modes (env/fd/stdin/argv/pty/reply)
	Hosts     []string // the item's allowedHosts
	Reply     []string // full --reply specs (REGEX=REF)
	Timeout   time.Duration
	Client    *client.Client
	Stderr    io.Writer // progress notices, never secrets

	// Execution context shown on the approval screen. CWD and the
	// resolved executable come from the exec layer (OnPolicyPassed); the
	// names, fd targets and template come straight from the flags.
	// Values only: never a secret.
	CWD              string
	Executable       string   // absolute file the exec layer spawns
	ExecutableReal   string   // symlink- and shebang-resolved executable
	ExecutableLayers []string // argv0 plus every shebang interpreter
	PassNames        []string // ambient variables forwarded with --pass
	EnvNames         []string // names given the secret with --env
	FDTargets        []int    // fds that receive a payload
	FDTemplate       string   // --fd-template, verbatim

	// Devices is the owner-signed device directory as last synced: the
	// only trusted source for the deciding device's key (protocol v2 B).
	Devices []audit.DeviceRecord
	// RefreshDevices re-syncs and returns the directory again. It is used
	// once when the deciding device is not in Devices yet (a decision
	// arrived before the revocation/rotation reached this CLI). May be nil.
	RefreshDevices func() ([]audit.DeviceRecord, error)
}

// Result is the payload an approved decision delivered: exactly one
// field is set, depending on the unwrap the caller asked for.
// DecisionDeviceID names the device that signed the decision (protocol
// §6.22) so the caller can put it in the audit event (design v0.8
// §14.5/§14.8).
type Result struct {
	Key              *secret.Key       // synced approval items: the one-time item key
	Secret           *secret.Plaintext // local items: the secret value itself
	DecisionDeviceID string            // the owner (kind=ios) or decider (kind=decider) that decided
}

// unwrapFunc opens the approved one-time wrap while the ephemeral
// private key is still alive; it must not retain the key material.
type unwrapFunc func(vaultID, deviceID, itemID, approvalID string,
	requestCiphertext, enc, wrapped, ephPrivate []byte) (*Result, error)

// RequestItemKey runs one approval round for a SYNCED approval item and
// returns the unwrapped item key in guarded memory. The caller must
// Destroy the key after the single exec (design §8.3 step 5). The
// returned exit code and deny state follow the exec convention (13 for
// denied/expired/timeout). When decisionDevice is non-nil it receives
// the deciding device id of the round (protocol §6.22), empty if the
// round produced no decision — the caller forwards it to the audit event.
func RequestItemKey(opts *Options, decisionDevice *string) (key *secret.Key, exitCode int, state string) {
	res, code, st := run(opts, unwrapItemKey, decisionDevice)
	if res == nil {
		return nil, code, st
	}
	return res.Key, code, st
}

// RequestSecret runs one approval round for a LOCAL item (design §6.6,
// v0.7): the approved decision carries the secret value itself,
// HPKE-sealed to the request's ephemeral public key under the same
// one-time binding. The value lands in guarded memory; the caller must
// Destroy it right after the injection — it never reaches the cache or
// the keyring (design §15). See RequestItemKey for decisionDevice.
func RequestSecret(opts *Options, decisionDevice *string) (value *secret.Plaintext, exitCode int, state string) {
	res, code, st := run(opts, unwrapSecret, decisionDevice)
	if res == nil {
		return nil, code, st
	}
	return res.Secret, code, st
}

// unwrapItemKey opens a one-time ITEM KEY wrap (synced approval items).
func unwrapItemKey(vaultID, deviceID, itemID, approvalID string,
	requestCiphertext, enc, wrapped, ephPrivate []byte) (*Result, error) {
	key, err := itemcrypt.UnwrapOneTimeItemKey(vaultID, deviceID, itemID, approvalID,
		requestCiphertext, enc, wrapped, ephPrivate)
	if err != nil {
		return nil, err
	}
	return &Result{Key: key}, nil
}

// unwrapSecret opens a one-time SECRET wrap (local items).
func unwrapSecret(vaultID, deviceID, itemID, approvalID string,
	requestCiphertext, enc, wrapped, ephPrivate []byte) (*Result, error) {
	value, err := itemcrypt.UnwrapOneTimeSecret(vaultID, deviceID, itemID, approvalID,
		requestCiphertext, enc, wrapped, ephPrivate)
	if err != nil {
		return nil, err
	}
	return &Result{Secret: value}, nil
}

// RequestMessage runs one approval round for an sms:<id> consumption
// (design v0.8 §14.5): the approved decision carries the message
// plaintext JSON, HPKE-sealed to the request's ephemeral public key
// under the one-time-message-key binding. The plaintext lands in
// guarded memory; the caller extracts the body for the injection and
// Destroys the buffer right after — sms values never reach the cache or
// the keyring (design §16). See RequestItemKey for decisionDevice.
func RequestMessage(opts *Options, decisionDevice *string) (value *secret.Plaintext, exitCode int, state string) {
	res, code, st := run(opts, unwrapMessage, decisionDevice)
	if res == nil {
		return nil, code, st
	}
	return res.Secret, code, st
}

// unwrapMessage opens a one-time MESSAGE wrap (sms consumption).
func unwrapMessage(vaultID, deviceID, messageID, approvalID string,
	requestCiphertext, enc, wrapped, ephPrivate []byte) (*Result, error) {
	value, err := itemcrypt.UnwrapOneTimeMessage(vaultID, deviceID, messageID, approvalID,
		requestCiphertext, enc, wrapped, ephPrivate)
	if err != nil {
		return nil, err
	}
	return &Result{Secret: value}, nil
}

// run executes one approval round: request build, submission, polling
// and the caller-chosen unwrap of the approved wrap. decisionDevice, when
// non-nil, receives the deciding device id of the round (protocol §6.22).
func run(opts *Options, unwrap unwrapFunc, decisionDevice *string) (*Result, int, string) {
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
		MessageID: opts.MessageID,
		Argv:      opts.Argv, Refs: sortedCopy(opts.Refs),
		Injection: strings.Join(sortedCopy(opts.Injection), ","),
		Hosts:     opts.Hosts, Reply: opts.Reply,
		EphemeralKEM:       wire.KEMX25519,
		EphemeralPublicKey: wire.Blob(ephPublic),
		CreatedAt:          nowMs,
		CWD:                opts.CWD,
		Executable:         opts.Executable,
		ExecutableReal:     opts.ExecutableReal,
		ExecutableLayers:   opts.ExecutableLayers,
		PassNames:          opts.PassNames,
		EnvNames:           opts.EnvNames,
		FDTargets:          opts.FDTargets,
		FDTemplate:         opts.FDTemplate,
	}
	req.ExecutableLayers = emptyIfNil(req.ExecutableLayers)
	req.PassNames = emptyIfNil(req.PassNames)
	req.EnvNames = emptyIfNil(req.EnvNames)
	req.FDTargets = emptyIfNil(req.FDTargets)
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

	// The CLI device signs the approval-request transcript (protocol
	// §3.11, v2 A): the signature covers the subject, the expiry and the
	// one-time public key as well as a digest of the ciphertext.
	subjectKind, subjectIDForSignature := wire.EntityItem, opts.ItemID
	if opts.MessageID != "" {
		subjectKind, subjectIDForSignature = wire.EntityMessage, opts.MessageID
	}
	expiresAt := nowMs + timeout.Milliseconds()
	tb, err := wire.BuildApprovalRequestTranscript(wire.ApprovalRequestTranscript{
		VaultID:               opts.VaultID,
		CLIDeviceID:           opts.DeviceID,
		SubjectKind:           subjectKind,
		SubjectID:             subjectIDForSignature,
		ExpiresAt:             uint64(expiresAt),
		CLIEphemeralPublicKey: ephPublic,
		RequestCiphertext:     requestCiphertext,
	})
	if err != nil {
		fmt.Fprintln(opts.Stderr, "keyref: approval request encoding failed")
		return nil, 1, "internal"
	}
	signature, err := wire.SignEd25519(tb, opts.Identity.SignPrivate)
	if err != nil {
		fmt.Fprintln(opts.Stderr, "keyref: approval request signing failed")
		return nil, 1, "internal"
	}

	send := &wire.ApprovalCreateRequest{
		ItemID:            opts.ItemID,
		MessageID:         opts.MessageID,
		RequestCiphertext: requestCiphertext,
		RequestSignature:  signature,
		ExpiresAt:         expiresAt,
		// The one-time public key is a signed field for both subjects:
		// a decider never decrypts request_ciphertext, so this is the
		// only authenticated source for the key it wraps to (v2 A).
		CLIEphemeralPublicKey: ephPublic,
	}
	created, err := opts.Client.ApprovalCreate(send)
	if err != nil {
		switch client.Code(err) {
		case "quota_exceeded":
			fmt.Fprintln(opts.Stderr, "keyref: approval queue is full (10 pending); try again later")
			return nil, 13, "approval-queue-full"
		case "not_found":
			// The subject is gone: for an item that is an unknown ref
			// (§7.6), for a message it is "unknown, expired or already
			// consumed" and design §14.5 pins exit 11.
			if opts.MessageID != "" {
				fmt.Fprintln(opts.Stderr, "keyref: message is unknown, expired or already consumed")
			} else {
				fmt.Fprintf(opts.Stderr, "keyref: unknown ref %q\n", opts.Ref)
			}
			return nil, 11, "unknown-ref"
		case "approval_not_pending":
			// One live approval per message (§14.3): another consumption
			// of the same message is in flight.
			fmt.Fprintln(opts.Stderr, "keyref: another consumption of this message is already pending")
			return nil, 13, "approval-busy"
		}
		fmt.Fprintln(opts.Stderr, "keyref: cannot submit approval request")
		return nil, 1, "approval-submit"
	}
	fmt.Fprintf(opts.Stderr, "keyref: approval requested for %s (waiting up to %s)\n", opts.Ref, timeout.Truncate(time.Second))

	return pollAndWait(opts, created.ApprovalID, requestCiphertext, ephPrivate, timeout, unwrap, decisionDevice)
}

// pollAndWait polls the approval at the 2-second floor until the wrap
// arrives, the owner denies, the request expires or the caller's
// deadline passes (exit 13 on all of those, design §7.6). Every terminal
// answer that carries a decision_device_id (§6.22) is forwarded to
// decisionDevice and, on approval, onto the Result — the audit event
// names who decided (design v0.8 §14.5/§14.8).
func pollAndWait(opts *Options, approvalID string, requestCiphertext, ephPrivate []byte, timeout time.Duration,
	unwrap unwrapFunc, decisionDevice *string) (*Result, int, string) {
	deadline := time.Now().Add(timeout)
	// The first poll may run immediately; every later poll waits out the
	// server's 2-second floor.
	first := true
	var decidedBy string
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
		if resp.DecisionDeviceID != "" {
			decidedBy = resp.DecisionDeviceID
			if decisionDevice != nil {
				*decisionDevice = decidedBy
			}
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
			// Before anything is unwrapped: the decision must be signed by
			// a device the owner's directory lists as active, for this
			// wrap (protocol §3.12, v2 B). HPKE base mode authenticates
			// nothing, so an unverified wrap is just server bytes.
			if err := verifyDecision(opts, approvalID, requestCiphertext, resp); err != nil {
				fmt.Fprintln(opts.Stderr, "keyref: approval decision is not signed by a trusted device")
				return nil, 13, "approval-decision-unverified"
			}
			// The binding subject is the message for an sms: consumption
			// (protocol §3.7 one-time-message-key) and the item
			// otherwise.
			subjectID := opts.ItemID
			if opts.MessageID != "" {
				subjectID = opts.MessageID
			}
			res, err := unwrap(opts.VaultID, opts.DeviceID, subjectID, approvalID,
				requestCiphertext, resp.OneTimeEnc, resp.OneTimeWrappedKey, ephPrivate)
			if err != nil {
				fmt.Fprintln(opts.Stderr, "keyref: one-time wrap did not open (request or subject mismatch)")
				return nil, 13, "approval-unwrap"
			}
			res.DecisionDeviceID = decidedBy
			return res, 0, ""
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

// emptyIfNil keeps an always-present JSON array an array ([]) rather
// than null, which a strict decoder would reject.
func emptyIfNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

// verifyDecision checks the decision device's signature over the
// approval-decision transcript (protocol §3.12, v2 B). The deciding
// device must come from the owner-signed directory: active, and either
// the owner (kind=ios) or — for a message subject only — a delegated
// decider (kind=decider).
func verifyDecision(opts *Options, approvalID string, requestCiphertext []byte, resp *wire.ApprovalPollResponse) error {
	if resp.DecisionDeviceID == "" || len(resp.DecisionSignature) == 0 {
		return errors.New("approval: decision carries no signature")
	}
	dev, ok := findDevice(opts.Devices, resp.DecisionDeviceID)
	if !ok && opts.RefreshDevices != nil {
		// The device may have been added since the last sync; refresh
		// once and look again (protocol v2 B).
		opts.Devices, _ = opts.RefreshDevices()
		dev, ok = findDevice(opts.Devices, resp.DecisionDeviceID)
	}
	if !ok {
		return errors.New("approval: deciding device is not in the signed directory")
	}
	if dev.Status != wire.DeviceStatusActive {
		return errors.New("approval: deciding device is not active")
	}
	switch {
	case dev.Kind == wire.DeviceKindIOS:
	case dev.Kind == wire.DeviceKindDecider && opts.MessageID != "":
		// A delegated decider only ever answers SMS consumptions.
	default:
		return errors.New("approval: deciding device kind cannot decide this subject")
	}
	tb, err := wire.BuildApprovalDecisionTranscript(wire.ApprovalDecisionTranscript{
		VaultID:           opts.VaultID,
		ApprovalID:        approvalID,
		DecisionDeviceID:  resp.DecisionDeviceID,
		Decision:          resp.Status,
		RequestCiphertext: requestCiphertext,
		OneTimeEnc:        resp.OneTimeEnc,
		OneTimeWrappedKey: resp.OneTimeWrappedKey,
	})
	if err != nil {
		return err
	}
	return wire.VerifyDeviceSignature(tb, resp.DecisionSignature, dev.SignAlg, dev.SignPublicKey)
}

func findDevice(devices []audit.DeviceRecord, id string) (audit.DeviceRecord, bool) {
	for _, d := range devices {
		if d.DeviceID == id {
			return d, true
		}
	}
	return audit.DeviceRecord{}, false
}
