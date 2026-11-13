// Package decider implements the optional auto-approval delegate of design
// v0.8 §14.8.
//
// A `kind = decider` device holds the plaintext of every message within the
// 24-hour TTL (the envelope wraps one copy to it) and can answer
// message-subject approvals on the owner's behalf — but only inside the
// policy the owner signed, and only with a mandatory external review.
//
// The rules this package enforces, in order:
//
//  1. Only `message:` subjects. Item consumptions are always human-signed
//     (the server refuses a decider decision on them too).
//  2. The signed policy must parse strictly (unknown fields are an error,
//     never something to ignore) and must actually hit: sender allowlist
//     (byte-exact), maximum age by the SERVER's created_at, allowed CLI
//     devices, and the per-CLI hourly / daily caps.
//  3. The review gate is mandatory and cannot be disabled: no reviewer, a
//     reviewer error, or a veto all mean "leave it pending".
//  4. Any failure is a non-decision. The approval stays pending and the
//     human path is unchanged; the CLI times out with 13.
//
// The payload sent to the CLI is the message's plaintext JSON (D18), sealed
// to the request's ephemeral public key — the message key never leaves the
// owner/decider domain.
package decider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/audit"
	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/device"
)

// Verdict is the reviewer's answer. It can only veto or pass — it never
// creates authorization of its own (design §14.8).
type Verdict int

const (
	// Veto refuses this consumption.
	Veto Verdict = iota
	// Pass leaves the structural policy in charge.
	Pass
)

// ReviewInput is what the reviewer sees. Body is UNTRUSTED — anyone can
// text this phone and the sender can be spoofed (B9) — so it is kept apart
// from the structured metadata that drives the decision.
type ReviewInput struct {
	MessageID string
	// Structured metadata (trusted relative to Body).
	Sender       string
	SourceDevice string
	AgeSeconds   int64
	CLI          string
	Argv         []string
	MatchedRule  string
	// Untrusted payload.
	Body string
}

// Reviewer is the mandatory second gate. Any error is treated as a veto.
type Reviewer interface {
	Review(ctx context.Context, in ReviewInput) (Verdict, error)
}

// ReviewerFunc adapts a function to Reviewer.
type ReviewerFunc func(ctx context.Context, in ReviewInput) (Verdict, error)

func (f ReviewerFunc) Review(ctx context.Context, in ReviewInput) (Verdict, error) {
	return f(ctx, in)
}

// Config wires one decider.
type Config struct {
	VaultID            string
	DeviceID           string
	Identity           *device.Identity
	Client             *client.Client
	Reviewer           Reviewer
	OwnerSignPublicKey []byte // pinned at pairing (§9.2)
	Now                func() time.Time
	Logger             *log.Logger
	// Devices returns the owner-signed device directory. It is the only
	// authority for the CLI key that signs an approval request (protocol
	// v2 A) — without it the plaintext would go to whatever key the
	// server put in the row.
	Devices func() ([]audit.DeviceRecord, error)
}

// Decider runs the §14.8 loop. Safe for sequential use; RunOnce is
// idempotent per pending approval because the server allows only one live
// approval per message.
type Decider struct {
	cfg     Config
	limiter *Limiter
}

// New builds a decider.
func New(cfg Config) (*Decider, error) {
	if !wire.ValidID(cfg.VaultID) || !wire.ValidID(cfg.DeviceID) {
		return nil, errors.New("decider: vault and device ids must be 32 lowercase hex")
	}
	if len(cfg.OwnerSignPublicKey) == 0 {
		return nil, errors.New("decider: owner signing key is required to verify the delegation")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	return &Decider{cfg: cfg, limiter: NewLimiter(cfg.Now)}, nil
}

// RunOnce performs one poll cycle and returns how many approvals it
// auto-answered. Every skip is logged with its reason; nothing is ever
// approved without passing every gate.
func (d *Decider) RunOnce(ctx context.Context) (approved int, err error) {
	policy, err := d.loadPolicy(ctx)
	if err != nil {
		return 0, err
	}
	if policy.IsEmpty() {
		// No delegation (or the revocation policy): nothing may be
		// auto-approved. This is the default posture.
		return 0, nil
	}

	list, err := d.cfg.Client.ListApprovals(wire.ApprovalStatusPending)
	if err != nil {
		return 0, fmt.Errorf("decider: list approvals: %w", err)
	}
	for _, row := range list.Approvals {
		if row.MessageID == "" {
			// Item consumptions are always human-signed (design §14.8).
			continue
		}
		if ok := d.tryApprove(ctx, policy, row); ok {
			approved++
		}
	}
	return approved, nil
}

// loadPolicy fetches, verifies and parses the owner's delegation.
func (d *Decider) loadPolicy(ctx context.Context) (wire.DelegationPolicy, error) {
	got, err := d.cfg.Client.GetDelegation()
	if err != nil {
		return wire.DelegationPolicy{}, fmt.Errorf("decider: get delegation: %w", err)
	}
	if got.DelegationRevision == 0 || len(got.DelegationSigned) == 0 {
		return wire.DelegationPolicy{}, nil // 未委托
	}
	// The policy bytes are verified BEFORE use, against the owner key
	// pinned at pairing — the server only relays them (design §14.8).
	if err := wire.VerifyOwnerSignature(got.DelegationSigned, got.Signature,
		d.cfg.OwnerSignPublicKey); err != nil {
		return wire.DelegationPolicy{}, fmt.Errorf("decider: delegation signature: %w", err)
	}
	t, err := wire.ParseDelegationTranscript(got.DelegationSigned, d.cfg.VaultID)
	if err != nil {
		return wire.DelegationPolicy{}, fmt.Errorf("decider: delegation transcript: %w", err)
	}
	if t.DelegationRevision != got.DelegationRevision {
		return wire.DelegationPolicy{}, errors.New("decider: delegation revision mismatch")
	}
	policy, err := wire.ParseDelegationPolicy(t.PolicyJSON)
	if err != nil {
		return wire.DelegationPolicy{}, fmt.Errorf("decider: %w", err)
	}
	return policy, nil
}

// tryApprove walks every gate for one approval. It returns true only when
// the decision was accepted by the server.
func (d *Decider) tryApprove(ctx context.Context, policy wire.DelegationPolicy, row wire.ApprovalRow) bool {
	logf := func(format string, args ...any) {
		d.cfg.Logger.Printf("decider: %s: "+format,
			append([]any{row.ApprovalID}, args...)...)
	}

	// Gate 1 — the CLI must be allowed.
	if !policy.AllowsCLI(row.CLIDeviceID) {
		logf("CLI %s is not in the delegation", row.CLIDeviceID)
		return false
	}
	// Gate 2 — the request must expose the ephemeral key the decision
	// seals to (D16); without it there is no way to answer.
	if len(row.CLIEphemeralPublicKey) != wire.SizeX25519Key {
		logf("approval carries no CLI ephemeral key")
		return false
	}
	// Gate 2b — the request must be signed by the CLI device the owner's
	// directory lists as active CLI (protocol v2 A). This is what binds
	// the plaintext ephemeral key above to a real request: the decider
	// never decrypts request_ciphertext, so without the signature the
	// server could substitute its own key and read the code.
	if !d.verifyRequest(row) {
		logf("approval request signature does not verify under the signed directory")
		return false
	}

	// Gate 3 — the message itself.
	msg, err := d.findMessage(ctx, row.MessageID)
	if err != nil {
		logf("message lookup: %v", err)
		return false
	}
	plaintext, sender, err := d.openMessage(msg)
	if err != nil {
		logf("message open: %v", err)
		return false
	}
	// Gate 4 — age by the SERVER's clock (never the device-reported
	// received_at, §6.29).
	age := d.cfg.Now().UnixMilli() - msg.CreatedAt
	if age < 0 {
		age = 0
	}
	if policy.MaxAgeMin > 0 && age > policy.MaxAgeMin*60_000 {
		logf("message is %ds old, delegation allows %dm", age/1000, policy.MaxAgeMin)
		return false
	}
	// Gate 5 — sender allowlist, byte-exact.
	if !policy.AllowsSender(sender) {
		logf("sender %q is not in the delegation", sender)
		return false
	}
	// Gate 6 — per-CLI rate limits.
	if !d.limiter.Allow(row.CLIDeviceID, policy) {
		logf("per-CLI limit reached")
		return false
	}

	// Gate 7 — the mandatory review. No reviewer configured is a veto, not
	// a pass: the design forbids "auto-approve because nothing could
	// check" (§14.8 failure semantics).
	if d.cfg.Reviewer == nil {
		logf("no review API configured; leaving it for a human")
		return false
	}
	verdict, err := d.cfg.Reviewer.Review(ctx, ReviewInput{
		MessageID:    msg.MessageID,
		Sender:       sender,
		SourceDevice: msg.SourceDeviceID,
		AgeSeconds:   age / 1000,
		CLI:          row.CLIDeviceID,
		MatchedRule:  "sender+age+cli",
		Body:         bodyOf(plaintext),
	})
	if err != nil {
		logf("review failed: %v", err)
		return false
	}
	if verdict != Pass {
		logf("review vetoed")
		return false
	}

	// Answer exactly like the phone: the message plaintext JSON, sealed to
	// the CLI's ephemeral key under the one-time-message binding (D18).
	info, err := crypto.OneTimeMessageKeyInfo(d.cfg.VaultID, row.CLIDeviceID,
		row.MessageID, row.ApprovalID, row.RequestCiphertext)
	if err != nil {
		logf("decision info: %v", err)
		return false
	}
	enc, wrapped, err := crypto.WrapKey(wire.KEMX25519, row.CLIEphemeralPublicKey, info, plaintext)
	if err != nil {
		logf("decision wrap: %v", err)
		return false
	}
	// Sign the decision before submitting it (protocol §3.12, v2 B): the
	// CLI verifies this signature before unwrapping, so an unsigned
	// decision would be refused on the other end.
	dtb, err := wire.BuildApprovalDecisionTranscript(wire.ApprovalDecisionTranscript{
		VaultID:           d.cfg.VaultID,
		ApprovalID:        row.ApprovalID,
		DecisionDeviceID:  d.cfg.DeviceID,
		Decision:          wire.ApprovalStatusApproved,
		RequestCiphertext: row.RequestCiphertext,
		OneTimeEnc:        enc,
		OneTimeWrappedKey: wrapped,
	})
	if err != nil {
		logf("decision transcript: %v", err)
		return false
	}
	dsig, err := wire.SignEd25519(dtb, d.cfg.Identity.SignPrivate)
	if err != nil {
		logf("decision signing: %v", err)
		return false
	}
	if err := d.cfg.Client.SubmitApprovalDecision(row.ApprovalID, &wire.ApprovalDecisionRequest{
		Decision:          wire.ApprovalStatusApproved,
		OneTimeEnc:        enc,
		OneTimeWrappedKey: wrapped,
		DecisionSignature: dsig,
	}); err != nil {
		logf("submit decision: %v", err)
		return false
	}
	d.limiter.Record(row.CLIDeviceID)
	d.cfg.Logger.Printf("decider: auto-approved %s (sender %q, CLI %s, %dms old)",
		row.ApprovalID, sender, row.CLIDeviceID, age)
	return true
}

// findMessage locates the message row the approval refers to.
func (d *Decider) findMessage(ctx context.Context, messageID string) (wire.MessageRow, error) {
	list, err := d.cfg.Client.ListMessages(0)
	if err != nil {
		return wire.MessageRow{}, err
	}
	for _, m := range list.Messages {
		if m.MessageID == messageID {
			if m.Status != wire.MessageStatusActive {
				return wire.MessageRow{}, errors.New("message is not active")
			}
			return m, nil
		}
	}
	return wire.MessageRow{}, errors.New("message not found")
}

// openMessage decrypts the envelope with this decider's device key and
// returns the §3.9 plaintext JSON plus the sender.
func (d *Decider) openMessage(msg wire.MessageRow) (plaintext []byte, sender string, err error) {
	plaintext, err = crypto.OpenMessage(msg.Envelope, d.cfg.VaultID, msg.SourceDeviceID,
		d.cfg.DeviceID, func(info, enc, ct []byte) ([]byte, error) {
			return crypto.UnwrapKey(wire.KEMX25519, d.cfg.Identity.HPKEPrivate, info, enc, ct)
		})
	if err != nil {
		return nil, "", err
	}
	var p struct {
		V      int    `json:"v"`
		Sender string `json:"sender"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, "", err
	}
	if p.V != 1 {
		return nil, "", errors.New("unsupported message version")
	}
	return plaintext, p.Sender, nil
}

func bodyOf(plaintext []byte) string {
	var p struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return ""
	}
	return p.Body
}

// Limiter enforces the per-CLI hourly and daily caps of the delegation.
// Counters are in memory: a restart forgets them, which can only make the
// decider more conservative within one lifetime — but it does mean a
// restart resets the budget, so the caps are a backstop, not a guarantee.
type Limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	history map[string][]time.Time
}

// NewLimiter builds an empty limiter.
func NewLimiter(now func() time.Time) *Limiter {
	return &Limiter{now: now, history: map[string][]time.Time{}}
}

// Allow reports whether one more auto-approval fits inside the caps.
func (l *Limiter) Allow(cli string, p wire.DelegationPolicy) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-24 * time.Hour)
	kept := l.history[cli][:0]
	for _, t := range l.history[cli] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.history[cli] = kept
	hourAgo := now.Add(-time.Hour)
	var hourly int
	for _, t := range kept {
		if t.After(hourAgo) {
			hourly++
		}
	}
	if p.PerCLIHourly > 0 && int64(hourly) >= p.PerCLIHourly {
		return false
	}
	if p.PerCLIDaily > 0 && int64(len(kept)) >= p.PerCLIDaily {
		return false
	}
	return true
}

// Record counts one auto-approval against the CLI's budget.
func (l *Limiter) Record(cli string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.history[cli] = append(l.history[cli], l.now())
}

// verifyRequest checks the CLI's signature over the approval-request
// transcript (protocol §3.11) using the key the owner's signed directory
// gives that device. Any doubt — no directory source, unknown device,
// revoked device, wrong kind, bad signature — is a veto: the approval
// stays pending for a human (design §14.8 failure semantics).
func (d *Decider) verifyRequest(row wire.ApprovalRow) bool {
	if d.cfg.Devices == nil {
		return false
	}
	devices, err := d.cfg.Devices()
	if err != nil {
		return false
	}
	var dev *audit.DeviceRecord
	for i := range devices {
		if devices[i].DeviceID == row.CLIDeviceID {
			dev = &devices[i]
			break
		}
	}
	if dev == nil || dev.Status != wire.DeviceStatusActive || dev.Kind != wire.DeviceKindCLI {
		return false
	}
	tb, err := wire.BuildApprovalRequestTranscript(wire.ApprovalRequestTranscript{
		VaultID:               d.cfg.VaultID,
		CLIDeviceID:           row.CLIDeviceID,
		SubjectKind:           wire.EntityMessage,
		SubjectID:             row.MessageID,
		ExpiresAt:             uint64(row.ExpiresAt),
		CLIEphemeralPublicKey: row.CLIEphemeralPublicKey,
		RequestCiphertext:     row.RequestCiphertext,
	})
	if err != nil {
		return false
	}
	return wire.VerifyCLISignature(tb, row.RequestSignature, dev.SignPublicKey) == nil
}
