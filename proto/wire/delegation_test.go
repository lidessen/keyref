package wire

import "testing"

// The delegation policy is the only owner-signed artifact the decider acts
// on, so its parser is deliberately strict: unknown fields are an error,
// an empty sender list is a revocation, and sender matching is byte-exact
// (design v0.8 §14.8: the decider may narrow, never broaden).
func TestParseDelegationPolicy(t *testing.T) {
	p, err := ParseDelegationPolicy(`{"v":1,"senders":["10086","95533"],"max_age_min":5,
		"per_cli_hourly":10,"per_cli_daily":50,"cli_devices":["aaaabbbbccccddddeeeeffff00001111"]}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.IsEmpty() || len(p.Senders) != 2 || p.MaxAgeMin != 5 ||
		p.PerCLIHourly != 10 || p.PerCLIDaily != 50 {
		t.Fatalf("policy: %+v", p)
	}
	if !p.AllowsSender("10086") || p.AllowsSender("+8610086") {
		t.Fatal("sender matching must be byte-exact")
	}
	if !p.AllowsCLI("aaaabbbbccccddddeeeeffff00001111") ||
		p.AllowsCLI("bbbbccccddddeeeeffff000011112222") {
		t.Fatal("CLI allowlist must be exact and closed")
	}
}

func TestDelegationPolicyRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":  `{"v":1,"senders":["10086"],"surprise":true}`,
		"wrong version":  `{"v":2,"senders":["10086"]}`,
		"negative limit": `{"v":1,"senders":["10086"],"per_cli_hourly":-1}`,
		"bad cli id":     `{"v":1,"senders":["10086"],"cli_devices":["nope"]}`,
		"empty sender":   `{"v":1,"senders":[""]}`,
		"not json":       `{`,
	}
	for name, raw := range cases {
		if _, err := ParseDelegationPolicy(raw); err == nil {
			t.Errorf("%s: parsed when it should not", name)
		}
	}
}

// {"v":1} is the revocation policy: no senders, so nothing can ever match.
func TestEmptyDelegationIsRevocation(t *testing.T) {
	p, err := ParseDelegationPolicy(`{"v":1}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.IsEmpty() {
		t.Fatal("an empty policy must report empty")
	}
	if p.AllowsSender("10086") {
		t.Fatal("an empty policy must allow no sender")
	}
	// An empty cli_devices list means "no restriction" — it is not a
	// second revocation switch; the sender list is the one that matters.
	if !p.AllowsCLI("aaaabbbbccccddddeeeeffff00001111") {
		t.Fatal("an empty CLI list must not block")
	}
}

// ---- §3.10 delegation transcript ----

func buildDelegation(t *testing.T, vaultID string, rev uint64, policy string) []byte {
	t.Helper()
	tb, err := BuildDelegationTranscript(DelegationTranscript{
		VaultID: vaultID, DelegationRevision: rev, PolicyJSON: policy})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return tb
}

func TestDelegationTranscriptRoundTrip(t *testing.T) {
	const vault = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	policy := `{"v":1,"senders":["10086"]}`
	tb := buildDelegation(t, vault, 3, policy)

	got, err := ParseDelegationTranscript(tb, vault)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.VaultID != vault || got.DelegationRevision != 3 || got.PolicyJSON != policy {
		t.Fatalf("round trip: %+v", got)
	}
}

// The parser rebuilds and compares, so a structural change fails closed
// (§1.5: transcripts are write-only). Content tampering inside a still
// valid policy string is caught by the owner SIGNATURE, not by the parser
// — this test pins the parser's half of that contract.
func TestDelegationTranscriptRejectsStructuralTamper(t *testing.T) {
	const vault = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	tb := buildDelegation(t, vault, 1, `{"v":1,"senders":["10086"]}`)

	cases := map[string][]byte{
		// NB: truncating the last policy byte still round-trips — the
		// parser guarantees framing, and JSON validity is the policy
		// parser's job (ParseDelegationPolicy rejects it).
		"separator removed": func() []byte {
			b := append([]byte(nil), tb...)
			// The NUL before the policy JSON.
			i := len(b) - len(`{"v":1,"senders":["10086"]}`) - 1
			if b[i] != 0x00 {
				t.Fatalf("expected a separator at %d", i)
			}
			return append(b[:i], b[i+1:]...)
		}(),
	}
	for name, bad := range cases {
		if _, err := ParseDelegationTranscript(bad, vault); err == nil {
			t.Errorf("%s: parsed when it should not", name)
		}
	}
}

func TestDelegationTranscriptRejectsWrongVault(t *testing.T) {
	tb := buildDelegation(t, "0f1e2d3c4b5a69788796a5b4c3d2e1f0", 1, `{"v":1}`)
	if _, err := ParseDelegationTranscript(tb, "ffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("a transcript for another vault parsed")
	}
}

func TestBuildDelegationTranscriptRejects(t *testing.T) {
	const vault = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	cases := map[string]DelegationTranscript{
		"bad vault":     {VaultID: "nope", DelegationRevision: 1, PolicyJSON: `{"v":1}`},
		"empty policy":  {VaultID: vault, DelegationRevision: 1, PolicyJSON: ""},
		"invalid utf-8": {VaultID: vault, DelegationRevision: 1, PolicyJSON: "\xff"},
	}
	for name, c := range cases {
		if _, err := BuildDelegationTranscript(c); err == nil {
			t.Errorf("%s: built when it should not", name)
		}
	}
}

// The revision is fixed-width inside the transcript: a revision whose bytes
// contain 0x00 must not break the positional parse (a NUL-splitting parser
// would).
func TestDelegationTranscriptRevisionWithZeroBytes(t *testing.T) {
	const vault = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	tb := buildDelegation(t, vault, 0x0100000000000002, `{"v":1}`)
	got, err := ParseDelegationTranscript(tb, vault)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.DelegationRevision != 0x0100000000000002 {
		t.Fatalf("revision: %d", got.DelegationRevision)
	}
}
