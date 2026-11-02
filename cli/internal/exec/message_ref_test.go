package exec

import "testing"

// TestParseMessageRef pins the sms:<message_id> grammar (design v0.8
// §14.5, protocol §1.1: 16 random bytes as 32 lowercase hex). Anything
// that is not exactly that shape must fall through to the ordinary
// unknown-ref path, not be treated as a message.
func TestParseMessageRef(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"

	cases := []struct {
		ref  string
		want string
		ok   bool
	}{
		{"sms:" + id, id, true},
		{"sms:", "", false},
		{"sms:0123456789ABCDEF0123456789abcdef", "", false},  // uppercase
		{"sms:0123456789abcdef0123456789abcde", "", false},   // 31 chars
		{"sms:0123456789abcdef0123456789abcdef0", "", false}, // 33 chars
		{"sms:0123456789abcdef0123456789abcdeg", "", false},  // non-hex
		{"SMS:" + id, "", false},
		{"item:" + id, "", false},
		{"openai-prod", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := ParseMessageRef(c.ref)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseMessageRef(%q) = (%q, %v), want (%q, %v)", c.ref, got, ok, c.want, c.ok)
		}
	}
}

// TestHasMessagePlaceholder: {{keyref:sms:…}} is not a syntax (design
// §14.5) and must be detected so the caller can reject it instead of
// handing the literal text to the child.
func TestHasMessagePlaceholder(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	if !HasMessagePlaceholder([]string{"curl", "{{keyref:sms:" + id + "}}"}) {
		t.Fatal("sms placeholder not detected")
	}
	if HasMessagePlaceholder([]string{"curl", "{{keyref:openai-prod}}"}) {
		t.Fatal("item placeholder misread as a message placeholder")
	}
	if HasMessagePlaceholder([]string{"curl", "sms:" + id}) {
		t.Fatal("a bare sms: value is not a placeholder")
	}
}
