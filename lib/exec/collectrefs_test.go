package exec

import (
	"reflect"
	"testing"
)

// CollectRefs is what a caller without synced item metas — a local
// source — uses to populate Request.Refs before Run.
func TestCollectRefs(t *testing.T) {
	req := &Request{
		EnvRefs:  []string{"A=one", "B=two"},
		FdRefs:   []string{"3=three"},
		StdinRef: "four",
		Replies:  []Reply{{Pattern: "Password:", Ref: "six"}},
		Argv:     []string{"cmd", "{{keyref:five}}"},
	}
	want := []string{"one", "two", "three", "four", "six", "five"}
	if got := CollectRefs(req); !reflect.DeepEqual(got, want) {
		t.Fatalf("CollectRefs = %v, want %v", got, want)
	}
}

func TestCollectRefsDeduplicates(t *testing.T) {
	req := &Request{
		EnvRefs:  []string{"A=one", "B=one"},
		StdinRef: "one",
		Argv:     []string{"cmd", "{{keyref:one}}"},
	}
	want := []string{"one"}
	if got := CollectRefs(req); !reflect.DeepEqual(got, want) {
		t.Fatalf("CollectRefs = %v, want %v", got, want)
	}
}

// A malformed spec contributes no ref: Run rejects the spec itself, and
// pre-filling a ref from it would only widen what gets decrypted.
func TestCollectRefsSkipsMalformedSpecs(t *testing.T) {
	req := &Request{
		EnvRefs: []string{"no-equals-sign", "=empty-name"},
		FdRefs:  []string{"2=too-low", "x=not-a-number"},
	}
	if got := CollectRefs(req); len(got) != 0 {
		t.Fatalf("CollectRefs = %v, want none", got)
	}
}

// Without --allow-argv there is no placeholder substitution, but the
// refs still have to be known so Run can reject them by policy.
func TestCollectRefsSeesArgvPlaceholders(t *testing.T) {
	req := &Request{Argv: []string{"cmd", "{{keyref:one}}", "{{keyref:two}}"}}
	want := []string{"one", "two"}
	if got := CollectRefs(req); !reflect.DeepEqual(got, want) {
		t.Fatalf("CollectRefs = %v, want %v", got, want)
	}
}
