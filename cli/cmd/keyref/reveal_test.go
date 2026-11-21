package main

import (
	"strings"
	"testing"
)

func TestReadConfirmLine(t *testing.T) {
	for answer, want := range map[string]string{
		"y\n":     "y",
		"Y\n":     "y",
		"yes\n":   "yes",
		"YES\r\n": "yes",
		" y \n":   "y",
		"\n":      "",
		"n\n":     "n",
		"no\n":    "no",
	} {
		got, err := readConfirmLine(strings.NewReader(answer))
		if err != nil {
			t.Fatalf("%q: %v", answer, err)
		}
		if got != want {
			t.Fatalf("%q: got %q, want %q", answer, got, want)
		}
	}

	// EOF without a newline still yields the typed answer.
	got, err := readConfirmLine(strings.NewReader("y"))
	if err != nil || got != "y" {
		t.Fatalf("EOF answer: got %q, %v", got, err)
	}
}

func TestConfirmed(t *testing.T) {
	for _, answer := range []string{"y", "yes"} {
		if !confirmed(answer) {
			t.Fatalf("%q must confirm", answer)
		}
	}
	for _, answer := range []string{"", "n", "no", "yeah", "true", "1"} {
		if confirmed(answer) {
			t.Fatalf("%q must not confirm", answer)
		}
	}
}
