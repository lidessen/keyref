package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/lidessen/keyref/cli/internal/secret"
)

func TestImportEnvMappings(t *testing.T) {
	valid, err := parseImportEnvMappings([]string{"FIRST_TOKEN=first-token", "second_token=second-token"})
	if err != nil || len(valid) != 2 || valid[0].name != "FIRST_TOKEN" || valid[1].ref != "second-token" {
		t.Fatal("valid explicit mappings were rejected")
	}
	for _, tc := range []struct {
		name string
		args []string
		code string
	}{
		{"none", nil, "INVALID_MAPPING_COUNT"},
		{"invalid name", []string{"2TOKEN=token"}, "INVALID_MAPPING"},
		{"invalid ref", []string{"TOKEN=TOKEN"}, "INVALID_MAPPING"},
		{"missing equals", []string{"TOKEN"}, "INVALID_MAPPING"},
		{"extra equals", []string{"TOKEN=tok=extra"}, "INVALID_MAPPING"},
		{"duplicate name", []string{"TOKEN=first", "TOKEN=second"}, "DUPLICATE_MAPPING"},
		{"duplicate ref", []string{"TOKEN=first", "OTHER=first"}, "DUPLICATE_MAPPING"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseImportEnvMappings(tc.args)
			if err == nil || err.Error() != tc.code {
				t.Fatal("invalid mappings did not produce the expected safe error code")
			}
		})
	}
}

func TestImportEnvParseSelectedValues(t *testing.T) {
	first, second, third := rand.Text(), rand.Text(), rand.Text()
	data := []byte("# ignored\r\n\texport FIRST=" + first + " # comment\r\n" +
		"UNSELECTED=\r\nSECOND='" + second + " $HOME $(literal)'\r\n" +
		"THIRD=\"" + third + `\"\\\$` + "\" # comment\r\n")
	defer secret.Wipe(data)
	mappings, err := parseImportEnvMappings([]string{"THIRD=third", "FIRST=first", "SECOND=second"})
	if err != nil {
		t.Fatal("valid mappings were rejected")
	}
	parsed, err := parseImportEnv(data, mappings)
	if err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	entries := parsed.entries
	if len(entries) != 3 || entries[0].name != "THIRD" || entries[0].ref != "third" ||
		!bytes.Equal(entries[0].value, []byte(third+`"\$`)) ||
		!bytes.Equal(entries[1].value, []byte(first)) ||
		!bytes.Equal(entries[2].value, []byte(second+" $HOME $(literal)")) {
		t.Fatal("selected values, escapes or mapping order were not preserved")
	}
}

func TestImportEnvLineEndings(t *testing.T) {
	value := rand.Text()
	mappings, err := parseImportEnvMappings([]string{"TOKEN=token"})
	if err != nil {
		t.Fatal("valid mapping was rejected")
	}
	for _, tc := range []struct {
		name   string
		input  string
		wantOK bool
	}{
		{"lf", "TOKEN=" + value + "\n", true},
		{"crlf", "TOKEN=" + value + "\r\n", true},
		{"no final newline", "TOKEN=" + value, true},
		{"bare final carriage return", "TOKEN=" + value + "\r", false},
		{"unselected bare final carriage return", "TOKEN=" + value + "\nOTHER='literal'\r", false},
		{"double carriage return", "TOKEN=" + value + "\r\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.input)
			defer secret.Wipe(data)
			parsed, err := parseImportEnv(data, mappings)
			if tc.wantOK {
				if err != nil || !parsed.complete || !bytes.Equal(parsed.entries[0].value, []byte(value)) {
					t.Fatal("valid line ending did not preserve the selected value")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "INVALID_SYNTAX") || parsed.complete {
				t.Fatal("bare carriage return was not rejected safely")
			}
		})
	}
}

func TestImportEnvRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	value := rand.Text()
	cases := []struct {
		name string
		data string
		want string
	}{
		{"unselected bad line", "TOKEN=" + value + "\ninvalid line\n", "line 2: INVALID_ASSIGNMENT"},
		{"duplicate", "TOKEN=" + value + "\nTOKEN=" + value + "\n", "line 2: DUPLICATE_VARIABLE"},
		{"empty selected", "TOKEN=''\n", "line 1: INVALID_VALUE_SIZE"},
		{"missing selected", "OTHER=" + value + "\n", "MISSING_VARIABLE"},
		{"unterminated single quote", "TOKEN='" + value + "\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"unterminated double quote", "TOKEN=\"" + value + "\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"variable expansion", "TOKEN=" + value + "$HOME\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"command substitution", "TOKEN=" + value + "$(true)\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"backticks", "TOKEN=\"" + value + "`true`\"\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"process substitution", "TOKEN=" + value + "<(true)\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"shell command", "TOKEN=" + value + ";true\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"multiple words", "TOKEN=" + value + " trailing\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"multiple fragments", "TOKEN='" + value + "'suffix\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"unsupported escape", "TOKEN=\"" + value + `\n` + "\"\n", "line 1: INVALID_VALUE_SYNTAX"},
		{"nul", "TOKEN=" + value + "\x00\n", "line 1: INVALID_SYNTAX"},
		{"embedded carriage return", "TOKEN=" + value + "\rmore\n", "line 1: INVALID_SYNTAX"},
	}
	mappings, err := parseImportEnvMappings([]string{"TOKEN=token"})
	if err != nil {
		t.Fatal("valid mapping was rejected")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.data)
			defer secret.Wipe(data)
			_, err := parseImportEnv(data, mappings)
			if err == nil || err.Error() != tc.want || strings.Contains(err.Error(), value) {
				t.Fatal("input did not produce the expected safe error code")
			}
		})
	}
}

func TestImportEnvInvalidQuotedValueDoesNotMutateInput(t *testing.T) {
	value := rand.Text()
	for _, suffix := range []string{`$BAD"`, `\n"`, `"suffix`, ``} {
		input := []byte(`"` + value + `\"` + suffix)
		original := bytes.Clone(input)
		defer secret.Wipe(input)
		defer secret.Wipe(original)
		if _, ok := parseImportEnvValue(input); ok || !bytes.Equal(input, original) {
			t.Fatal("invalid quoted input was accepted or changed")
		}
	}
}

func TestImportEnvAssignmentLimit(t *testing.T) {
	value := rand.Text()
	var input strings.Builder
	for i := 0; i <= maxImportEnvAssignments; i++ {
		fmt.Fprintf(&input, "NAME_%d=%s\n", i, value)
	}
	data := []byte(input.String())
	defer secret.Wipe(data)
	mappings, err := parseImportEnvMappings([]string{"NAME_0=first"})
	if err != nil {
		t.Fatal("valid mapping was rejected")
	}
	_, err = parseImportEnv(data, mappings)
	if err == nil || !strings.Contains(err.Error(), "TOO_MANY_ASSIGNMENTS") || strings.Contains(err.Error(), value) {
		t.Fatal("assignment limit did not return a safe error")
	}
}

func TestReadImportEnvFileIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.env")
	value := []byte(rand.Text())
	defer secret.Wipe(value)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal("could not create synthetic input")
	}
	got, err := readImportEnvFile(path)
	if err != nil || !bytes.Equal(got, value) {
		t.Fatal("could not read the synthetic file")
	}
	secret.Wipe(got)
	if err := os.Truncate(path, maxImportEnvFileBytes+1); err != nil {
		t.Fatal("could not resize the synthetic file")
	}
	if _, err := readImportEnvFile(path); err == nil || err.Error() != "FILE_TOO_LARGE" {
		t.Fatal("oversized file was not rejected")
	}
	if _, err := readImportEnvFile(filepath.Join(path, rand.Text())); err == nil || err.Error() != "FILE_READ_FAILED" {
		t.Fatal("unreadable file did not return a safe error")
	}
	fifo := filepath.Join(t.TempDir(), "input.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal("could not create a synthetic FIFO")
	}
	if _, err := readImportEnvFile(fifo); err == nil || err.Error() != "FILE_READ_FAILED" {
		t.Fatal("non-regular input was not rejected")
	}
}
