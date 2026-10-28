package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/cli/local"
)

func TestLocalCLILifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault.db")
	key := bytes.Repeat([]byte{0x91}, 32)
	lookup := func(name string) (string, bool) {
		if name != "SYNTHETIC_LOCAL_MASTER" {
			return "", false
		}
		return base64.StdEncoding.EncodeToString(key), true
	}
	args := func(command string, refs ...string) []string {
		return append([]string{command, "--vault", path, "--master-env", "SYNTHETIC_LOCAL_MASTER"}, refs...)
	}
	var diagnostics bytes.Buffer
	if got := runLocal(ctx, args("init"), strings.NewReader(""), &diagnostics, lookup); got != 0 {
		t.Fatalf("init: %d %s", got, diagnostics.String())
	}
	value := []byte("synthetic-secret\nwith-final-newline\n")
	if got := runLocal(ctx, args("set", "test-ref"), bytes.NewReader(value), &diagnostics, lookup); got != 0 {
		t.Fatalf("set: %d %s", got, diagnostics.String())
	}
	store, err := local.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	err = store.Use(ctx, "test-ref", func(v []byte) error {
		if !bytes.Equal(v, value) {
			return errors.New("input bytes did not round trip")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if got := runLocal(ctx, args("delete", "test-ref"), strings.NewReader(""), &diagnostics, lookup); got != 0 {
		t.Fatalf("delete: %d %s", got, diagnostics.String())
	}
	store, err = local.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if !errors.Is(store.Use(ctx, "test-ref", func([]byte) error { return nil }), local.ErrNotFound) {
		t.Fatal("entry remained after delete")
	}
	if diagnostics.Len() != 0 {
		t.Fatal("success emitted diagnostics")
	}
}

type failingLocalInput struct{}

func (failingLocalInput) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestLocalCLIRejectsInvalidInputWithoutDisclosingIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault.db")
	key := bytes.Repeat([]byte{0x42}, 32)
	lookup := func(string) (string, bool) { return base64.StdEncoding.EncodeToString(key), true }
	base := []string{"init", "--vault", path, "--master-env", "SYNTHETIC_LOCAL_MASTER"}
	var out bytes.Buffer
	missing := func(string) (string, bool) { return "", false }
	if runLocal(context.Background(), base, strings.NewReader(""), &out, missing) == 0 {
		t.Fatal("missing key accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing key touched vault")
	}
	out.Reset()
	if runLocal(context.Background(), base, strings.NewReader(""), &out, lookup) != 0 {
		t.Fatal("init failed")
	}
	if runLocal(context.Background(), base, strings.NewReader(""), &out, lookup) == 0 {
		t.Fatal("existing vault overwritten")
	}
	set := []string{"set", "--vault", path, "--master-env", "SYNTHETIC_LOCAL_MASTER", "test-ref"}
	for _, reader := range []io.Reader{strings.NewReader(""), strings.NewReader(strings.Repeat("x", maxLocalSecretBytes+1)), failingLocalInput{}} {
		if runLocal(context.Background(), set, reader, &out, lookup) == 0 {
			t.Fatal("invalid input accepted")
		}
	}
	secretCanary := "synthetic-secret-never-log"
	if runLocal(context.Background(), []string{"set", "--" + secretCanary}, strings.NewReader(secretCanary), &out, lookup) == 0 {
		t.Fatal("invalid option accepted")
	}
	if strings.Contains(out.String(), secretCanary) || strings.Contains(out.String(), base64.StdEncoding.EncodeToString(key)) {
		t.Fatal("diagnostics exposed synthetic secret")
	}
}

// Run a fresh process so the flag dispatch, environment and standard input
// are exercised without inheriting any actual parent secrets.
func TestLocalCLISubprocess(t *testing.T) {
	if os.Getenv("KEYREF_LOCAL_TEST_CHILD") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Exit(dispatch("local", os.Args[i+1:]))
			}
		}
		os.Exit(2)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault.db")
	key := bytes.Repeat([]byte{0x63}, 32)
	master := base64.StdEncoding.EncodeToString(key)
	run := func(command, input string, refs ...string) {
		args := append([]string{"-test.run=^TestLocalCLISubprocess$", "--", command, "--vault", path, "--master-env", "LOCAL_TEST_MASTER"}, refs...)
		child := exec.Command(os.Args[0], args...)
		child.Env = []string{"PATH=/usr/bin:/bin", "KEYREF_LOCAL_TEST_CHILD=1", "LOCAL_TEST_MASTER=" + master}
		child.Stdin = strings.NewReader(input)
		out, err := child.CombinedOutput()
		if err != nil || len(out) != 0 {
			t.Fatalf("local %s failed or produced output: %v", command, err)
		}
	}
	run("init", "")
	run("set", "synthetic-child-value", "child-ref")
	s, err := local.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Use(context.Background(), "child-ref", func(value []byte) error {
		if string(value) != "synthetic-child-value" {
			return errors.New("wrong value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	run("delete", "", "child-ref")
}
