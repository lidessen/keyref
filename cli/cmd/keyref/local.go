package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/lidessen/keyref/cli/store"
)

const maxLocalSecretBytes = 1 << 20

// cmdLocal deliberately prints neither the input nor the key on any path.
// The local vault is independent of the paired and synchronized Keyref vault.
func cmdLocal(args []string) int {
	return runLocal(context.Background(), args, os.Stdin, os.Stderr, os.LookupEnv)
}

func runLocal(ctx context.Context, args []string, input io.Reader, errors io.Writer, lookup func(string) (string, bool)) int {
	fail := func(message string, code int) int { fmt.Fprintln(errors, "keyref local:", message); return code }
	if len(args) == 0 || (args[0] != "init" && args[0] != "set" && args[0] != "delete") {
		return fail("expected init, set or delete", 2)
	}
	command := args[0]
	flags := flag.NewFlagSet("local "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard) // User input is never copied to diagnostics.
	vault := flags.String("vault", "", "")
	masterEnv := flags.String("master-env", "", "")
	if flags.Parse(args[1:]) != nil || *vault == "" || !localEnvName(*masterEnv) || (command == "init" && flags.NArg() != 0) || (command != "init" && flags.NArg() != 1) {
		return fail("expected --vault PATH --master-env NAME and, for set/delete, a ref", 2)
	}
	encoded, present := lookup(*masterEnv)
	if !present || len(encoded) != base64.StdEncoding.EncodedLen(32) {
		return fail("master key unavailable or invalid", 1)
	}
	// Allocate exactly 33 bytes for the padded base64 decoder, then wipe it.
	key := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	defer wipeLocalBytes(key)
	encodedBytes := []byte(encoded)
	defer wipeLocalBytes(encodedBytes)
	n, err := base64.StdEncoding.Strict().Decode(key, encodedBytes)
	if err != nil || n != 32 {
		return fail("master key unavailable or invalid", 1)
	}
	key = key[:n]
	if command == "init" {
		vaultStore, err := store.NewRegistry().Create(store.Options{Config: store.LocalOptions{Path: *vault, Key: key}})
		if err != nil {
			return fail("could not create vault", 1)
		}
		if vaultStore.Close() != nil {
			return fail("could not close vault", 1)
		}
		return 0
	}
	vaultStore, err := store.NewRegistry().Open(store.Options{Config: store.LocalOptions{Path: *vault, Key: key}})
	if err != nil {
		return fail("could not open vault", 1)
	}
	defer vaultStore.Close()
	if command == "delete" {
		if vaultStore.Delete(ctx, flags.Arg(0)) != nil {
			return fail("could not delete entry", 1)
		}
		return 0
	}
	value, err := io.ReadAll(io.LimitReader(input, maxLocalSecretBytes+1))
	defer wipeLocalBytes(value)
	if err != nil || len(value) == 0 || len(value) > maxLocalSecretBytes {
		return fail("input must contain 1 to 1048576 bytes", 1)
	}
	if vaultStore.Put(ctx, flags.Arg(0), value) != nil {
		return fail("could not store entry", 1)
	}
	return 0
}

func localEnvName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for i, c := range name {
		if !(c == '_' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func wipeLocalBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
