package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/exitcode"
	"github.com/lidessen/keyref/cli/internal/secret"
	"github.com/lidessen/keyref/cli/internal/source"
	"github.com/lidessen/keyref/cli/local"
)

const importEnvUsage = `usage: keyref import-env --file PATH --map NAME=REF [--map NAME=REF ...] [--source NAME]

Import selected variables from a regular file into a local vault. Each --map
names one variable and its distinct ref. The whole file is validated before
any entry is written; shell code and expansion are never executed. See the
CLI documentation for the supported assignment and quoting syntax.
`

func cmdImportEnv(args []string) int {
	fs := flag.NewFlagSet("import-env", flag.ContinueOnError)
	// flag's default error messages quote invalid argument contents. They may
	// contain input the caller supplied by mistake, so never forward them.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	filePath := fs.String("file", "", "input file")
	sourceName := fs.String("source", "", "local source")
	var mappingArgs stringList
	fs.Var(&mappingArgs, "map", "NAME=REF mapping (repeatable)")
	rest, err := parseArgs(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(os.Stdout, importEnvUsage)
		return 0
	}
	if err != nil || *filePath == "" || len(rest) != 0 {
		return fatalf(2, "import-env: INVALID_ARGUMENTS")
	}
	mappings, err := parseImportEnvMappings(mappingArgs)
	if err != nil {
		return fatalf(2, "import-env: %s", err)
	}
	data, err := readImportEnvFile(*filePath)
	if err != nil {
		return fatalf(1, "import-env: %s", err)
	}
	defer secret.Wipe(data)
	parsed, err := parseImportEnv(data, mappings)
	if err != nil {
		return importEnvDiagnostic(2, err.Error(), parsed)
	}
	// Names, refs and statuses are intentionally public, but a value can
	// coincidentally equal one of them. Check every possible success line
	// before changing the vault, including values on unselected lines.
	if importEnvOutputConflicts(parsed) {
		return importEnvDiagnostic(2, "OUTPUT_CONFLICT", parsed)
	}

	p, err := config.Resolve()
	if err != nil {
		return importEnvDiagnostic(1, "SOURCE_ERROR", parsed)
	}
	spec, err := resolveSource(p, *sourceName)
	if err != nil {
		return importEnvDiagnostic(1, "SOURCE_ERROR", parsed)
	}
	if spec.Kind != source.KindLocal {
		return importEnvDiagnostic(2, "SOURCE_READ_ONLY", parsed)
	}
	vault, err := openLocal(p, spec)
	if errors.Is(err, errLocalLocked) {
		return importEnvDiagnostic(exitcode.SessionLocked, "SOURCE_LOCKED", parsed)
	}
	if err != nil {
		return importEnvDiagnostic(1, "SOURCE_ERROR", parsed)
	}
	defer vault.Close()
	items := make([]local.ImportItem, len(parsed.entries))
	for i, entry := range parsed.entries {
		items[i] = local.ImportItem{Ref: entry.ref, Value: entry.value}
	}
	results, err := vault.Import(context.Background(), items)
	if err != nil {
		return importEnvDiagnostic(1, "IMPORT_FAILED", parsed)
	}
	for i, entry := range parsed.entries {
		if _, err := fmt.Fprintf(os.Stdout, "%s\t%s\t%s\n", entry.name, entry.ref, results[i]); err != nil {
			return importEnvDiagnostic(1, "OUTPUT_FAILED", parsed)
		}
	}
	return 0
}

// importEnvDiagnostic never formats a file value. A coincidental overlap with
// a value, or an incomplete value scan, suppresses the diagnostic entirely;
// the nonzero exit code still reports failure.
func importEnvDiagnostic(code int, message string, parsed parsedImportEnv) int {
	line := []byte("keyref: import-env: " + message + "\n")
	if parsed.complete && !importEnvContainsValue(line, parsed.values) {
		_, _ = os.Stderr.Write(line)
	}
	return code
}

func importEnvOutputConflicts(parsed parsedImportEnv) bool {
	var candidates bytes.Buffer
	for _, entry := range parsed.entries {
		for _, status := range []local.ImportStatus{local.ImportCreated, local.ImportReplaced, local.ImportUnchanged} {
			fmt.Fprintf(&candidates, "%s\t%s\t%s\n", entry.name, entry.ref, status)
		}
	}
	return importEnvContainsValue(candidates.Bytes(), parsed.values)
}

func importEnvContainsValue(output []byte, values [][]byte) bool {
	for _, value := range values {
		if len(value) > 0 && bytes.Contains(output, value) {
			return true
		}
	}
	return false
}
