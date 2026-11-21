package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/lidessen/keyref/lib/local"
	"github.com/lidessen/keyref/lib/secret"
)

const (
	maxImportEnvFileBytes   = 16 << 20
	maxImportEnvMappings    = 256
	maxImportEnvAssignments = 10000
	maxImportEnvNameBytes   = 256
)

// importEnvError contains only a fixed error code and, for a file error,
// the line number. It must never retain or format an input line or value.
type importEnvError struct {
	line int
	code string
}

func (e *importEnvError) Error() string {
	if e.line > 0 {
		return fmt.Sprintf("line %d: %s", e.line, e.code)
	}
	return e.code
}

type importEnvMapping struct {
	name string
	ref  string
}

type importEnvEntry struct {
	importEnvMapping
	value []byte
}

type parsedImportEnv struct {
	entries  []importEnvEntry
	values   [][]byte
	complete bool
}

// parseImportEnvMappings requires explicit, unique names and refs. No
// normalization is performed, so two names cannot silently target one ref.
func parseImportEnvMappings(args []string) ([]importEnvMapping, error) {
	if len(args) == 0 || len(args) > maxImportEnvMappings {
		return nil, &importEnvError{code: "INVALID_MAPPING_COUNT"}
	}
	byName := make(map[string]bool, len(args))
	byRef := make(map[string]bool, len(args))
	result := make([]importEnvMapping, 0, len(args))
	for _, arg := range args {
		name, ref, ok := strings.Cut(arg, "=")
		if !ok || !validImportEnvName([]byte(name)) || !local.ValidRef(ref) {
			return nil, &importEnvError{code: "INVALID_MAPPING"}
		}
		if byName[name] || byRef[ref] {
			return nil, &importEnvError{code: "DUPLICATE_MAPPING"}
		}
		byName[name], byRef[ref] = true, true
		result = append(result, importEnvMapping{name: name, ref: ref})
	}
	return result, nil
}

func validImportEnvName(name []byte) bool {
	if len(name) == 0 || len(name) > maxImportEnvNameBytes {
		return false
	}
	for i, c := range name {
		if c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

// readImportEnvFile reads only a bounded regular file. The caller must wipe
// the returned bytes after the import, including on every error path. It
// rejects a byte count that differs from the initial file size.
func readImportEnvFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, &importEnvError{code: "FILE_READ_FAILED"}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, &importEnvError{code: "FILE_READ_FAILED"}
	}
	if info.Size() > maxImportEnvFileBytes {
		return nil, &importEnvError{code: "FILE_TOO_LARGE"}
	}
	data := make([]byte, int(info.Size())+1)
	n, readErr := io.ReadFull(f, data)
	if n != int(info.Size()) || !(errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF)) {
		secret.Wipe(data)
		return nil, &importEnvError{code: "FILE_READ_FAILED"}
	}
	return data[:n], nil
}

// parseImportEnv validates the entire file, even lines that were not
// selected. It collects valid values for the output collision check, including
// values after a malformed line. Values alias data; decoding a quoted value
// may change data in place. The caller wipes data after its last use.
func parseImportEnv(data []byte, mappings []importEnvMapping) (parsedImportEnv, error) {
	selected := make(map[string]int, len(mappings))
	parsed := parsedImportEnv{entries: make([]importEnvEntry, len(mappings)), complete: true}
	for i, mapping := range mappings {
		selected[mapping.name] = i
		parsed.entries[i].importEnvMapping = mapping
	}
	seen := make(map[string]bool)
	var firstErr error
	fail := func(line int, code string) {
		if firstErr == nil {
			firstErr = &importEnvError{line: line, code: code}
		}
	}
	lineNo, assignments := 0, 0
	for len(data) > 0 {
		lineNo++
		line := data
		if end := bytes.IndexByte(data, '\n'); end >= 0 {
			line, data = data[:end], data[end+1:]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
		} else {
			data = nil
		}
		if bytes.IndexByte(line, 0) >= 0 || bytes.IndexByte(line, '\r') >= 0 {
			fail(lineNo, "INVALID_SYNTAX")
			parsed.complete = false
			continue
		}
		line = trimImportEnvSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if bytes.HasPrefix(line, []byte("export")) && len(line) > len("export") && isImportEnvSpace(line[len("export")]) {
			line = trimImportEnvSpace(line[len("export"):])
		}
		eq := bytes.IndexByte(line, '=')
		if eq < 0 {
			fail(lineNo, "INVALID_ASSIGNMENT")
			continue
		}
		assignments++
		if assignments > maxImportEnvAssignments {
			fail(lineNo, "TOO_MANY_ASSIGNMENTS")
			parsed.complete = false
			break
		}
		validName := validImportEnvName(line[:eq])
		if !validName {
			fail(lineNo, "INVALID_ASSIGNMENT")
		}
		var name string
		duplicate := false
		if validName {
			name = string(line[:eq])
			duplicate = seen[name]
			if duplicate {
				fail(lineNo, "DUPLICATE_VARIABLE")
			}
			seen[name] = true
		}
		value, ok := parseImportEnvValue(line[eq+1:])
		if !ok {
			fail(lineNo, "INVALID_VALUE_SYNTAX")
			// An invalid value has no unambiguous decoded form to compare
			// with diagnostics. Suppress those diagnostics rather than
			// risk displaying bytes from the malformed assignment.
			parsed.complete = false
			continue
		}
		if len(value) > 0 {
			parsed.values = append(parsed.values, value)
		}
		if index, ok := selected[name]; ok && validName && !duplicate {
			if len(value) == 0 || len(value) > maxLocalSecretBytes {
				fail(lineNo, "INVALID_VALUE_SIZE")
			} else {
				parsed.entries[index].value = value
			}
		}
	}
	if firstErr != nil {
		return parsed, firstErr
	}
	for _, entry := range parsed.entries {
		if entry.value == nil {
			return parsed, &importEnvError{code: "MISSING_VARIABLE"}
		}
	}
	return parsed, nil
}

func isImportEnvSpace(c byte) bool { return c == ' ' || c == '\t' }

func trimImportEnvSpace(b []byte) []byte {
	for len(b) > 0 && isImportEnvSpace(b[0]) {
		b = b[1:]
	}
	return b
}

// A value is one unquoted token or one complete quoted token. Unquoted shell
// metacharacters and unescaped substitutions in double quotes are rejected.
// Single quotes and supported double-quote escapes preserve literal bytes;
// no shell, substitution, interpolation or command is ever run.
func parseImportEnvValue(input []byte) ([]byte, bool) {
	if len(input) == 0 {
		return input, true
	}
	if input[0] == '\'' {
		end := bytes.IndexByte(input[1:], '\'')
		if end < 0 {
			return nil, false
		}
		end++
		return input[1:end], validImportEnvTail(input[end+1:])
	}
	if input[0] == '"' {
		for i := 1; i < len(input); i++ {
			switch input[i] {
			case '"':
				if !validImportEnvTail(input[i+1:]) {
					return nil, false
				}
				// Validate the whole token before decoding into the input.
				// A rejected token must retain its original bytes.
				value := input[1:1]
				for j := 1; j < i; j++ {
					if input[j] == '\\' {
						j++
					}
					value = append(value, input[j])
				}
				return value, true
			case '$', '`':
				return nil, false
			case '\\':
				i++
				if i >= len(input) || !bytes.ContainsRune([]byte(`\"$`+"`"), rune(input[i])) {
					return nil, false
				}
			}
		}
		return nil, false
	}
	for i, c := range input {
		if isImportEnvSpace(c) {
			return input[:i], validImportEnvTail(input[i:])
		}
		if bytes.ContainsRune([]byte("$`\\'\";&|<>()"), rune(c)) {
			return nil, false
		}
	}
	return input, true
}

func validImportEnvTail(tail []byte) bool {
	if len(tail) == 0 {
		return true
	}
	if !isImportEnvSpace(tail[0]) {
		return false
	}
	tail = trimImportEnvSpace(tail)
	return len(tail) == 0 || tail[0] == '#'
}
