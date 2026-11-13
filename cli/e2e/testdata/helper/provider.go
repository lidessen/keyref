package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// providerEnvironmentProbe is a Keyref transport fixture, not Neowind.
// The loopback receiver checks the exact generated key in the auth header.
// Intentional echoes exercise both captured output streams; no value is
// written to disk. The marker proves whether the child was started.
func providerEnvironmentProbe(args []string) int {
	if len(args) != 3 {
		return 31
	}
	endpoint, envName, marker := args[0], args[1], args[2]
	if err := os.WriteFile(marker, []byte("started\n"), 0600); err != nil {
		return 32
	}
	value := os.Getenv(envName)
	if value == "" || os.Getenv("XDG_CONFIG_HOME") == "" || filepath.Dir(marker) != os.Getenv("NEOWIND_STATE_DIR") {
		return 33
	}
	for _, excluded := range []string{"KEYREF_LOCAL_MASTER", "KEYREF_HOME", "KEYREF_KEYRING_DIR", "UNRELATED_PROVIDER_KEY"} {
		if _, exists := os.LookupEnv(excluded); exists {
			return 34
		}
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"probe":true}`))
	if err != nil {
		return 35
	}
	req.Header.Set("Authorization", "Bearer "+value)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 36
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return 37
	}
	fmt.Printf("provider-ok\ncredential=%s\n", value)
	fmt.Fprintf(os.Stderr, "credential-base64=%s\n", base64.StdEncoding.EncodeToString([]byte(value)))
	return 0
}
