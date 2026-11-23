package store

import (
	"os"
	"testing"
)

func TestRemoteStateLibSQL(t *testing.T) {
	dsn := os.Getenv("KEYREF_TEST_LIBSQL_DSN")
	if dsn == "" {
		t.Skip("set KEYREF_TEST_LIBSQL_DSN to a disposable libSQL database")
	}
	testRemoteState(t, "libsql", dsn)
}
