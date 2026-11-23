package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"time"

	"github.com/tursodatabase/libsql-client-go/libsql"
)

// OpenTurso opens a dedicated Turso Cloud database.
func OpenTurso(ctx context.Context, endpoint, token string) (*Store, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "libsql" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || token == "" {
		return nil, errors.New("store: Turso requires a libsql URL and an authentication token")
	}
	connector, err := libsql.NewConnector(u.String(), libsql.WithAuthToken(token))
	if err != nil {
		return nil, errors.New("store: cannot configure Turso connection")
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st := &Store{db: db, remote: true}
	if err := st.initRemote(ctx); err != nil {
		db.Close()
		return nil, errors.New("store: cannot initialize Turso database")
	}
	return st, nil
}
