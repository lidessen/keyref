package accountvault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/remote"
	"github.com/lidessen/keyref/server/internal/store"
)

type Vault struct {
	store       *store.Store
	wrappingKey []byte
	github      githubProvider
	allowed     map[int64]bool
	vercel      bool
	oauth       *browserOAuth
}

func Open(ctx context.Context, st *store.Store, encodedKey, clientID, ids string) (*Vault, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 || clientID == "" {
		return nil, errors.New("remote vault requires a 32-byte base64 wrapping key and GitHub client ID")
	}
	allowed, err := allowedIDs(ids)
	if err != nil {
		return nil, err
	}
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS account_vaults (account INTEGER PRIMARY KEY, wrapped_key BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS account_sessions (token_hash BLOB PRIMARY KEY, account INTEGER NOT NULL, expires INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS account_sessions_expiry ON account_sessions (expires)`,
		`CREATE TABLE IF NOT EXISTS account_vault_migrations (name TEXT PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS account_items (account INTEGER NOT NULL, id TEXT NOT NULL, metadata BLOB NOT NULL, value BLOB NOT NULL, PRIMARY KEY (account, id))`,
	} {
		if _, err := st.DB().ExecContext(ctx, query); err != nil {
			return nil, errors.New("could not initialize remote vault storage")
		}
	}
	vault := &Vault{store: st, wrappingKey: key, github: newGitHub(clientID), allowed: allowed}
	if err := vault.migrateCommandPolicy(ctx); err != nil {
		return nil, errors.New("could not migrate account vault metadata")
	}
	return vault, nil
}

// SetVercel enables secure cookies behind the trusted Vercel proxy.
func (v *Vault) SetVercel(enabled bool) { v.vercel = enabled }

func (v *Vault) Handler() http.Handler {
	mux := http.NewServeMux()
	v.registerBrowser(mux)
	mux.HandleFunc("POST /v1/remote/login/device", v.begin)
	mux.HandleFunc("POST /v1/remote/login/poll", v.poll)
	mux.HandleFunc("DELETE /v1/remote/session", v.authorize(v.logout))
	mux.HandleFunc("GET /v1/remote/items", v.authorize(v.list))
	mux.HandleFunc("GET /v1/remote/items/{id}", v.authorize(v.get))
	mux.HandleFunc("PUT /v1/remote/items/{id}", v.authorize(v.put))
	mux.HandleFunc("DELETE /v1/remote/items/{id}", v.authorize(v.remove))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, remote.MaxBody)
		mux.ServeHTTP(w, r)
	})
}

func respond(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func failure(w http.ResponseWriter, status int, code string) {
	respond(w, status, map[string]string{"error": code})
}

func read(r *http.Request, out any) bool {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF
}

func (v *Vault) begin(w http.ResponseWriter, r *http.Request) {
	device, err := v.github.begin(r.Context())
	if err != nil {
		failure(w, 502, "github_unavailable")
		return
	}
	respond(w, 200, device)
}

func (v *Vault) poll(w http.ResponseWriter, r *http.Request) {
	var p remote.Poll
	if !read(r, &p) || len(p.DeviceCode) < 16 || len(p.DeviceCode) > 256 {
		failure(w, 400, "invalid_request")
		return
	}
	account, pending, err := v.github.poll(r.Context(), p.DeviceCode)
	if err != nil {
		failure(w, 502, "github_unavailable")
		return
	}
	if pending != "" {
		failure(w, 409, pending)
		return
	}
	if !v.allowed[account] {
		failure(w, 403, "forbidden")
		return
	}
	session, err := v.issue(r.Context(), account)
	if err != nil {
		failure(w, 500, "internal")
		return
	}
	defer clear(session.VaultKey)
	respond(w, 200, session)
}

func accountKeyAAD(account int64) []byte {
	return []byte("keyref-account-key-v1\x00" + strconv.FormatInt(account, 10))
}

func (v *Vault) unwrapAccountKey(account int64, wrapped []byte) ([]byte, error) {
	return crypto.OpenBlob(v.wrappingKey, accountKeyAAD(account), wrapped)
}

func (v *Vault) accountKey(ctx context.Context, account int64) ([]byte, error) {
	var wrapped []byte
	if err := v.store.DB().QueryRowContext(ctx, "SELECT wrapped_key FROM account_vaults WHERE account = ?", account).Scan(&wrapped); err != nil {
		return nil, err
	}
	return v.unwrapAccountKey(account, wrapped)
}

func (v *Vault) issue(ctx context.Context, account int64) (remote.Session, error) {
	var key [32]byte
	var random [32]byte
	defer clear(key[:])
	defer clear(random[:])
	if _, err := rand.Read(key[:]); err != nil {
		return remote.Session{}, err
	}
	if _, err := rand.Read(random[:]); err != nil {
		return remote.Session{}, err
	}
	token := hex.EncodeToString(random[:])
	digest := sha256.Sum256([]byte(token))
	wrapped, err := crypto.SealBlob(v.wrappingKey, accountKeyAAD(account), key[:])
	if err != nil {
		return remote.Session{}, err
	}
	var active []byte
	now := time.Now()
	err = v.store.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO account_vaults VALUES (?, ?) ON CONFLICT(account) DO NOTHING", account, wrapped); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT wrapped_key FROM account_vaults WHERE account = ?", account).Scan(&wrapped); err != nil {
			return err
		}
		var err error
		active, err = v.unwrapAccountKey(account, wrapped)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM account_sessions WHERE expires <= ?", now.UnixMilli()); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO account_sessions VALUES (?, ?, ?)", digest[:], account, now.Add(12*time.Hour).UnixMilli())
		return err
	})
	if err != nil {
		clear(active)
		return remote.Session{}, err
	}
	return remote.Session{Token: token, VaultKey: active}, nil
}

type accountHandler func(http.ResponseWriter, *http.Request, int64, [32]byte)

func (v *Vault) authorize(handler accountHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		b, err := hex.DecodeString(token)
		if !ok || err != nil || len(b) != 32 {
			failure(w, 401, "unauthorized")
			return
		}
		clear(b)
		digest := sha256.Sum256([]byte(token))
		var account int64
		err = v.store.DB().QueryRowContext(r.Context(), "SELECT account FROM account_sessions WHERE token_hash = ? AND expires > ?", digest[:], time.Now().UnixMilli()).Scan(&account)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !v.allowed[account]) {
			failure(w, 401, "unauthorized")
			return
		}
		if err != nil {
			failure(w, 500, "internal")
			return
		}
		handler(w, r, account, digest)
	}
}

func (v *Vault) logout(w http.ResponseWriter, r *http.Request, _ int64, digest [32]byte) {
	if _, err := v.store.DB().ExecContext(r.Context(), "DELETE FROM account_sessions WHERE token_hash = ?", digest[:]); err != nil {
		failure(w, 500, "internal")
		return
	}
	w.WriteHeader(204)
}

func (v *Vault) list(w http.ResponseWriter, r *http.Request, account int64, _ [32]byte) {
	rows, err := v.store.DB().QueryContext(r.Context(), "SELECT id, metadata FROM account_items WHERE account = ? ORDER BY id", account)
	if err != nil {
		failure(w, 500, "internal")
		return
	}
	defer rows.Close()
	items := make([]remote.Item, 0)
	for rows.Next() {
		var i remote.Item
		if err := rows.Scan(&i.ID, &i.Metadata); err != nil {
			failure(w, 500, "internal")
			return
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		failure(w, 500, "internal")
		return
	}
	respond(w, 200, items)
}

func validID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 32 && id == strings.ToLower(id)
}

func (v *Vault) get(w http.ResponseWriter, r *http.Request, account int64, _ [32]byte) {
	item := remote.Item{ID: r.PathValue("id")}
	if !validID(item.ID) {
		failure(w, 400, "invalid_request")
		return
	}
	var err error
	if r.URL.Query().Get("metadata") == "1" {
		err = v.store.DB().QueryRowContext(r.Context(), "SELECT metadata FROM account_items WHERE account = ? AND id = ?", account, item.ID).Scan(&item.Metadata)
	} else {
		err = v.store.DB().QueryRowContext(r.Context(), "SELECT metadata,value FROM account_items WHERE account = ? AND id = ?", account, item.ID).Scan(&item.Metadata, &item.Value)
	}
	if errors.Is(err, sql.ErrNoRows) {
		failure(w, 404, "not_found")
		return
	}
	if err != nil {
		failure(w, 500, "internal")
		return
	}
	respond(w, 200, item)
}

func (v *Vault) put(w http.ResponseWriter, r *http.Request, account int64, _ [32]byte) {
	var item remote.Item
	id := r.PathValue("id")
	if !validID(id) || !read(r, &item) || item.ID != id || len(item.Metadata) < 28 || len(item.Metadata) > remote.MaxMetadata+28 || len(item.Value) < 29 || len(item.Value) > remote.MaxSecret+28 {
		failure(w, 400, "invalid_request")
		return
	}
	// Older clients can still write items, but cannot restore the retired policy.
	key, err := v.accountKey(r.Context(), account)
	if err != nil {
		failure(w, 500, "internal")
		return
	}
	defer clear(key)
	metadata, _, err := stripCommandPolicy(key, id, item.Metadata)
	if err != nil {
		failure(w, 400, "invalid_request")
		return
	}
	item.Metadata = metadata
	res, err := v.store.DB().ExecContext(r.Context(), `INSERT INTO account_items (account,id,metadata,value)
		SELECT ?,?,?,? WHERE EXISTS (SELECT 1 FROM account_items WHERE account=? AND id=?)
		OR (SELECT COUNT(*) FROM account_items WHERE account=?) < ?
		ON CONFLICT(account,id) DO UPDATE SET metadata=excluded.metadata,value=excluded.value`, account, id, item.Metadata, item.Value, account, id, account, remote.MaxItems)
	if err != nil {
		failure(w, 500, "internal")
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		failure(w, 500, "internal")
		return
	}
	if n == 0 {
		failure(w, 409, "item_limit")
		return
	}
	w.WriteHeader(204)
}

func (v *Vault) remove(w http.ResponseWriter, r *http.Request, account int64, _ [32]byte) {
	id := r.PathValue("id")
	if !validID(id) {
		failure(w, 400, "invalid_request")
		return
	}
	if _, err := v.store.DB().ExecContext(r.Context(), "DELETE FROM account_items WHERE account = ? AND id = ?", account, id); err != nil {
		failure(w, 500, "internal")
		return
	}
	w.WriteHeader(204)
}
