package accountvault

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/remote"
)

//go:embed all:web
var browserAssets embed.FS

const browserSession = "keyref_session"
const browserDevice = "keyref_device"

var browserRef = regexp.MustCompile(`^(?:[a-z]|[a-z][a-z0-9-]{0,62}[a-z0-9])$`)

func (v *Vault) registerBrowser(mux *http.ServeMux) {
	mux.HandleFunc("GET /manage/{$}", v.browserPage)
	mux.HandleFunc("GET /manage/assets/{asset}", v.browserAsset)
	mux.HandleFunc("POST /manage/api/login/device", v.browserBegin)
	mux.HandleFunc("POST /manage/api/login/poll", v.browserPoll)
	mux.HandleFunc("DELETE /manage/api/session", v.browserAuthorized(v.browserLogout))
	mux.HandleFunc("GET /manage/api/items", v.browserAuthorized(v.browserList))
	mux.HandleFunc("POST /manage/api/items", v.browserAuthorized(v.browserCreate))
	mux.HandleFunc("PATCH /manage/api/items/{ref}", v.browserAuthorized(v.browserEdit))
	mux.HandleFunc("DELETE /manage/api/items/{ref}", v.browserAuthorized(v.browserDelete))
}

func browserHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
}

func (v *Vault) browserPage(w http.ResponseWriter, r *http.Request) {
	browserHeaders(w)
	data, err := browserAssets.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "Management UI is not built", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (v *Vault) browserAsset(w http.ResponseWriter, r *http.Request) {
	browserHeaders(w)
	name := r.PathValue("asset")
	var path, contentType string
	switch name {
	case "main.js":
		path, contentType = "web/build/main.js", "text/javascript; charset=utf-8"
	case "styles.css":
		path, contentType = "web/styles.css", "text/css; charset=utf-8"
	case "logo.png":
		path, contentType = "web/logo.png", "image/png"
	default:
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(browserAssets, path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(data)
}

func (v *Vault) cookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/manage/", MaxAge: maxAge,
		Secure: v.vercel || r.TLS != nil, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func browserMutation(r *http.Request) bool {
	if r.Header.Get("X-Keyref-Admin") != "1" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
	}
	return true
}

func (v *Vault) browserBegin(w http.ResponseWriter, r *http.Request) {
	if !browserMutation(r) {
		failure(w, http.StatusForbidden, "forbidden")
		return
	}
	device, err := v.github.begin(r.Context())
	if err != nil {
		failure(w, http.StatusBadGateway, "github_unavailable")
		return
	}
	v.cookie(w, r, browserDevice, device.DeviceCode, device.ExpiresIn)
	respond(w, http.StatusOK, struct {
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}{device.UserCode, device.VerificationURI, device.ExpiresIn, device.Interval})
}

func (v *Vault) browserPoll(w http.ResponseWriter, r *http.Request) {
	if !browserMutation(r) {
		failure(w, http.StatusForbidden, "forbidden")
		return
	}
	device, err := r.Cookie(browserDevice)
	if err != nil || len(device.Value) < 16 || len(device.Value) > 256 {
		failure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	account, pending, err := v.github.poll(r.Context(), device.Value)
	if err != nil {
		failure(w, http.StatusBadGateway, "github_unavailable")
		return
	}
	if pending != "" {
		if pending == "access_denied" || pending == "expired_token" {
			v.cookie(w, r, browserDevice, "", -1)
		}
		failure(w, http.StatusConflict, pending)
		return
	}
	v.cookie(w, r, browserDevice, "", -1)
	if !v.allowed[account] {
		failure(w, http.StatusForbidden, "forbidden")
		return
	}
	session, err := v.issue(r.Context(), account)
	if err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	defer clear(session.VaultKey)
	v.cookie(w, r, browserSession, session.Token, int((12 * time.Hour).Seconds()))
	w.WriteHeader(http.StatusNoContent)
}

type browserAccountHandler func(http.ResponseWriter, *http.Request, int64, [32]byte)

func (v *Vault) browserAuthorized(next browserAccountHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && !browserMutation(r) {
			failure(w, http.StatusForbidden, "forbidden")
			return
		}
		cookie, err := r.Cookie(browserSession)
		if err != nil {
			failure(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		token, err := hex.DecodeString(cookie.Value)
		if err != nil || len(token) != 32 {
			failure(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		clear(token)
		digest := sha256.Sum256([]byte(cookie.Value))
		var account int64
		err = v.store.DB().QueryRowContext(r.Context(), "SELECT account FROM account_sessions WHERE token_hash = ? AND expires > ?", digest[:], time.Now().UnixMilli()).Scan(&account)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !v.allowed[account]) {
			failure(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if err != nil {
			failure(w, http.StatusInternalServerError, "internal")
			return
		}
		next(w, r, account, digest)
	}
}

func (v *Vault) browserKey(r *http.Request, account int64) ([]byte, error) {
	var wrapped []byte
	if err := v.store.DB().QueryRowContext(r.Context(), "SELECT wrapped_key FROM account_vaults WHERE account = ?", account).Scan(&wrapped); err != nil {
		return nil, err
	}
	return crypto.OpenBlob(v.wrappingKey, []byte("keyref-account-key-v1\x00"+strconv.FormatInt(account, 10)), wrapped)
}

func (v *Vault) browserLogout(w http.ResponseWriter, r *http.Request, _ int64, digest [32]byte) {
	if _, err := v.store.DB().ExecContext(r.Context(), "DELETE FROM account_sessions WHERE token_hash = ?", digest[:]); err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	v.cookie(w, r, browserSession, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func decodeBrowserMetadata(key []byte, id string, blob []byte) (remote.Metadata, error) {
	cipherKey := remote.CipherKey(key)
	defer clear(cipherKey)
	raw, err := crypto.OpenBlob(cipherKey, remote.ItemAAD(id, "meta"), blob)
	if err != nil {
		return remote.Metadata{}, err
	}
	defer clear(raw)
	var meta remote.Metadata
	if json.Unmarshal(raw, &meta) != nil || !browserRef.MatchString(meta.Ref) || remote.ItemID(key, meta.Ref) != id {
		return remote.Metadata{}, errors.New("invalid metadata")
	}
	return meta, nil
}

func (v *Vault) browserList(w http.ResponseWriter, r *http.Request, account int64, _ [32]byte) {
	key, err := v.browserKey(r, account)
	if err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	defer clear(key)
	rows, err := v.store.DB().QueryContext(r.Context(), "SELECT id, metadata FROM account_items WHERE account = ?", account)
	if err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	defer rows.Close()
	entries := make([]remote.Metadata, 0)
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			failure(w, http.StatusInternalServerError, "internal")
			return
		}
		entry, err := decodeBrowserMetadata(key, id, blob)
		if err != nil {
			failure(w, http.StatusInternalServerError, "internal")
			return
		}
		entries = append(entries, entry)
	}
	if rows.Err() != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Ref < entries[j].Ref })
	respond(w, http.StatusOK, entries)
}

type browserWrite struct {
	Ref           string   `json:"ref"`
	Description   string   `json:"description"`
	AllowCommands []string `json:"allow_commands"`
	Value         string   `json:"value"`
}

func (v *Vault) browserCreate(w http.ResponseWriter, r *http.Request, account int64, _ [32]byte) {
	v.browserPut(w, r, account, true)
}

func (v *Vault) browserEdit(w http.ResponseWriter, r *http.Request, account int64, _ [32]byte) {
	v.browserPut(w, r, account, false)
}

func (v *Vault) browserPut(w http.ResponseWriter, r *http.Request, account int64, create bool) {
	var input browserWrite
	if !read(r, &input) || !browserRef.MatchString(input.Ref) || (!create && input.Ref != r.PathValue("ref")) || len(input.Value) > remote.MaxSecret || (create && len(input.Value) == 0) {
		failure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	for _, command := range input.AllowCommands {
		if command == "" || strings.ContainsRune(command, 0) {
			failure(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	key, err := v.browserKey(r, account)
	if err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	defer clear(key)
	id := remote.ItemID(key, input.Ref)
	cipherKey := remote.CipherKey(key)
	defer clear(cipherKey)
	meta := remote.Metadata{Ref: input.Ref, Description: input.Description, AllowCommands: input.AllowCommands}
	var oldMeta, oldValue []byte
	if !create {
		err := v.store.DB().QueryRowContext(r.Context(), "SELECT metadata, value FROM account_items WHERE account=? AND id=?", account, id).Scan(&oldMeta, &oldValue)
		if errors.Is(err, sql.ErrNoRows) {
			failure(w, http.StatusNotFound, "not_found")
			return
		}
		if err != nil {
			failure(w, http.StatusInternalServerError, "internal")
			return
		}
		old, err := decodeBrowserMetadata(key, id, oldMeta)
		if err != nil {
			failure(w, http.StatusInternalServerError, "internal")
			return
		}
		meta.Mask, meta.Size = old.Mask, old.Size
	}
	value := []byte(input.Value)
	defer clear(value)
	var sealedValue []byte
	if len(value) > 0 {
		meta.Mask, meta.Size = "***", len(value)
		sealedValue, err = crypto.SealBlob(cipherKey, remote.ItemAAD(id, "value"), value)
		if err != nil {
			failure(w, http.StatusInternalServerError, "internal")
			return
		}
	} else {
		sealedValue = oldValue
	}
	raw, err := json.Marshal(meta)
	if err != nil || len(raw) > remote.MaxMetadata {
		failure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(raw)
	sealedMeta, err := crypto.SealBlob(cipherKey, remote.ItemAAD(id, "meta"), raw)
	if err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	var res sql.Result
	if create {
		res, err = v.store.DB().ExecContext(r.Context(), `INSERT INTO account_items(account,id,metadata,value)
			SELECT ?,?,?,? WHERE (SELECT COUNT(*) FROM account_items WHERE account=?) < ?
			ON CONFLICT(account,id) DO NOTHING`, account, id, sealedMeta, sealedValue, account, remote.MaxItems)
	} else {
		res, err = v.store.DB().ExecContext(r.Context(), "UPDATE account_items SET metadata=?, value=? WHERE account=? AND id=? AND metadata=? AND value=?", sealedMeta, sealedValue, account, id, oldMeta, oldValue)
	}
	if err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	if n, err := res.RowsAffected(); err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	} else if n != 1 {
		failure(w, http.StatusConflict, "conflict")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (v *Vault) browserDelete(w http.ResponseWriter, r *http.Request, account int64, _ [32]byte) {
	ref := r.PathValue("ref")
	if !browserRef.MatchString(ref) {
		failure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	key, err := v.browserKey(r, account)
	if err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	defer clear(key)
	res, err := v.store.DB().ExecContext(r.Context(), "DELETE FROM account_items WHERE account=? AND id=?", account, remote.ItemID(key, ref))
	if err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		failure(w, http.StatusInternalServerError, "internal")
		return
	}
	if n == 0 {
		failure(w, http.StatusNotFound, "not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
