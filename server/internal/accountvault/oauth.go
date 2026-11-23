package accountvault

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const OAuthCallbackPath = "/manage/api/login/github/callback"

type browserOAuth struct {
	secret   string
	callback *url.URL
}

func (v *Vault) ConfigureBrowserOAuth(secret, callback string) error {
	if secret == "" && callback == "" {
		return nil
	}
	u, err := url.Parse(callback)
	if secret == "" || err != nil || u == nil || u.Path != OAuthCallbackPath || u.RawPath != "" ||
		u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		return errors.New("configure a GitHub client secret and an HTTPS browser callback URL (HTTP allowed on loopback)")
	}
	v.oauth = &browserOAuth{secret: secret, callback: u}
	return nil
}

func (v *Vault) oauthCookie(w http.ResponseWriter, value string, age int) string {
	name := "keyref_oauth"
	secure := v.oauth.callback.Scheme == "https"
	if secure {
		name = "__Host-keyref_oauth"
	}
	if w != nil {
		http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: age, Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	return name
}

func (v *Vault) oauthMatchesOrigin(r *http.Request) bool {
	return v.oauth != nil && r.Host == v.oauth.callback.Host &&
		(v.oauth.callback.Scheme == "http" || v.vercel || r.TLS != nil)
}

func (v *Vault) oauthStart(w http.ResponseWriter, r *http.Request) {
	if v.oauth == nil {
		failure(w, http.StatusServiceUnavailable, "github_oauth_unconfigured")
		return
	}
	if !browserMutation(r) || !v.oauthMatchesOrigin(r) {
		failure(w, http.StatusForbidden, "forbidden")
		return
	}
	state := base64.RawURLEncoding.EncodeToString(randomOAuthBytes())
	verifier := base64.RawURLEncoding.EncodeToString(randomOAuthBytes())
	challenge := sha256.Sum256([]byte(verifier))
	v.oauthCookie(w, state+"."+verifier, 600)
	params := url.Values{
		"client_id": {v.github.clientID}, "redirect_uri": {v.oauth.callback.String()}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"},
	}
	respond(w, http.StatusOK, map[string]string{"authorization_url": v.github.loginURL + "/login/oauth/authorize?" + params.Encode()})
}

func randomOAuthBytes() []byte {
	data := make([]byte, 32)
	// crypto/rand.Read always fills the buffer.
	_, _ = rand.Read(data)
	return data
}

func (v *Vault) oauthCallback(w http.ResponseWriter, r *http.Request) {
	browserHeaders(w)
	if !v.oauthMatchesOrigin(r) {
		failure(w, http.StatusForbidden, "forbidden")
		return
	}
	failed := func(status string) {
		http.Redirect(w, r, "/manage/?login="+status, http.StatusSeeOther)
	}
	cookie, err := r.Cookie(v.oauthCookie(nil, "", 0))
	v.oauthCookie(w, "", -1)
	if err != nil {
		failed("failed")
		return
	}
	state, verifier, valid := strings.Cut(cookie.Value, ".")
	query := r.URL.Query()
	if !valid || len(state) != 43 || len(verifier) != 43 || len(query["state"]) != 1 ||
		subtle.ConstantTimeCompare([]byte(state), []byte(query.Get("state"))) != 1 {
		failed("failed")
		return
	}
	if query.Get("error") == "access_denied" {
		failed("cancelled")
		return
	}
	code := query.Get("code")
	if len(query["code"]) != 1 || code == "" || len(code) > 512 || query.Has("error") {
		failed("failed")
		return
	}
	var token struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	form := url.Values{"client_id": {v.github.clientID}, "client_secret": {v.oauth.secret},
		"redirect_uri": {v.oauth.callback.String()}, "code": {code}, "code_verifier": {verifier}}
	if err := v.github.request(r.Context(), http.MethodPost, v.github.loginURL+"/login/oauth/access_token", "", form, &token); err != nil || token.AccessToken == "" || token.Error != "" {
		failed("failed")
		return
	}
	account, err := v.github.userID(r.Context(), token.AccessToken)
	if err != nil {
		failed("failed")
		return
	}
	if !v.allowed[account] {
		failed("forbidden")
		return
	}
	session, err := v.issue(r.Context(), account)
	if err != nil {
		failed("failed")
		return
	}
	clear(session.VaultKey)
	v.cookie(w, r, browserSession, session.Token, int((12 * time.Hour).Seconds()))
	http.Redirect(w, r, "/manage/", http.StatusSeeOther)
}
