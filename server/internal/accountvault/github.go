package accountvault

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lidessen/keyref/proto/remote"
)

type githubProvider struct {
	clientID string
	client   *http.Client
	loginURL string
	apiURL   string
}

func (g githubProvider) request(ctx context.Context, method, endpoint, token string, values url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("GitHub returned a non-success status")
	}
	return json.NewDecoder(io.LimitReader(res.Body, 16<<10)).Decode(out)
}

func (g githubProvider) begin(ctx context.Context) (remote.Device, error) {
	var d remote.Device
	err := g.request(ctx, http.MethodPost, g.loginURL+"/login/device/code", "", url.Values{"client_id": {g.clientID}}, &d)
	if err == nil && (d.DeviceCode == "" || d.UserCode == "" || d.ExpiresIn < 1 || d.ExpiresIn > 1800 || d.Interval < 1 || d.Interval > 60 || d.VerificationURI != "https://github.com/login/device") {
		err = errors.New("invalid GitHub device response")
	}
	return d, err
}

func (g githubProvider) poll(ctx context.Context, code string) (int64, string, error) {
	var token struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	form := url.Values{"client_id": {g.clientID}, "device_code": {code}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}}
	if err := g.request(ctx, http.MethodPost, g.loginURL+"/login/oauth/access_token", "", form, &token); err != nil {
		return 0, "", err
	}
	switch token.Error {
	case "authorization_pending", "slow_down", "access_denied", "expired_token":
		return 0, token.Error, nil
	case "":
	default:
		return 0, "", errors.New("GitHub device authorization failed")
	}
	if token.AccessToken == "" {
		return 0, "", errors.New("missing GitHub access token")
	}
	var user struct {
		ID int64 `json:"id"`
	}
	if err := g.request(ctx, http.MethodGet, g.apiURL+"/user", token.AccessToken, nil, &user); err != nil {
		return 0, "", err
	}
	if user.ID <= 0 {
		return 0, "", errors.New("invalid GitHub user ID")
	}
	return user.ID, "", nil
}

func newGitHub(clientID string) githubProvider {
	return githubProvider{clientID: clientID, loginURL: "https://github.com", apiURL: "https://api.github.com", client: &http.Client{
		Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func allowedIDs(raw string) (map[int64]bool, error) {
	ids := make(map[int64]bool)
	for _, value := range strings.Split(raw, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.New("invalid KEYREF_REMOTE_GITHUB_IDS")
		}
		ids[id] = true
	}
	return ids, nil
}
