package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/lib/exec"
	"github.com/lidessen/keyref/lib/exitcode"
	"github.com/lidessen/keyref/lib/local"
	"github.com/lidessen/keyref/lib/secret"
	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/remote"
)

const remoteKeyringService = "keyref-remote"

type remoteClient struct {
	origin  string
	http    *http.Client
	session remote.Session
}

type remoteError struct {
	status int
	code   string
}

func (e *remoteError) Error() string { return fmt.Sprintf("remote server returned HTTP %d", e.status) }

func (c *remoteClient) request(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return errors.New("could not encode request")
		}
		defer clear(data)
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+remote.Path+path, body)
	if err != nil {
		return errors.New("invalid remote request")
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.session.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.session.Token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return errors.New("could not reach remote server")
	}
	defer res.Body.Close()
	rd := json.NewDecoder(io.LimitReader(res.Body, remote.MaxBody))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var errorBody struct {
			Error string `json:"error"`
		}
		_ = rd.Decode(&errorBody)
		return &remoteError{res.StatusCode, errorBody.Error}
	}
	if out != nil && rd.Decode(out) != nil {
		return errors.New("invalid remote response")
	}
	return nil
}

func newRemoteClient(p config.Paths) (*remoteClient, error) {
	u, err := url.Parse(config.Origin(p))
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		return nil, errors.New("configure an HTTPS server origin with keyref server set")
	}
	c := &remoteClient{origin: u.Scheme + "://" + strings.ToLower(u.Host), http: &http.Client{
		Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	return c, nil
}

func (c *remoteClient) keyringSlot(p config.Paths) string {
	return c.origin + "|" + filepath.Clean(p.Dir)
}

func (c *remoteClient) loadSession(p config.Paths, ks keyring.SecretStore) error {
	state, err := ks.Get(remoteKeyringService, c.keyringSlot(p))
	if err != nil {
		return err
	}
	rawState := []byte(state)
	err = json.Unmarshal(rawState, &c.session)
	clear(rawState)
	if err != nil || !validRemoteSession(c.session) {
		clear(c.session.VaultKey)
		return errRemoteSession
	}
	return nil
}

var errRemoteSession = errors.New("remote login state is invalid; sign in with keyref remote login")

func remoteSessionError(err error) int {
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		return fatalf(exitcode.SessionLocked, "sign in with keyref remote login")
	case errors.Is(err, errRemoteSession):
		return fatalf(exitcode.SessionLocked, "%v", err)
	default:
		return fatalf(1, "could not access remote login in keyring")
	}
}

func cmdRemote(args []string) int {
	if len(args) == 0 {
		return fatalf(2, "usage: keyref remote <login|logout|list|get|set|delete|exec>")
	}
	p, err := config.Resolve()
	if err != nil {
		return fatalf(1, "could not resolve keyref configuration")
	}
	c, err := newRemoteClient(p)
	if err != nil {
		return fatalf(2, "%v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ks := secretStore()
	slot := c.keyringSlot(p)
	cmd, args := args[0], args[1:]
	if cmd == "login" {
		if len(args) != 0 {
			return fatalf(2, "usage: keyref remote login")
		}
		if err := c.login(ctx, ks, slot); err != nil {
			return fatalf(1, "%v", err)
		}
		fmt.Println("Signed in to remote vault.")
		return 0
	}
	if err := c.loadSession(p, ks); err != nil {
		return remoteSessionError(err)
	}
	defer clear(c.session.VaultKey)
	switch cmd {
	case "logout":
		if len(args) != 0 {
			return fatalf(2, "usage: keyref remote logout")
		}
		err := c.request(ctx, http.MethodDelete, "session", nil, nil)
		var apiErr *remoteError
		if err != nil && !(errors.As(err, &apiErr) && apiErr.status == 401) {
			return remoteFail(err)
		}
		if err := ks.Delete(remoteKeyringService, slot); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return fatalf(1, "could not clear remote login state")
		}
		return 0
	case "list":
		if len(args) != 0 {
			return fatalf(2, "usage: keyref remote list")
		}
		metas, err := c.listMetadata(ctx)
		if err != nil {
			return remoteFail(err)
		}
		sort.Slice(metas, func(i, j int) bool { return metas[i].Ref < metas[j].Ref })
		for _, meta := range metas {
			fmt.Printf("%s\t%s\n", meta.Ref, meta.Mask)
		}
		return 0
	case "get", "delete":
		if len(args) != 1 || !local.ValidRef(args[0]) {
			return fatalf(2, "expected one valid ref")
		}
		id := remote.ItemID(c.session.VaultKey, args[0])
		if cmd == "delete" {
			if err := c.request(ctx, http.MethodDelete, "items/"+id, nil, nil); err != nil {
				return remoteFail(err)
			}
			return 0
		}
		item, err := c.item(ctx, args[0], true)
		if err != nil {
			return remoteFail(err)
		}
		meta, err := c.metadata(item)
		if err != nil {
			return remoteFail(err)
		}
		fmt.Printf("%s\t%s\n", meta.Ref, meta.Mask)
		return 0
	case "set":
		return c.set(ctx, args)
	case "exec":
		return c.execute(ctx, args)
	default:
		return fatalf(2, "unknown remote command")
	}
}

func (c *remoteClient) listMetadata(ctx context.Context) ([]remote.Metadata, error) {
	var items []remote.Item
	if err := c.request(ctx, http.MethodGet, "items", nil, &items); err != nil {
		return nil, err
	}
	metas := make([]remote.Metadata, 0, len(items))
	for _, item := range items {
		meta, err := c.metadata(item)
		if err != nil {
			return nil, err
		}
		metas = append(metas, meta)
	}
	return metas, nil
}

func validRemoteSession(s remote.Session) bool {
	decoded, err := hex.DecodeString(s.Token)
	defer clear(decoded)
	return err == nil && len(decoded) == 32 && len(s.VaultKey) == 32
}

func (c *remoteClient) login(ctx context.Context, ks keyring.SecretStore, slot string) error {
	var d remote.Device
	if err := c.request(ctx, http.MethodPost, "login/device", nil, &d); err != nil {
		return err
	}
	if d.VerificationURI != "https://github.com/login/device" || len(d.DeviceCode) < 16 || len(d.DeviceCode) > 256 ||
		len(d.UserCode) > 16 || d.UserCode == "" || strings.IndexFunc(d.UserCode, func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') }) >= 0 ||
		d.ExpiresIn < 1 || d.ExpiresIn > 1800 || d.Interval < 1 || d.Interval > 60 {
		return errors.New("invalid GitHub authorization instructions")
	}
	fmt.Fprintf(os.Stderr, "Open %s and enter code %s.\n", d.VerificationURI, d.UserCode)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.ExpiresIn)*time.Second)
	defer cancel()
	interval := time.Duration(d.Interval) * time.Second
	for {
		select {
		case <-ctx.Done():
			return errors.New("GitHub authorization canceled or expired")
		case <-time.After(interval):
		}
		var s remote.Session
		err := c.request(ctx, http.MethodPost, "login/poll", remote.Poll{DeviceCode: d.DeviceCode}, &s)
		if err == nil {
			defer clear(s.VaultKey)
			if !validRemoteSession(s) {
				return errors.New("invalid remote session")
			}
			raw, err := json.Marshal(s)
			if err != nil {
				return err
			}
			defer clear(raw)
			if err := ks.Set(remoteKeyringService, slot, string(raw)); err != nil {
				return errors.New("could not store remote login in keyring")
			}
			return nil
		}
		clear(s.VaultKey)
		var apiErr *remoteError
		if !errors.As(err, &apiErr) {
			return err
		}
		switch {
		case apiErr.status == 409 && apiErr.code == "authorization_pending":
		case apiErr.status == 409 && apiErr.code == "slow_down":
			interval += 5 * time.Second
		case apiErr.status == 429:
			interval += 5 * time.Second
		default:
			return err
		}
	}
}

func remoteFail(err error) int {
	var apiErr *remoteError
	if errors.As(err, &apiErr) {
		switch apiErr.status {
		case 401:
			return fatalf(exitcode.SessionLocked, "sign in with keyref remote login")
		case 404:
			return fatalf(exitcode.UnknownRef, "remote entry not found or remote vault unavailable")
		}
	}
	return fatalf(1, "%v", err)
}

func (c *remoteClient) metadata(item remote.Item) (remote.Metadata, error) {
	key := remote.CipherKey(c.session.VaultKey)
	defer clear(key)
	var m remote.Metadata
	raw, err := crypto.OpenBlob(key, remote.ItemAAD(item.ID, "meta"), item.Metadata)
	if err != nil || json.Unmarshal(raw, &m) != nil || !local.ValidRef(m.Ref) ||
		remote.ItemID(c.session.VaultKey, m.Ref) != item.ID {
		return m, errors.New("could not authenticate remote entry")
	}
	return m, nil
}

func (c *remoteClient) item(ctx context.Context, ref string, metaOnly bool) (remote.Item, error) {
	id := remote.ItemID(c.session.VaultKey, ref)
	path := "items/" + id
	if metaOnly {
		path += "?metadata=1"
	}
	var i remote.Item
	err := c.request(ctx, http.MethodGet, path, nil, &i)
	if err == nil && i.ID != id {
		err = errors.New("remote entry did not match request")
	}
	return i, err
}

func (c *remoteClient) set(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("remote set", flag.ContinueOnError)
	raw := fs.Bool("raw", false, "keep input bytes unchanged")
	var commands stringList
	fs.Var(&commands, "allow-command", "exact command name permitted to consume this entry")
	if err := fs.Parse(args); err != nil {
		return parseExit(err)
	}
	if fs.NArg() != 1 || !local.ValidRef(fs.Arg(0)) {
		return fatalf(2, "usage: keyref remote set [--raw] [--allow-command NAME] REF")
	}
	return c.putFromStdin(ctx, fs.Arg(0), *raw, local.PutOptions{AllowCommands: commands})
}

func (c *remoteClient) putFromStdin(ctx context.Context, ref string, raw bool, opts local.PutOptions) int {
	value, err := readLocalSecret(os.Stdin, raw)
	defer clear(value)
	if err != nil || len(value) == 0 || len(value) > remote.MaxSecret {
		return fatalf(2, "remote secret must be between 1 and 65536 bytes")
	}
	id := remote.ItemID(c.session.VaultKey, ref)
	key := remote.CipherKey(c.session.VaultKey)
	defer clear(key)
	rawMeta, err := json.Marshal(remote.Metadata{Ref: ref, Mask: local.Mask(value), Size: len(value), AllowCommands: opts.AllowCommands, Description: opts.Description})
	if err != nil || len(rawMeta) > remote.MaxMetadata {
		return fatalf(2, "remote metadata exceeds size limit")
	}
	meta, err := crypto.SealBlob(key, remote.ItemAAD(id, "meta"), rawMeta)
	if err != nil {
		return remoteFail(err)
	}
	sealed, err := crypto.SealBlob(key, remote.ItemAAD(id, "value"), value)
	if err != nil {
		return remoteFail(err)
	}
	if err := c.request(ctx, http.MethodPut, "items/"+id, remote.Item{ID: id, Metadata: meta, Value: sealed}, nil); err != nil {
		return remoteFail(err)
	}
	return 0
}

func (c *remoteClient) execute(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("remote exec", flag.ContinueOnError)
	var envs multiFlag
	fs.Var(&envs, "env", "NAME=REF inject a remote secret")
	if err := fs.Parse(args); err != nil {
		return parseExit(err)
	}
	if fs.NArg() == 0 || len(envs) == 0 {
		return fatalf(2, "usage: keyref remote exec --env NAME=REF -- COMMAND")
	}
	req := exec.Request{EnvRefs: envs, Argv: fs.Args(), Refs: make(map[string]*exec.ResolvedRef), Stdout: os.Stdout, Stderr: os.Stderr, ParentEnv: os.Environ()}
	items := map[string]remote.Item{}
	for _, ref := range exec.CollectRefs(&req) {
		if !local.ValidRef(ref) {
			return fatalf(2, "invalid remote ref")
		}
		item, err := c.item(ctx, ref, false)
		if err != nil {
			return remoteFail(err)
		}
		meta, err := c.metadata(item)
		if err != nil {
			return remoteFail(err)
		}
		items[ref] = item
		req.Refs[ref] = &exec.ResolvedRef{Ref: ref, Injectable: true, Policy: exec.Policy{AllowCommands: meta.AllowCommands, RequireAllowList: true}}
	}
	req.ResolveValue = func(ref string) (*secret.Plaintext, int, string) {
		i := items[ref]
		key := remote.CipherKey(c.session.VaultKey)
		defer clear(key)
		raw, err := crypto.OpenBlob(key, remote.ItemAAD(i.ID, "value"), i.Value)
		if err != nil {
			return nil, exitcode.UnwrapFailed, "unwrap_failed"
		}
		defer clear(raw)
		p, err := secret.NewPlaintextFromBytes(raw)
		if err != nil {
			return nil, exitcode.UnwrapFailed, "unwrap_failed"
		}
		return p, 0, ""
	}
	return exec.Run(&req)
}
