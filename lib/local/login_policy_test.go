package local

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestLoginPolicyAndImport(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	username := "fixture-user"
	opts := PutOptions{Username: &username, URL: "https://example.test", AllowCommands: []string{"python3", "helper"}, AllowArgv: true}
	if _, err := s.Put(ctx, "login", []byte("fixture-password"), opts); err != nil {
		t.Fatal(err)
	}
	m, err := s.Stat(ctx, "login")
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != "login" || m.Username != username || m.URL != opts.URL || !m.Policy.AllowArgv || !reflect.DeepEqual(m.Policy.AllowCommands, opts.AllowCommands) || m.Bytes != len("fixture-password") {
		t.Fatalf("metadata: %+v", m)
	}
	check := func(want string) {
		t.Helper()
		if err := s.Use(ctx, "login", func(value []byte) error {
			if string(value) != want {
				t.Error("incorrect value")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.UseLogin(ctx, "login", func(u, v []byte) error {
			if string(u) != username || string(v) != want {
				t.Error("incorrect login")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check("fixture-password")
	status, err := s.Import(ctx, []ImportItem{{Ref: "login", Value: []byte("fixture-password")}})
	if err != nil || status[0] != ImportUnchanged {
		t.Fatalf("unchanged: %v %v", status, err)
	}
	status, err = s.Import(ctx, []ImportItem{{Ref: "login", Value: []byte("replacement-password")}})
	if err != nil || status[0] != ImportReplaced {
		t.Fatalf("replace: %v %v", status, err)
	}
	check("replacement-password")
	m, err = s.Stat(ctx, "login")
	if err != nil || !m.Policy.AllowArgv || !reflect.DeepEqual(m.Policy.AllowCommands, opts.AllowCommands) || m.URL != opts.URL {
		t.Fatalf("import metadata: %+v %v", m, err)
	}
	raw := []byte(`{"v":1,"username":"fixture-user","value":"fixture-password"}`)
	if _, err := s.Put(ctx, "raw", raw, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Use(ctx, "raw", func(v []byte) error {
		if string(v) != string(raw) {
			t.Error("JSON raw value changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UseLogin(ctx, "raw", func(_, _ []byte) error { t.Error("raw value interpreted as login"); return nil }); !errors.Is(err, ErrNotLogin) {
		t.Fatalf("non-login: %v", err)
	}
	if _, err := s.Put(ctx, "bad", []byte("password"), PutOptions{AllowCommands: []string{""}}); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("invalid command: %v", err)
	}
}

func TestLoginCodec(t *testing.T) {
	username := "user\"\\雪"
	value := []byte("pass\n\"\\雪")
	m := &Meta{Username: username, Bytes: len(value)}
	encoded, err := encodeLogin(username, value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, value) || !bytes.Contains(encoded, []byte(`"v":2`)) {
		t.Fatal("login payload is not encoded as version 2")
	}
	legacy := []byte(`{"v":1,"username":"user\"\\雪","value":"pass\n\"\\雪"}`)
	for _, data := range [][]byte{encoded, legacy} {
		u, v, err := decodeLogin(data, m)
		if err != nil || !bytes.Equal(u, []byte(username)) || !bytes.Equal(v, value) {
			t.Fatalf("login round trip failed: %v", err)
		}
	}
	for _, data := range [][]byte{
		[]byte(`{"v":2,"username":"%%%","value":"cA=="}`),
		[]byte(`{"v":2,"username":"dXNlcg==","value":"%%%"}`),
		[]byte(`{"v":3,"username":"dXNlcg==","value":"cA=="}`),
		[]byte(`{"v":1,"username":"user","value":3}`),
	} {
		if _, _, err := decodeLogin(data, m); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("malformed login accepted: %v", err)
		}
	}
}

func TestLoginCallbackBuffersAreWiped(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	username := "fixture-user"
	if _, err := s.Put(ctx, "login", []byte("fixture-password"), PutOptions{Username: &username}); err != nil {
		t.Fatal(err)
	}
	var userBuffer, valueBuffer []byte
	if err := s.UseLogin(ctx, "login", func(u, v []byte) error {
		userBuffer, valueBuffer = u, v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(userBuffer, make([]byte, len(userBuffer))) || !bytes.Equal(valueBuffer, make([]byte, len(valueBuffer))) {
		t.Fatal("login callback buffers were not wiped")
	}
}
