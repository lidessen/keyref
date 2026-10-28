package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type fixtureStore struct{ value []byte }

func (s *fixtureStore) Put(_ context.Context, _ string, value []byte) error {
	s.value = bytes.Clone(value)
	return nil
}
func (s *fixtureStore) Use(_ context.Context, _ string, fn func([]byte) error) error {
	return fn(s.value)
}
func (s *fixtureStore) Delete(context.Context, string) error { s.value = nil; return nil }
func (s *fixtureStore) Close() error                         { return nil }

func TestDefaultAndExplicitLocal(t *testing.T) {
	registry := NewRegistry()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	opts := Options{Config: LocalOptions{Path: filepath.Join(dir, "vault.db"), Key: bytes.Repeat([]byte{42}, 32)}}
	s, err := registry.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Put(context.Background(), "test", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Provider = "local"
	s, err = registry.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Use(context.Background(), "test", func(value []byte) error {
		if string(value) != "synthetic" {
			t.Fatal("unexpected value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProviderSelectionAndNoFallback(t *testing.T) {
	registry := NewRegistry()
	failure := errors.New("fixture unavailable")
	seen := []bool{}
	if err := registry.Register("fixture", func(config any, create bool) (Store, error) {
		seen = append(seen, create)
		if config != "config" {
			return nil, failure
		}
		return &fixtureStore{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, create := range []bool{true, false} {
		opts := Options{Provider: "fixture", Config: "config"}
		var got Store
		var err error
		if create {
			got, err = registry.Create(opts)
		} else {
			got, err = registry.Open(opts)
		}
		if err != nil {
			t.Fatal(err)
		}
		got.Close()
	}
	if len(seen) != 2 || !seen[0] || seen[1] {
		t.Fatal("create/open not forwarded")
	}
	if _, err := registry.Open(Options{Provider: "fixture", Config: "bad"}); !errors.Is(err, failure) {
		t.Fatalf("provider error: %v", err)
	}
	if _, err := registry.Open(Options{Provider: "missing", Config: LocalOptions{}}); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("unknown provider: %v", err)
	}
	if _, err := registry.Open(Options{Config: "bad"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("local configuration: %v", err)
	}
	if err := registry.Register("fixture", func(any, bool) (Store, error) { return nil, nil }); !errors.Is(err, ErrProviderRegistered) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := registry.Register("local", func(any, bool) (Store, error) { return nil, nil }); !errors.Is(err, ErrProviderRegistered) {
		t.Fatalf("local replacement: %v", err)
	}
	if err := registry.Register("", nil); !errors.Is(err, ErrInvalidProvider) {
		t.Fatalf("invalid: %v", err)
	}
}

func TestConcurrentRegistrationAndOpen(t *testing.T) {
	registry := NewRegistry()
	factory := func(any, bool) (Store, error) { return &fixtureStore{}, nil }
	if err := registry.Register("fixture", factory); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s, err := registry.Open(Options{Provider: "fixture"})
				if err != nil {
					t.Error(err)
					return
				}
				_ = s.Close()
				if err = registry.Register("fixture", factory); !errors.Is(err, ErrProviderRegistered) {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
