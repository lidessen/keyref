// Package store provides a small provider-neutral interface for Keyref stores.
// The default provider is the standalone local vault; no remote provider is
// registered automatically.
package store

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lidessen/keyref/cli/local"
)

var (
	ErrUnknownProvider    = errors.New("keyref store provider unavailable")
	ErrInvalidProvider    = errors.New("invalid keyref store provider")
	ErrProviderRegistered = errors.New("keyref store provider already registered")
	ErrInvalidConfig      = errors.New("invalid keyref store configuration")
)

// Store exposes secret values only during the Use callback. Callers must not
// retain or disclose the value passed to the callback.
type Store interface {
	Put(context.Context, string, []byte) error
	Use(context.Context, string, func([]byte) error) error
	Delete(context.Context, string) error
	Close() error
}

// Options chooses a provider and passes its own configuration unchanged. An
// empty Provider selects local; an unknown explicit provider is an error.
type Options struct {
	Provider string
	Config   any
}

type LocalOptions struct {
	Path string
	Key  []byte
}

// Factory constructs the requested provider. create distinguishes exclusive
// creation from opening an existing store; factories must not silently fall
// back to a different provider on failure.
type Factory func(config any, create bool) (Store, error)

// Registry is an instance-scoped, concurrent-safe set of providers. It has no
// global registrations, so applications choose which providers they trust.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Factory
}

func NewRegistry() *Registry {
	r := &Registry{providers: make(map[string]Factory)}
	r.providers["local"] = func(config any, create bool) (Store, error) {
		opts, ok := config.(LocalOptions)
		if !ok {
			return nil, ErrInvalidConfig
		}
		if create {
			return local.Create(opts.Path, opts.Key)
		}
		return local.Open(opts.Path, opts.Key)
	}
	return r
}

func (r *Registry) Register(name string, factory Factory) error {
	if r == nil || name == "" || factory == nil {
		return ErrInvalidProvider
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.providers == nil {
		r.providers = make(map[string]Factory)
	}
	if _, exists := r.providers[name]; exists {
		return ErrProviderRegistered
	}
	r.providers[name] = factory
	return nil
}

func (r *Registry) Open(options Options) (Store, error)   { return r.open(options, false) }
func (r *Registry) Create(options Options) (Store, error) { return r.open(options, true) }

func (r *Registry) open(options Options, create bool) (Store, error) {
	if r == nil {
		return nil, ErrInvalidProvider
	}
	name := options.Provider
	if name == "" {
		name = "local"
	}
	r.mu.RLock()
	factory, ok := r.providers[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownProvider, name)
	}
	result, err := factory(options.Config, create)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrInvalidProvider
	}
	return result, nil
}
