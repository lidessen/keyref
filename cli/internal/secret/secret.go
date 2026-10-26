// Package secret provides guarded memory for sensitive buffers: unwrapped
// meta and item keys, and secret plaintexts (design.md §12.2).
//
// Guarded buffers are allocated outside the Go heap, locked with mlock,
// invisible to the garbage collector and immovable by it. They are
// explicitly zeroed on Destroy, on Vault.Lock (the `keyref lock` command)
// and on process exit (Purge, deferred in main). Secrets never travel
// through ordinary heap strings: this package exposes byte slices only,
// and secret values are extracted from decrypted JSON by jsonscan.go
// without creating Go strings.
//
// Residual risk is recorded by the design, not hidden here: the AES-GCM
// key schedule, circl's HPKE internals and error-path formatting still
// pass through the ordinary heap; a fully compromised host reads them
// (design §4.2 B1/B2, §12.2). What this package guarantees is that the
// long-lived secret material itself does not sit on the GC heap.
package secret

import (
	"fmt"
	"sync"

	"github.com/awnumar/memguard"
)

// Key is a 32-byte symmetric key (meta key, item key) held in guarded
// memory. The zero Key is not usable; obtain keys via NewKey and release
// them with Destroy, or keep them inside a Vault.
type Key struct {
	buf *memguard.LockedBuffer
}

// NewKey moves material into a guarded buffer and wipes the source slice
// in constant time (memguard semantics). Callers must treat material as
// consumed: the slice is zeroed even on failure paths after the copy.
func NewKey(material []byte) (*Key, error) {
	if len(material) != 32 {
		return nil, fmt.Errorf("secret: key material must be 32 bytes, got %d", len(material))
	}
	buf := memguard.NewBuffer(len(material))
	if !buf.IsAlive() {
		return nil, fmt.Errorf("secret: guarded allocation failed")
	}
	buf.Move(material) // copies into guarded memory and wipes material
	return &Key{buf: buf}, nil
}

// Bytes returns the guarded key bytes, or nil after Destroy. The slice
// aliases guarded memory: do not copy it onto the heap, do not append to
// it, and do not retain it past Destroy.
func (k *Key) Bytes() []byte {
	if k == nil || k.buf == nil || !k.buf.IsAlive() {
		return nil
	}
	return k.buf.Bytes()
}

// EqualTo compares the key against want in constant time.
func (k *Key) EqualTo(want []byte) bool {
	if k == nil || k.buf == nil {
		return false
	}
	return k.buf.EqualTo(want)
}

// Destroy explicitly zeroes and unlocks the guarded key. It is idempotent.
func (k *Key) Destroy() {
	if k != nil && k.buf != nil {
		k.buf.Destroy()
		k.buf = nil
	}
}

// Vault holds the unwrapped keys of the current session in guarded
// memory, keyed by item id (design.md §6.5: unlocked item keys stay in
// process memory only, at most 8 hours, dropped by `keyref lock`).
type Vault struct {
	mu   sync.Mutex
	keys map[string]*Key
}

// NewVault returns an empty key vault.
func NewVault() *Vault {
	return &Vault{keys: make(map[string]*Key)}
}

// Put stores key under itemID, taking ownership: a previously stored key
// for the same item is destroyed, and on failure key is destroyed too.
func (v *Vault) Put(itemID string, key *Key) {
	if key == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	old, ok := v.keys[itemID]
	if ok && old != key {
		old.Destroy()
	}
	v.keys[itemID] = key
}

// Get returns the guarded key for itemID if present.
func (v *Vault) Get(itemID string) (*Key, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	k, ok := v.keys[itemID]
	return k, ok
}

// Delete destroys and removes the key for itemID.
func (v *Vault) Delete(itemID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[itemID]; ok {
		k.Destroy()
		delete(v.keys, itemID)
	}
}

// Lock destroys every key in the vault — the memory effect of
// `keyref lock` (design.md §6.5, §12.2).
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, k := range v.keys {
		k.Destroy()
		delete(v.keys, id)
	}
}

// Len returns the number of live keys.
func (v *Vault) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.keys)
}

// NewPlaintext allocates a guarded buffer of size n for a secret
// plaintext (decryption output, fd-template rendering). Use
// memguard.LockedBuffer.Destroy when done.
func NewPlaintext(n int) (*memguard.LockedBuffer, error) {
	buf := memguard.NewBuffer(n)
	if !buf.IsAlive() {
		return nil, fmt.Errorf("secret: guarded allocation failed")
	}
	return buf, nil
}

// NewPlaintextFromBytes moves value into a fresh guarded Plaintext and
// wipes the source slice (memguard Move semantics: the bytes never
// remain on the ordinary heap). The empty value yields the nil-buffer
// Plaintext, matching ExtractStringField.
func NewPlaintextFromBytes(value []byte) (*Plaintext, error) {
	if len(value) == 0 {
		return &Plaintext{}, nil
	}
	buf := memguard.NewBuffer(len(value))
	if !buf.IsAlive() {
		return nil, fmt.Errorf("secret: guarded allocation failed")
	}
	buf.Move(value)
	return &Plaintext{buf: buf}, nil
}

// Wipe best-effort zeroes a heap slice that briefly held sensitive
// material (for example the circl unwrap output before it is moved into
// a guarded Key).
func Wipe(b []byte) { memguard.WipeBytes(b) }

// Purge destroys every guarded buffer process-wide and is intended for
// process exit; main defers it so keys never survive the process.
func Purge() { memguard.Purge() }
