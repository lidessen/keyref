package secret

import (
	"bytes"
	"testing"
)

func TestNewKeyMovesAndWipesSource(t *testing.T) {
	material := bytes.Repeat([]byte{0xab}, 32)
	key, err := NewKey(material)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if !bytes.Equal(material, bytes.Repeat([]byte{0}, 32)) {
		t.Fatal("NewKey left key material on the source slice")
	}
	if !key.EqualTo(bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatal("guarded key does not hold the original material")
	}
	got := key.Bytes()
	if got == nil || !bytes.Equal(got, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatal("Bytes() does not expose the guarded key")
	}
	if _, err := NewKey(bytes.Repeat([]byte{1}, 31)); err == nil {
		t.Fatal("31-byte key material accepted")
	}
}

func TestKeyDestroyIsIdempotent(t *testing.T) {
	key, err := NewKey(bytes.Repeat([]byte{0xcd}, 32))
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	if key.Bytes() != nil {
		t.Fatal("Bytes() must return nil after Destroy")
	}
	key.Destroy() // must not panic
}

func TestVaultLifecycle(t *testing.T) {
	v := NewVault()
	itemA := "00112233445566778899aabbccddeeff"
	itemB := "99998888777766665555444433332222"

	k1, err := NewKey(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	v.Put(itemA, k1)
	if v.Len() != 1 {
		t.Fatalf("vault len %d, want 1", v.Len())
	}
	got, ok := v.Get(itemA)
	if !ok || !got.EqualTo(bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("vault did not return the stored key")
	}

	// Replacing a key destroys the previous one.
	k2, err := NewKey(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	v.Put(itemA, k2)
	got2, ok := v.Get(itemA)
	if !ok || !got2.EqualTo(bytes.Repeat([]byte{2}, 32)) {
		t.Fatal("vault did not replace the key")
	}

	k3, err := NewKey(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	v.Put(itemB, k3)

	// Lock destroys everything — the memory effect of `keyref lock`
	// (design.md §6.5, §12.2).
	v.Lock()
	if v.Len() != 0 {
		t.Fatalf("vault still holds %d keys after Lock", v.Len())
	}
	if _, ok := v.Get(itemA); ok {
		t.Fatal("vault returned a key after Lock")
	}
	if k2.Bytes() != nil || k3.Bytes() != nil {
		t.Fatal("guarded key survived Vault.Lock")
	}
	v.Lock() // idempotent

	// Delete removes single keys.
	k4, _ := NewKey(bytes.Repeat([]byte{4}, 32))
	v.Put(itemA, k4)
	v.Delete(itemA)
	if _, ok := v.Get(itemA); ok {
		t.Fatal("vault returned a key after Delete")
	}
	if k4.Bytes() != nil {
		t.Fatal("guarded key survived Vault.Delete")
	}
}
