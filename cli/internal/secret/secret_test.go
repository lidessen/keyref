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
