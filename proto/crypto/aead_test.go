package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

const (
	tvVault = "00112233445566778899aabbccddeeff"
	tvItem  = "ffeeddccbbaa99887766554433221100"
	tvDev   = "0123456789abcdef0123456789abcdef"
	tvOther = "99999999999999999999999999999999"
)

func mustAAD(t *testing.T, f func(string, string) ([]byte, error)) []byte {
	t.Helper()
	aad, err := f(tvVault, tvItem)
	if err != nil {
		t.Fatal(err)
	}
	return aad
}

func TestInfoLayout(t *testing.T) {
	got, err := Info(PurposeItemKey, tvVault, tvDev)
	if err != nil {
		t.Fatal(err)
	}
	want := "keyref v1\x1fitem-key\x1f" + tvVault + "\x1f" + tvDev
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("info mismatch\n got: %q\nwant: %q", got, want)
	}
	for _, bad := range []string{"", "ABC", tvVault[:31], tvOther + "x"} {
		if _, err := Info(PurposeItemKey, bad, tvDev); err == nil {
			t.Errorf("Info accepted invalid vault id %q", bad)
		}
	}
}

func TestOneTimeItemKeyInfoLayout(t *testing.T) {
	reqCT := []byte("request-ciphertext-bytes")
	got, err := OneTimeItemKeyInfo(tvVault, tvDev, tvItem, tvOther, reqCT)
	if err != nil {
		t.Fatal(err)
	}
	// Independently assembled expectation: base info + US + item + US +
	// approval + US + SHA-256(request ciphertext) (protocol §3.7, D4).
	sum := sha256Sum(reqCT)
	want := "keyref v1\x1fone-time-item-key\x1f" + tvVault + "\x1f" + tvDev +
		"\x1f" + tvItem + "\x1f" + tvOther + "\x1f" + string(sum)
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("one-time info mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestAADLayouts(t *testing.T) {
	base := "keyref v1\x1f"
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"secret", mustAAD(t, SecretAAD), base + "secret\x1f" + tvVault + "\x1f" + tvItem},
		{"meta", mustAAD(t, MetaAAD), base + "meta\x1f" + tvVault + "\x1f" + tvItem},
		{"vault-meta-key", mustAAD(t, VaultWrappedMetaKeyAAD), base + "vault-meta-key\x1f" + tvVault + "\x1f" + tvItem},
		{"vault-item-key", mustAAD(t, VaultWrappedItemKeyAAD), base + "vault-item-key\x1f" + tvVault + "\x1f" + tvItem},
	}
	for _, c := range cases {
		if !bytes.Equal(c.got, []byte(c.want)) {
			t.Errorf("%s aad mismatch\n got: %q\nwant: %q", c.name, c.got, c.want)
		}
	}
	rec, err := RecoveryAAD(tvVault)
	if err != nil {
		t.Fatal(err)
	}
	if want := base + "recovery\x1f" + tvVault; !bytes.Equal(rec, []byte(want)) {
		t.Fatalf("recovery aad mismatch: %q", rec)
	}
	aud, err := AuditAAD(tvVault, tvDev)
	if err != nil {
		t.Fatal(err)
	}
	if want := base + "audit\x1f" + tvVault + "\x1f" + tvDev; !bytes.Equal(aud, []byte(want)) {
		t.Fatalf("audit aad mismatch: %q", aud)
	}
}

func TestSealOpenBlobRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aad := mustAAD(t, SecretAAD)
	for _, size := range []int{0, 1, 15, 16, 4096, 64 * 1024} {
		pt := make([]byte, size)
		if _, err := rand.Read(pt); err != nil {
			t.Fatal(err)
		}
		blob, err := SealBlob(key, aad, pt)
		if err != nil {
			t.Fatalf("size %d: seal: %v", size, err)
		}
		if len(blob) != size+nonceSize+tagSize {
			t.Fatalf("size %d: blob length %d, want %d", size, len(blob), size+28)
		}
		got, err := OpenBlob(key, aad, blob)
		if err != nil {
			t.Fatalf("size %d: open: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: plaintext mismatch", size)
		}
	}
	if _, err := SealBlob(key[:31], aad, []byte("x")); err == nil {
		t.Fatal("SealBlob accepted a 31-byte key")
	}
}

func TestOpenBlobRejectsWrongKeyAADAndTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	otherKey := bytes.Repeat([]byte{0x22}, 32)
	secretAAD := mustAAD(t, SecretAAD)
	metaAAD := mustAAD(t, MetaAAD)
	blob, err := SealBlob(key, secretAAD, []byte("sk-roundtrip"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenBlob(otherKey, secretAAD, blob); err == nil {
		t.Error("wrong key accepted")
	}
	if _, err := OpenBlob(key, metaAAD, blob); err == nil {
		t.Error("wrong aad (meta vs secret) accepted")
	}
	otherItem, err := SecretAAD(tvVault, tvOther)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBlob(key, otherItem, blob); err == nil {
		t.Error("aad of another item accepted")
	}
	otherVault, err := SecretAAD(tvOther, tvItem)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBlob(key, otherVault, blob); err == nil {
		t.Error("aad of another vault accepted")
	}
	if _, err := OpenBlob(key, secretAAD, []byte(blob[:len(blob)-1])); err == nil {
		t.Error("truncated blob accepted")
	}
	if _, err := OpenBlob(key, secretAAD, blob[:12]); err == nil {
		t.Error("empty ciphertext accepted")
	}
	for _, pos := range []int{0, 12, 13, len(blob) - 1} {
		tampered := append([]byte(nil), blob...)
		tampered[pos] ^= 0x01
		if _, err := OpenBlob(key, secretAAD, tampered); err == nil {
			t.Errorf("tampered blob accepted at position %d", pos)
		}
	}
}

func TestOpenBlobIntoWritesIntoCallerBuffer(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	aad := mustAAD(t, SecretAAD)
	pt := bytes.Repeat([]byte{0x44}, 100)
	blob, err := SealBlob(key, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	// A caller-provided buffer with enough capacity, like a guarded
	// allocation: OpenBlobInto must reuse it, not reallocate.
	dst := make([]byte, 0, len(blob))
	out, err := OpenBlobInto(dst, key, aad, blob)
	if err != nil {
		t.Fatal(err)
	}
	if &out[:1][0] != &dst[:1][0] {
		t.Fatal("OpenBlobInto reallocated despite sufficient capacity")
	}
	if !bytes.Equal(out, pt) {
		t.Fatal("plaintext mismatch")
	}
	// Insufficient capacity still works (allocates — documented path).
	small := make([]byte, 0, 4)
	out2, err := OpenBlobInto(small, key, aad, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out2, pt) {
		t.Fatal("plaintext mismatch on grow path")
	}
}

func TestKeyLengthEnforced(t *testing.T) {
	if _, err := newGCM(bytes.Repeat([]byte{1}, 16)); err == nil {
		t.Fatal("AES-128 key accepted for AES-256 interface")
	}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
