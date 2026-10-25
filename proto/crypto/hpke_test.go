package crypto

import (
	"bytes"
	"testing"
)

func TestWrapUnwrapKeyRoundtripBothKEMs(t *testing.T) {
	for _, kem := range []string{KEMX25519, KEMP256} {
		t.Run(kem, func(t *testing.T) {
			pub, priv, err := GenerateHPKEKeyPair(kem)
			if err != nil {
				t.Fatal(err)
			}
			wantEncLen := 32
			if kem == KEMP256 {
				wantEncLen = 65
			}
			if len(pub) != wantEncLen {
				t.Fatalf("public key length %d, want %d (protocol §1.4)", len(pub), wantEncLen)
			}
			info, err := Info(PurposeItemKey, tvVault, tvDev)
			if err != nil {
				t.Fatal(err)
			}
			itemKey := bytes.Repeat([]byte{0x5a}, 32)
			enc, ct, err := WrapKey(kem, pub, info, itemKey)
			if err != nil {
				t.Fatal(err)
			}
			if len(enc) != wantEncLen {
				t.Fatalf("enc length %d, want %d", len(enc), wantEncLen)
			}
			if len(ct) != len(itemKey)+16 {
				t.Fatalf("ct length %d, want %d", len(ct), len(itemKey)+16)
			}
			pt, err := UnwrapKey(kem, priv, info, enc, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt, itemKey) {
				t.Fatal("unwrapped key mismatch")
			}

			// Any change to info, ciphertext or keys must fail.
			if _, err := UnwrapKey(kem, priv, append(info, 0x00), enc, ct); err == nil {
				t.Error("modified info accepted")
			}
			tamperedCT := append([]byte(nil), ct...)
			tamperedCT[0] ^= 1
			if _, err := UnwrapKey(kem, priv, info, enc, tamperedCT); err == nil {
				t.Error("tampered ciphertext accepted")
			}
			tamperedEnc := append([]byte(nil), enc...)
			tamperedEnc[0] ^= 1
			if _, err := UnwrapKey(kem, priv, info, tamperedEnc, ct); err == nil {
				t.Error("tampered enc accepted")
			}
			_, otherPriv, err := GenerateHPKEKeyPair(kem)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnwrapKey(kem, otherPriv, info, enc, ct); err == nil {
				t.Error("wrong private key accepted")
			}
		})
	}
}

func TestUnwrapKeyRejectsGarbage(t *testing.T) {
	_, priv, err := GenerateHPKEKeyPair(KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := Info(PurposeMetaKey, tvVault, tvDev)
	if _, err := UnwrapKey(KEMX25519, priv, info, []byte("junk"), []byte("junk")); err == nil {
		t.Fatal("garbage envelope accepted")
	}
	if _, err := UnwrapKey("Ed448", priv, info, nil, nil); err == nil {
		t.Fatal("unknown KEM accepted")
	}
}

func TestOneTimeWrapBinding(t *testing.T) {
	// The approval one-time wrap binds item, approval and the request
	// transcript digest into the HPKE info (protocol §3.7 D4, design
	// §8.3): the wrap must refuse to open under any other binding.
	ephPub, ephPriv, err := GenerateHPKEKeyPair(KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	reqCT := []byte("approval-request-ciphertext")
	itemKey := bytes.Repeat([]byte{0x77}, 32)
	info, err := OneTimeItemKeyInfo(tvVault, tvDev, tvItem, tvOther, reqCT)
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := WrapKey(KEMX25519, ephPub, info, itemKey)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := UnwrapKey(KEMX25519, ephPriv, info, enc, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, itemKey) {
		t.Fatal("one-time unwrap mismatch")
	}

	wrongApproval, err := OneTimeItemKeyInfo(tvVault, tvDev, tvItem, tvItem, reqCT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapKey(KEMX25519, ephPriv, wrongApproval, enc, ct); err == nil {
		t.Error("wrap opened under a different approval id")
	}
	wrongItem, err := OneTimeItemKeyInfo(tvVault, tvDev, tvOther, tvOther, reqCT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapKey(KEMX25519, ephPriv, wrongItem, enc, ct); err == nil {
		t.Error("wrap opened under a different item id")
	}
	wrongRequest, err := OneTimeItemKeyInfo(tvVault, tvDev, tvItem, tvOther, []byte("other-request"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapKey(KEMX25519, ephPriv, wrongRequest, enc, ct); err == nil {
		t.Error("wrap opened under a different request ciphertext")
	}
	wrongDevice, err := OneTimeItemKeyInfo(tvVault, tvItem, tvItem, tvOther, reqCT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapKey(KEMX25519, ephPriv, wrongDevice, enc, ct); err == nil {
		t.Error("wrap opened under a different recipient device")
	}
}

func TestPublicKeyOfRecoversPublicKey(t *testing.T) {
	pub, priv, err := GenerateHPKEKeyPair(KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := PublicKeyOf(KEMX25519, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, pub) {
		t.Fatal("recovered public key does not match the generated one")
	}
	if _, err := PublicKeyOf(KEMX25519, []byte("corrupt")); err == nil {
		t.Fatal("corrupt private key accepted")
	}
}
