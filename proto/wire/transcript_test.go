package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

// Fixed test identifiers (32 lowercase hex characters each).
const (
	tvVault   = "00112233445566778899aabbccddeeff"
	tvItem    = "ffeeddccbbaa99887766554433221100"
	tvItem2   = "11111111111111111111111111111111"
	tvDevice  = "0123456789abcdef0123456789abcdef"
	tvDevice2 = "ffffffffffffffffffffffffffffffff"
	tvWriter  = "99998888777766665555444433332222"
	tvNonce   = "abcdefabcdefabcdefabcdefabcdef12"
)

// u64hex encodes v the way the protocol fixes for transcript integers:
// 8-byte big-endian (protocol §1.1). Tests use it to assemble expected
// bytes independently of the builder's internal helpers.
func u64hex(v uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return string(b[:])
}

func rep(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func TestBuildTranscriptGolden(t *testing.T) {
	// Small binary payloads, deliberately including 0x00 bytes to prove
	// binary fields are carried raw.
	meta := []byte{0xaa}
	secret := []byte{0xbb, 0xcc}
	vwMeta := []byte{0x01, 0x00, 0x02}
	vwItem := []byte{}
	enc := []byte{0x0a}
	wrapped := []byte{0x0b}
	digestA := rep(0xd4, SizeDigest)
	digestB := rep(0x07, SizeDigest)

	// Directory records assembled by hand (independent of the builder).
	dirA := DirectoryDevice{
		DeviceID:             tvDevice,
		Kind:                 DeviceKindIOS,
		Status:               DeviceStatusActive,
		HPKEKEM:              KEMP256,
		HPKEPublicKey:        append([]byte{0x04, 0x00}, rep(0xa1, 63)...),
		SignAlg:              SignAlgECDSAP256,
		SignPublicKey:        append([]byte{0x04, 0x00}, rep(0xb2, 63)...),
		RenewalSignPublicKey: rep(0xc3, SizeEd25519Key),
		GrantsDigest:         digestA,
		ReceiverRole:         ReceiverRolePrimary,
	}
	dirB := DirectoryDevice{
		DeviceID:      tvDevice2,
		Kind:          DeviceKindCLI,
		Status:        DeviceStatusRevoked,
		HPKEKEM:       KEMX25519,
		HPKEPublicKey: append([]byte{0x00}, rep(0xe5, 31)...), // starts with NUL
		SignAlg:       SignAlgEd25519,
		SignPublicKey: append([]byte{0x00}, rep(0xf6, 31)...), // starts with NUL
		GrantsDigest:  digestB,
	}

	recA := strings.Join([]string{dirA.DeviceID, dirA.Kind, dirA.Status, dirA.HPKEKEM}, "\x00")
	recB := strings.Join([]string{dirB.DeviceID, dirB.Kind, dirB.Status, dirB.HPKEKEM}, "\x00")

	grantItem1 := GrantTranscript{ // view on tvItem2, sorts first by item_id
		VaultID: tvVault, DeviceID: tvDevice, ItemID: tvItem2,
		Kind: GrantKindView, Revision: 1, ExpiresAt: 0,
		HPKEEnc: []byte{0x1a}, WrappedKey: []byte{0x1b},
	}
	grantItem2 := GrantTranscript{ // use on tvItem, second by item_id
		VaultID: tvVault, DeviceID: tvDevice, ItemID: tvItem,
		Kind: GrantKindUse, Revision: 2, ExpiresAt: 1790000000000,
		HPKEEnc: enc, WrappedKey: wrapped,
	}
	// Hand-assembled grant transcript bytes (independent of the builder).
	grant1Str := "KEYREF1\x00grant\x00" + tvVault + "\x00" + tvDevice + "\x00" + tvItem2 +
		"\x00view\x00" + u64hex(1) + "\x00" + u64hex(0) + "\x00" + "\x1a\x00" + "\x1b"
	grant2Str := "KEYREF1\x00grant\x00" + tvVault + "\x00" + tvDevice + "\x00" + tvItem +
		"\x00use\x00" + u64hex(2) + "\x00" + u64hex(1790000000000) + "\x00" + "\x0a\x00" + "\x0b"

	pairNonce := []byte("0123456789abcdef")

	tests := []struct {
		name string
		got  []byte
		want string // expected transcript bytes, hand-assembled from protocol §3
	}{
		{
			name: "item full row",
			got: mustBuild(t, func() ([]byte, error) {
				return BuildItemTranscript(ItemTranscript{
					VaultID: tvVault, ItemID: tvItem, Revision: 4,
					MetaCiphertext: meta, SecretCiphertext: secret,
					VaultWrappedMetaKey: vwMeta, VaultWrappedItemKey: vwItem,
					WriterDeviceID: tvWriter,
				})
			}),
			want: "KEYREF1\x00item\x00" + tvVault + "\x00" + tvItem + "\x00" +
				u64hex(4) + "\x00" +
				"\xaa\x00" + "\xbb\xcc\x00" + "\x01\x00\x02\x00" + "\x00" + tvWriter,
		},
		{
			name: "item tombstone row has four empty ciphertext fields",
			got: mustBuild(t, func() ([]byte, error) {
				return BuildItemTranscript(ItemTranscript{
					VaultID: tvVault, ItemID: tvItem, Revision: 5,
					WriterDeviceID: tvWriter,
				})
			}),
			want: "KEYREF1\x00item\x00" + tvVault + "\x00" + tvItem + "\x00" +
				u64hex(5) + "\x00\x00\x00\x00\x00" + tvWriter,
		},
		{
			name: "grant use with expiry",
			got: mustBuild(t, func() ([]byte, error) {
				return BuildGrantTranscript(grantItem2)
			}),
			want: grant2Str,
		},
		{
			name: "grant deletion form keeps revision with empty enc and key",
			got: mustBuild(t, func() ([]byte, error) {
				return BuildGrantTranscript(GrantTranscript{
					VaultID: tvVault, DeviceID: tvDevice, ItemID: tvItem,
					Kind: GrantKindUse, Revision: 3,
				})
			}),
			want: "KEYREF1\x00grant\x00" + tvVault + "\x00" + tvDevice + "\x00" + tvItem +
				"\x00use\x00" + u64hex(3) + "\x00" + u64hex(0) + "\x00\x00",
		},
		{
			name: "directory sorts device records by device_id hex",
			got: mustBuild(t, func() ([]byte, error) {
				// Input deliberately unsorted: B before A.
				return BuildDirectoryTranscript(DirectoryTranscript{
					VaultID: tvVault, DirectoryRevision: 2,
					Devices: []DirectoryDevice{dirB, dirA},
				})
			}),
			want: "KEYREF1\x00directory\x00" + tvVault + "\x00" + u64hex(2) + "\x00" +
				recA + "\x00" + string(dirA.HPKEPublicKey) + "\x00" + dirA.SignAlg + "\x00" +
				string(dirA.SignPublicKey) + "\x00" + string(dirA.RenewalSignPublicKey) + "\x00" +
				string(digestA) + "\x01" + // receiver_role directly after the digest (§14.4)
				"\x00" + recB + "\x00" + string(dirB.HPKEPublicKey) + "\x00" + dirB.SignAlg + "\x00" +
				string(dirB.SignPublicKey) + "\x00" + "" + "\x00" + string(digestB) + "\x00",
		},
		{
			name: "pair sorts grants and concatenates transcripts",
			got: mustBuild(t, func() ([]byte, error) {
				return BuildPairTranscript(PairTranscript{
					VaultID:            tvVault,
					OwnerSignPublicKey: append([]byte{0x04}, rep(0x33, 64)...),
					Nonce:              tvNonce,
					DeviceID:           tvDevice,
					HPKEKEM:            KEMX25519,
					HPKEPublicKey:      rep(0x44, SizeX25519Key),
					SignAlg:            SignAlgEd25519,
					SignPublicKey:      rep(0x55, SizeEd25519Key),
					Label:              "build-agent-1",
					Grants:             []GrantTranscript{grantItem2, grantItem1}, // unsorted input
				})
			}),
			want: "KEYREF1\x00pair\x00" + tvVault + "\x00" +
				string(append([]byte{0x04}, rep(0x33, 64)...)) + "\x00" +
				tvNonce + "\x00" + tvDevice + "\x00" +
				"X25519\x00" + string(rep(0x44, SizeX25519Key)) + "\x00" +
				"ed25519\x00" + string(rep(0x55, SizeEd25519Key)) + "\x00" +
				"build-agent-1\x00" + u64hex(2) + "\x00" +
				grant1Str + grant2Str,
		},
		{
			name: "pair-register signs the raw nonce",
			got: mustBuild(t, func() ([]byte, error) {
				return BuildPairRegisterTranscript(pairNonce, "build-agent-1")
			}),
			want: "KEYREF1\x00pair-register\x00" + string(pairNonce) + "\x00build-agent-1",
		},
		{
			name: "session challenge",
			got: mustBuild(t, func() ([]byte, error) {
				return BuildSessionTranscript(tvDevice, rep(0x61, SizeChallenge))
			}),
			want: "KEYREF1\x00session\x00" + tvDevice + "\x00" + string(rep(0x61, SizeChallenge)),
		},
		{
			name: "vault-delete challenge",
			got: mustBuild(t, func() ([]byte, error) {
				return BuildVaultDeleteTranscript(tvVault, rep(0x62, SizeChallenge))
			}),
			want: "KEYREF1\x00vault-delete\x00" + tvVault + "\x00" + string(rep(0x62, SizeChallenge)),
		},
		{
			name: "vault-recovery material",
			got: mustBuild(t, func() ([]byte, error) {
				return BuildVaultRecoveryTranscript(tvVault, []byte{0x99, 0x88},
					`{"v":1,"kdf":"hkdf-sha256"}`, rep(0x77, SizeEd25519Key))
			}),
			want: "KEYREF1\x00vault-recovery\x00" + tvVault + "\x00" +
				"\x99\x88\x00" + `{"v":1,"kdf":"hkdf-sha256"}` + "\x00" +
				string(rep(0x77, SizeEd25519Key)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !bytes.Equal(tt.got, []byte(tt.want)) {
				t.Fatalf("transcript mismatch\n got: %q\nwant: %q", tt.got, tt.want)
			}
		})
	}
}

func mustBuild(t *testing.T, build func() ([]byte, error)) []byte {
	t.Helper()
	b, err := build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return b
}

func TestBuildTranscriptRejectsInvalidInput(t *testing.T) {
	validItem := ItemTranscript{
		VaultID: tvVault, ItemID: tvItem, Revision: 1,
		MetaCiphertext: []byte{1}, SecretCiphertext: []byte{2},
		VaultWrappedMetaKey: []byte{3}, VaultWrappedItemKey: []byte{4},
		WriterDeviceID: tvWriter,
	}
	validGrant := GrantTranscript{
		VaultID: tvVault, DeviceID: tvDevice, ItemID: tvItem,
		Kind: GrantKindUse, Revision: 1, ExpiresAt: 0,
		HPKEEnc: []byte{1}, WrappedKey: []byte{2},
	}
	validDevice := DirectoryDevice{
		DeviceID: tvDevice, Kind: DeviceKindCLI, Status: DeviceStatusActive,
		HPKEKEM: KEMX25519, HPKEPublicKey: rep(1, SizeX25519Key),
		SignAlg: SignAlgEd25519, SignPublicKey: rep(2, SizeEd25519Key),
		GrantsDigest: rep(3, SizeDigest),
	}

	tests := []struct {
		name string
		call func() ([]byte, error)
	}{
		{"item uppercase hex vault", func() ([]byte, error) {
			it := validItem
			it.VaultID = strings.ToUpper(tvVault)
			return BuildItemTranscript(it)
		}},
		{"item short item_id", func() ([]byte, error) {
			it := validItem
			it.ItemID = "abc"
			return BuildItemTranscript(it)
		}},
		{"item revision zero", func() ([]byte, error) {
			it := validItem
			it.Revision = 0
			return BuildItemTranscript(it)
		}},
		{"grant bad kind", func() ([]byte, error) {
			g := validGrant
			g.Kind = "admin"
			return BuildGrantTranscript(g)
		}},
		{"grant enc without wrapped key", func() ([]byte, error) {
			g := validGrant
			g.WrappedKey = nil
			return BuildGrantTranscript(g)
		}},
		{"grant revision zero", func() ([]byte, error) {
			g := validGrant
			g.Revision = 0
			return BuildGrantTranscript(g)
		}},
		{"directory bad status", func() ([]byte, error) {
			d := validDevice
			d.Status = "banned"
			return BuildDirectoryTranscript(DirectoryTranscript{VaultID: tvVault, DirectoryRevision: 1, Devices: []DirectoryDevice{d}})
		}},
		{"directory bad kind", func() ([]byte, error) {
			d := validDevice
			d.Kind = "android"
			return BuildDirectoryTranscript(DirectoryTranscript{VaultID: tvVault, DirectoryRevision: 1, Devices: []DirectoryDevice{d}})
		}},
		{"directory kem/key size mismatch", func() ([]byte, error) {
			d := validDevice
			d.HPKEPublicKey = rep(9, SizeP256Key) // 65 bytes under X25519
			return BuildDirectoryTranscript(DirectoryTranscript{VaultID: tvVault, DirectoryRevision: 1, Devices: []DirectoryDevice{d}})
		}},
		{"directory sign alg/key size mismatch", func() ([]byte, error) {
			d := validDevice
			d.SignPublicKey = rep(9, SizeP256Key) // 65 bytes under ed25519
			return BuildDirectoryTranscript(DirectoryTranscript{VaultID: tvVault, DirectoryRevision: 1, Devices: []DirectoryDevice{d}})
		}},
		{"directory bad renewal key size", func() ([]byte, error) {
			d := validDevice
			d.RenewalSignPublicKey = rep(9, 5)
			return BuildDirectoryTranscript(DirectoryTranscript{VaultID: tvVault, DirectoryRevision: 1, Devices: []DirectoryDevice{d}})
		}},
		{"directory short grants digest", func() ([]byte, error) {
			d := validDevice
			d.GrantsDigest = rep(9, 31)
			return BuildDirectoryTranscript(DirectoryTranscript{VaultID: tvVault, DirectoryRevision: 1, Devices: []DirectoryDevice{d}})
		}},
		{"directory duplicate device", func() ([]byte, error) {
			dup := validDevice
			return BuildDirectoryTranscript(DirectoryTranscript{VaultID: tvVault, DirectoryRevision: 1, Devices: []DirectoryDevice{validDevice, dup}})
		}},
		{"directory revision zero", func() ([]byte, error) {
			return BuildDirectoryTranscript(DirectoryTranscript{VaultID: tvVault, DirectoryRevision: 0, Devices: []DirectoryDevice{validDevice}})
		}},
		{"pair owner key too short", func() ([]byte, error) {
			return BuildPairTranscript(PairTranscript{
				VaultID: tvVault, OwnerSignPublicKey: rep(1, SizeEd25519Key),
				Nonce: tvNonce, DeviceID: tvDevice,
				HPKEKEM: KEMX25519, HPKEPublicKey: rep(2, SizeX25519Key),
				SignAlg: SignAlgEd25519, SignPublicKey: rep(3, SizeEd25519Key),
				Label: "agent",
			})
		}},
		{"pair label too long", func() ([]byte, error) {
			return BuildPairTranscript(PairTranscript{
				VaultID: tvVault, OwnerSignPublicKey: append([]byte{0x04}, rep(1, 64)...),
				Nonce: tvNonce, DeviceID: tvDevice,
				HPKEKEM: KEMX25519, HPKEPublicKey: rep(2, SizeX25519Key),
				SignAlg: SignAlgEd25519, SignPublicKey: rep(3, SizeEd25519Key),
				Label: strings.Repeat("a", LabelNameMaxBytes+1),
			})
		}},
		{"pair grant for other device", func() ([]byte, error) {
			g := validGrant
			g.DeviceID = tvWriter
			return BuildPairTranscript(PairTranscript{
				VaultID: tvVault, OwnerSignPublicKey: append([]byte{0x04}, rep(1, 64)...),
				Nonce: tvNonce, DeviceID: tvDevice,
				HPKEKEM: KEMX25519, HPKEPublicKey: rep(2, SizeX25519Key),
				SignAlg: SignAlgEd25519, SignPublicKey: rep(3, SizeEd25519Key),
				Label: "agent", Grants: []GrantTranscript{g},
			})
		}},
		{"pair-register short nonce", func() ([]byte, error) {
			return BuildPairRegisterTranscript(rep(1, 15), "agent")
		}},
		{"pair-register invalid utf-8 name", func() ([]byte, error) {
			return BuildPairRegisterTranscript(rep(1, SizePairNonce), "\xff\xfe")
		}},
		{"session short challenge", func() ([]byte, error) {
			return BuildSessionTranscript(tvDevice, rep(1, 31))
		}},
		{"session bad device id", func() ([]byte, error) {
			return BuildSessionTranscript("not-hex", rep(1, SizeChallenge))
		}},
		{"vault-delete short challenge", func() ([]byte, error) {
			return BuildVaultDeleteTranscript(tvVault, rep(1, 31))
		}},
		{"vault-recovery short sign pub", func() ([]byte, error) {
			return BuildVaultRecoveryTranscript(tvVault, nil, "{}", rep(1, 31))
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.call()
			if err == nil {
				t.Fatalf("expected error, got transcript %q", b)
			}
			if b != nil {
				t.Fatalf("expected nil transcript alongside error, got %q", b)
			}
		})
	}
}

func TestGrantsDigest(t *testing.T) {
	use := GrantTranscript{
		VaultID: tvVault, DeviceID: tvDevice, ItemID: tvItem,
		Kind: GrantKindUse, Revision: 2, ExpiresAt: 1790000000000,
		HPKEEnc: []byte{0x0a}, WrappedKey: []byte{0x0b},
	}
	view := GrantTranscript{
		VaultID: tvVault, DeviceID: tvDevice, ItemID: tvItem2,
		Kind: GrantKindView, Revision: 1,
		HPKEEnc: []byte{0x1a}, WrappedKey: []byte{0x1b},
	}
	tUse, err := BuildGrantTranscript(use)
	if err != nil {
		t.Fatal(err)
	}
	tView, err := BuildGrantTranscript(view)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("order independent and matches manual concatenation", func(t *testing.T) {
		got1, err := GrantsDigest([]GrantTranscript{view, use})
		if err != nil {
			t.Fatal(err)
		}
		got2, err := GrantsDigest([]GrantTranscript{use, view})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got1, got2) {
			t.Fatal("digest depends on input order")
		}
		h := sha256.New()
		h.Write(tView) // tvItem2 < tvItem
		h.Write(tUse)
		if want := h.Sum(nil); !bytes.Equal(got1, want) {
			t.Fatalf("digest mismatch: got %x want %x", got1, want)
		}
	})

	t.Run("use sorts before view for the same item", func(t *testing.T) {
		useSameItem := GrantTranscript{
			VaultID: tvVault, DeviceID: tvDevice, ItemID: tvItem,
			Kind: GrantKindUse, Revision: 1,
			HPKEEnc: []byte{1}, WrappedKey: []byte{2},
		}
		viewSameItem := useSameItem
		viewSameItem.Kind = GrantKindView
		got, err := GrantsDigest([]GrantTranscript{viewSameItem, useSameItem})
		if err != nil {
			t.Fatal(err)
		}
		tUseSame, err := BuildGrantTranscript(useSameItem)
		if err != nil {
			t.Fatal(err)
		}
		tViewSame, err := BuildGrantTranscript(viewSameItem)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		h.Write(tUseSame)  // "use" sorts before "view" (byte order, protocol D6)
		h.Write(tViewSame) // same item_id, second by kind
		if want := h.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("digest mismatch: got %x want %x", got, want)
		}
	})

	t.Run("empty grant set digests the empty string", func(t *testing.T) {
		got, err := GrantsDigest(nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := sha256.Sum256(nil); !bytes.Equal(got, want[:]) {
			t.Fatalf("got %x want %x", got, want)
		}
	})

	t.Run("changing a grant changes the digest", func(t *testing.T) {
		base, err := GrantsDigest([]GrantTranscript{use, view})
		if err != nil {
			t.Fatal(err)
		}
		bumped := use
		bumped.Revision = 3
		other, err := GrantsDigest([]GrantTranscript{bumped, view})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(base, other) {
			t.Fatal("digest ignored a revision change")
		}
	})

	t.Run("rejects grants of mixed devices", func(t *testing.T) {
		foreign := view
		foreign.DeviceID = tvWriter
		if _, err := GrantsDigest([]GrantTranscript{use, foreign}); err == nil {
			t.Fatal("expected error for grants of two devices")
		}
	})
}

func TestValidID(t *testing.T) {
	valid := []string{
		"00112233445566778899aabbccddeeff",
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
	}
	invalid := []string{
		"",
		"abc",
		strings.ToUpper(tvVault),
		tvVault + "0",
		tvVault[:31],
		"g00112233445566778899aabbccddeef",
	}
	for _, v := range valid {
		if !ValidID(v) {
			t.Errorf("ValidID(%q) = false, want true", v)
		}
	}
	for _, v := range invalid {
		if ValidID(v) {
			t.Errorf("ValidID(%q) = true, want false", v)
		}
	}
}
