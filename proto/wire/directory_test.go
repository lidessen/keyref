package wire

import (
	"bytes"
	"testing"
)

func validDirDevice(id string) DirectoryDevice {
	return DirectoryDevice{
		DeviceID:      id,
		Kind:          DeviceKindCLI,
		Status:        DeviceStatusActive,
		HPKEKEM:       KEMX25519,
		HPKEPublicKey: rep(0x11, SizeX25519Key),
		SignAlg:       SignAlgEd25519,
		SignPublicKey: rep(0x22, SizeEd25519Key),
		GrantsDigest:  rep(0x33, SizeDigest),
	}
}

func TestParseDirectoryRoundTrip(t *testing.T) {
	owner := DirectoryDevice{
		DeviceID:             "0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0",
		Kind:                 DeviceKindIOS,
		Status:               DeviceStatusActive,
		HPKEKEM:              KEMP256,
		HPKEPublicKey:        append([]byte{0x04, 0x00}, rep(0xaa, 63)...), // NUL inside key
		SignAlg:              SignAlgECDSAP256,
		SignPublicKey:        append([]byte{0x04, 0x00}, rep(0xbb, 63)...), // NUL inside key
		RenewalSignPublicKey: append([]byte{0x00}, rep(0xcc, 31)...),       // renewal key starting with NUL
		GrantsDigest:         rep(0xdd, SizeDigest),
	}
	cli := validDirDevice("0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0")
	revoked := validDirDevice("0cccccccccccccccccccccccccccccc0")
	revoked.Status = DeviceStatusRevoked

	// Builders sort by device id; supply unsorted input.
	built, err := BuildDirectoryTranscript(DirectoryTranscript{
		VaultID: tvVault, DirectoryRevision: 9,
		Devices: []DirectoryDevice{revoked, cli, owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDirectoryTranscript(built)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.VaultID != tvVault || parsed.DirectoryRevision != 9 {
		t.Fatalf("header mismatch: %s %d", parsed.VaultID, parsed.DirectoryRevision)
	}
	if len(parsed.Devices) != 3 {
		t.Fatalf("device count = %d, want 3", len(parsed.Devices))
	}
	// Expected sort order: 0aaa < 0bbb < 0ccc.
	wantOrder := []DirectoryDevice{owner, cli, revoked}
	for i, want := range wantOrder {
		got := parsed.Devices[i]
		if got.DeviceID != want.DeviceID || got.Kind != want.Kind || got.Status != want.Status ||
			got.HPKEKEM != want.HPKEKEM || got.SignAlg != want.SignAlg ||
			!bytes.Equal(got.HPKEPublicKey, want.HPKEPublicKey) ||
			!bytes.Equal(got.SignPublicKey, want.SignPublicKey) ||
			!bytes.Equal(got.RenewalSignPublicKey, want.RenewalSignPublicKey) ||
			!bytes.Equal(got.GrantsDigest, want.GrantsDigest) {
			t.Fatalf("device %d mismatch:\n got %+v\nwant %+v", i, got, want)
		}
	}

	keys := parsed.ActiveOwnerSignPublicKeys()
	if len(keys) != 1 || !bytes.Equal(keys[0], owner.SignPublicKey) {
		t.Fatalf("ActiveOwnerSignPublicKeys = %x", keys)
	}
	if _, ok := parsed.Device(cli.DeviceID); !ok {
		t.Fatal("Device lookup failed for present id")
	}
	if _, ok := parsed.Device(tvDevice); ok {
		t.Fatal("Device lookup succeeded for absent id")
	}
}

func TestParseDirectoryEmpty(t *testing.T) {
	built, err := BuildDirectoryTranscript(DirectoryTranscript{
		VaultID: tvVault, DirectoryRevision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDirectoryTranscript(built)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Devices) != 0 {
		t.Fatalf("devices = %d, want 0", len(parsed.Devices))
	}
}

func TestParseDirectoryRejectsMalformed(t *testing.T) {
	good, err := BuildDirectoryTranscript(DirectoryTranscript{
		VaultID: tvVault, DirectoryRevision: 2,
		Devices: []DirectoryDevice{validDirDevice(tvDevice), validDirDevice(tvDevice2)},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Header: "KEYREF1" NUL "directory" NUL vault(32) NUL u64be NUL.
	headerLen := len("KEYREF1\x00directory\x00") + 32 + 1 + 8 + 1
	// Record (validDirDevice): id(32) NUL kind(3) NUL status(6) NUL
	// kem(6) NUL hpke(32) NUL alg(7) NUL sign(32) NUL renewal(0) NUL digest(32).
	recLen := 32 + 3 + 6 + 6 + 32 + 7 + 32 + 0 + 32 + 8
	doubleSep := append([]byte{}, good...)
	doubleSep = append(doubleSep[:headerLen+recLen], append([]byte{0x00}, good[headerLen+recLen:]...)...)

	// A flip inside a binary field (digest/key bytes) must still parse:
	// tamper detection is the signature's job, not the parser's.
	flippedBinary := append([]byte{}, good...)
	flippedBinary[len(good)/2] ^= 0xff
	if _, err := ParseDirectoryTranscript(flippedBinary); err != nil {
		t.Fatalf("flip inside a binary field must not break parsing: %v", err)
	}

	// A flip inside the kind enum text must fail the enum check.
	flippedEnum := append([]byte{}, good...)
	flippedEnum[headerLen+32+1] ^= 0x20 // "cli" -> "Cli"

	tests := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"wrong prefix", []byte("KEYREF2\x00directory\x00" + tvVault)},
		{"wrong kind", []byte("KEYREF1\x00grant\x00" + tvVault)},
		{"truncated header", append([]byte{}, good[:20]...)},
		{"truncated mid record", append([]byte{}, good[:len(good)-10]...)},
		{"trailing separator", append(append([]byte{}, good...), 0x00)},
		{"trailing garbage", append(append([]byte{}, good...), 0x41)},
		{"uppercase vault id", []byte("KEYREF1\x00directory\x00" + "AA" + tvVault[2:] + "\x00\x00\x00\x00\x00\x00\x00\x01\x00")},
		{"double separator between records", doubleSep},
		{"corrupted kind enum", flippedEnum},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseDirectoryTranscript(tt.b); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseDirectoryRejectsBadEnums(t *testing.T) {
	// Hand-build a directory whose device kind is not an enum value.
	rec := "KEYREF1\x00directory\x00" + tvVault + "\x00" + u64hex(1) + "\x00" +
		tvDevice + "\x00android\x00active\x00X25519\x00" +
		string(rep(1, SizeX25519Key)) + "\x00ed25519\x00" +
		string(rep(2, SizeEd25519Key)) + "\x00\x00" + string(rep(3, SizeDigest))
	if _, err := ParseDirectoryTranscript([]byte(rec)); err == nil {
		t.Fatal("expected error for invalid kind enum")
	}
}

func TestEmptyGrantsDigest(t *testing.T) {
	got, err := GrantsDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, EmptyGrantsDigest()) {
		t.Fatal("GrantsDigest(nil) differs from EmptyGrantsDigest")
	}
}
