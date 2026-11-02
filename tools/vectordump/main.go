// Command vectordump generates the deterministic cross-language test
// vectors consumed by the iOS KeyrefCore test suite (docs/protocol.md as
// the byte-level contract; docs/design.md §9.2 "跨语言测试向量").
//
// Everything in the output is deterministic: signing keys are derived
// from fixed scalars/seeds, AES-GCM blobs use fixed nonces, and HPKE
// envelopes use fixed encapsulation seeds (circl's Sender.Setup reads the
// encapsulation seed from the provided io.Reader, so feeding a fixed
// 32-byte seed makes enc/ct reproducible).
//
// The vectors anchor the Swift implementation against the Go reference:
//
//   - Swift opens circl-sealed HPKE envelopes for both KEMs (receiver
//     path: VMK wraps, approval one-time wraps, audit key wraps);
//   - Swift verifies Go-produced signatures over rebuilt transcript
//     bytes, byte-for-byte;
//   - Swift reproduces the info/AAD strings, AEAD blobs, recovery-code
//     encoding and HKDF derivations byte-for-byte;
//   - negative cases assert that wrong AAD / wrong info / tampered
//     transcripts fail closed.
//
// Usage: go run . -out <file>
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/cloudflare/circl/hpke"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"
)

// ---- fixed test identities (all hex below are literal constants) ----

const (
	vaultID      = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	ownerDevID   = "99998888777766665555444433332222"
	cliDevID     = "aaaabbbbccccddddeeeeffff00001111"
	itemID       = "deadbeefdeadbeefdeadbeefdeadbeef"
	otherItemID  = "feedfacefeedfacefeedfacefeedface"
	approvalID   = "1029384756afbcde1029384756afbcde"
	nonceHex     = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a" // 16 raw bytes
	labelCLI     = "build-agent-1"
	kdfJSON      = `{"v":1,"kdf":"hkdf-sha256","salt":"","kek_info":"recovery-kek","sign_info":"recovery-sign"}`
	secretText   = "sk-VECTOR-PLAINTEXT-do-not-use-0000"
	challengeHex = "3132333435363738393031323334353637383930313233343536373839303132"
)

// fixed scalar for the owner ECDSA P-256 signing key (deterministic).
var ownerScalar = mustHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

// fixed seeds / scalars for the HPKE recipients and CLI keys.
var (
	cliX25519Priv  = mustHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	cliEd25519Seed = mustHex("1122334455667788112233445566778811223344556677881122334455667788")
	ownerP256Priv  = mustHex("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
	recoverySeed   = mustHex("c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00")
	vmk            = mustHex("7676767676767676767676767676767676767676767676767676767676767676")
	metaKey        = mustHex("6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d")
	itemKey        = mustHex("6969696969696969696969696969696969696969696969696969696969696969")
	// 32-byte encapsulation seeds: circl Sender.Setup reads exactly this
	// many bytes from its io.Reader (shortKEM/xKEM EncapsulationSeedSize).
	x25519EncapSeed = mustHex("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60")
	p256EncapSeed   = mustHex("6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80")
	// fixed AEAD nonces (12 bytes each)
	nonceAEAD = mustHex("000102030405060708090a0b")
	nonceVWM  = mustHex("0a0b0c0d0e0f101112131415")
	nonceVWI  = mustHex("1a1b1c1d1e1f202122232425")
	nonceRec  = mustHex("2a2b2c2d2e2f303132333435")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// ---- deterministic signing keys ----

func ownerKey() (*ecdsa.PrivateKey, []byte) {
	d := new(big.Int).SetBytes(ownerScalar)
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: d}
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(priv.D.Bytes())
	pub, err := wire.EncodeP256PublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	return priv, pub
}

// sealBlobAEAD produces the §1.5 blob layout nonce(12) ‖ ct ‖ tag with a
// fixed nonce (SealBlob uses a random nonce, so this mirrors it directly
// on the stdlib AEAD).
func sealBlobAEAD(key, aad, nonce, plaintext []byte) []byte {
	if len(key) != 32 || len(nonce) != 12 {
		panic("bad aead inputs")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad)
}

// deterministicHPKE seals with a fixed encapsulation seed.
func deterministicHPKE(kem hpke.KEM, recipientPub, info, seed, plaintext []byte) (enc, ct []byte) {
	pub, err := kem.Scheme().UnmarshalBinaryPublicKey(recipientPub)
	if err != nil {
		panic(err)
	}
	sender, err := hpke.NewSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM).NewSender(pub, info)
	if err != nil {
		panic(err)
	}
	enc, sealer, err := sender.Setup(bytes.NewReader(seed))
	if err != nil {
		panic(err)
	}
	ct, err = sealer.Seal(plaintext, nil)
	if err != nil {
		panic(err)
	}
	return enc, ct
}

// ---- Crockford Base32 (display encoding of the recovery code) ----
//
// The protocol fixes the payload (vault_id ‖ seed, 48 bytes) and the
// alphabet family but not the exact code layout; this tool is the
// reference for the concrete choice: 5-bit groups MSB-first over the
// big-endian payload, 77 symbols (ceil(384/5), the last symbol carries 4
// significant bits, zero-padded), displayed in 5-symbol groups joined by
// '-'. Decoders accept lowercase, strip '-' and spaces, and fold the
// confusable symbols I/L→1 and O→0.
var crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func crockfordEncode(payload []byte) string {
	bits := 0
	acc := 0
	var out []byte
	for _, b := range payload {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, crockfordAlphabet[(acc>>bits)&0x1f])
		}
	}
	if bits > 0 {
		out = append(out, crockfordAlphabet[(acc<<(5-bits))&0x1f])
	}
	var groups []string
	for i := 0; i < len(out); i += 5 {
		end := i + 5
		if end > len(out) {
			end = len(out)
		}
		groups = append(groups, string(out[i:end]))
	}
	return join(groups, "-")
}

func join(parts []string, sep string) string {
	s := ""
	for i, p := range parts {
		if i > 0 {
			s += sep
		}
		s += p
	}
	return s
}

// ---- vector output shapes ----

type kvInput struct {
	Purpose  string `json:"purpose"`
	VaultID  string `json:"vault_id"`
	DeviceID string `json:"recipient_device_id"`
}

type infoVector struct {
	Input    kvInput `json:"input"`
	InfoHex  string  `json:"info_hex"`
}

type oneTimeInfoVector struct {
	VaultID            string `json:"vault_id"`
	RecipientDeviceID  string `json:"recipient_device_id"`
	ItemID             string `json:"item_id"`
	ApprovalID         string `json:"approval_id"`
	RequestCipherHex   string `json:"request_ciphertext_hex"`
	InfoHex            string `json:"info_hex"`
}

type aadVector struct {
	VaultID  string `json:"vault_id"`
	ItemID   string `json:"item_id"`
	DeviceID string `json:"device_id"`
	SecretHex   string `json:"secret_hex"`
	MetaHex     string `json:"meta_hex"`
	VaultMetaHex string `json:"vault_meta_key_hex"`
	VaultItemHex string `json:"vault_item_key_hex"`
	RecoveryHex  string `json:"recovery_hex"`
	AuditHex     string `json:"audit_hex"`
	// negative: decrypting the §3.7 secret blob under another item's AAD
	// (or another vault's) must fail.
	WrongItemHex string `json:"secret_wrong_item_hex"`
	WrongVaultHex string `json:"secret_wrong_vault_hex"`
}

type aeadVector struct {
	KeyHex       string `json:"key_hex"`
	AADHex       string `json:"aad_hex"`
	NonceHex     string `json:"nonce_hex"`
	PlaintextHex string `json:"plaintext_hex"`
	BlobHex      string `json:"blob_hex"`
}

type hpkeVector struct {
	KEMName           string `json:"kem"`
	RecipientPrivHex  string `json:"recipient_private_hex"`
	RecipientPubHex   string `json:"recipient_public_hex"`
	InfoHex           string `json:"info_hex"`
	EncapSeedHex      string `json:"encapsulation_seed_hex"`
	PlaintextHex      string `json:"plaintext_hex"`
	EncHex            string `json:"enc_hex"`
	CTHex             string `json:"ct_hex"`
}

type recoveryVector struct {
	VaultIDHex    string `json:"vault_id_hex"`
	SeedHex       string `json:"seed_hex"`
	Code          string `json:"code"`
	KEKHex        string `json:"kek_hex"`
	SignPublicHex string `json:"sign_public_hex"`
	KDFJSON       string `json:"kdf_json"`
	RecoveryWrapHex string `json:"recovery_wrap_hex"`
	VMKHex        string `json:"vmk_hex"`
	RecoveryAADHex string `json:"recovery_aad_hex"`
}

type grantFields struct {
	DeviceID  string `json:"device_id"`
	ItemID    string `json:"item_id"`
	Kind      string `json:"kind"`
	HPKEEnc   string `json:"hpke_enc"`
	WrappedKey string `json:"wrapped_key"`
	ExpiresAt uint64 `json:"expires_at"`
	Revision  uint64 `json:"revision"`
}

type transcriptVector struct {
	Fields       json.RawMessage `json:"fields"`
	BytesHex     string          `json:"bytes_hex"`
	SignatureHex string          `json:"signature_hex"`
	SignAlg      string          `json:"sign_alg"`
	SignerPubHex string          `json:"signer_public_hex"`
	// a single flipped byte (reported index) must break verification
	TamperedHex  string `json:"tampered_bytes_hex,omitempty"`
	TamperedIdx  int    `json:"tampered_index,omitempty"`
}

type vectors struct {
	Generator string `json:"generator"`

	VaultID   string `json:"vault_id"`
	OwnerDev  string `json:"owner_device_id"`
	CLIDev    string `json:"cli_device_id"`
	ItemID    string `json:"item_id"`
	OtherItem string `json:"other_item_id"`
	ApprovalID string `json:"approval_id"`

	OwnerSignPubHex string `json:"owner_sign_public_hex"`
	CLISignPubHex   string `json:"cli_sign_public_hex"`

	InfoItemKey  infoVector        `json:"info_item_key"`
	InfoOneTime  oneTimeInfoVector `json:"info_one_time"`
	AAD          aadVector         `json:"aad"`
	AEADBlob     aeadVector        `json:"aead_blob"`
	HPKEP256     hpkeVector        `json:"hpke_p256"`
	HPKEX25519   hpkeVector        `json:"hpke_x25519"`
	Recovery     recoveryVector    `json:"recovery"`

	Item          transcriptVector `json:"item_transcript"`
	GrantView     transcriptVector `json:"grant_view_transcript"`
	GrantUse      transcriptVector `json:"grant_use_transcript"`
	GrantDelete   transcriptVector `json:"grant_delete_transcript"`
	Directory     transcriptVector `json:"directory_transcript"`
	Pair          transcriptVector `json:"pair_transcript"`
	PairRegister  transcriptVector `json:"pair_register_transcript"`
	Session       transcriptVector `json:"session_transcript"`
	VaultDelete   transcriptVector `json:"vault_delete_transcript"`
	VaultRecovery transcriptVector `json:"vault_recovery_transcript"`

	// owner ECDSA signature over the session transcript (exercises the
	// owner signer on a §3.6 transcript as the iOS session client does)
	OwnerSessionSigHex string `json:"owner_session_signature_hex"`

	// grants digest of the CLI's two grants (directory record input)
	GrantsDigestHex string `json:"cli_grants_digest_hex"`
	EmptyDigestHex  string `json:"empty_grants_digest_hex"`
}

func tv(fields any, tb []byte, sig []byte, alg, pubHex string, wantTamper bool) transcriptVector {
	v := transcriptVector{
		BytesHex:     hx(tb),
		SignatureHex: hx(sig),
		SignAlg:      alg,
		SignerPubHex: pubHex,
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	v.Fields = raw
	if wantTamper && len(tb) > 0 {
		t := append([]byte(nil), tb...)
		idx := len(t) / 2
		t[idx] ^= 0x01
		// Flipping a byte can, in principle, still verify on ECDSA with
		// negligible probability; Ed25519/ECDSA both fail with overwhelming
		// likelihood. Retry on the next byte in the astronomically unlikely
		// event it verifies.
		for tries := 0; tries < 8; tries++ {
			v.TamperedHex = hx(t)
			v.TamperedIdx = idx
			if !stillVerifies(tb, sig, v.SignAlg, pubHex, t) {
				break
			}
			idx = (idx + 1) % len(t)
			t = append([]byte(nil), tb...)
			t[idx] ^= 0x01
		}
	}
	return v
}

func stillVerifies(orig, sig []byte, alg, pubHex string, tampered []byte) bool {
	pub := mustHex(pubHex)
	return wire.VerifyDeviceSignature(tampered, sig, alg, pub) == nil
}

// sealCheckFile is the input of -check-seal: envelopes produced by the
// Swift side (CryptoKit) that this tool verifies with circl.
type sealCheckFile struct {
	Envelopes []struct {
		KEM              string `json:"kem"`
		RecipientPrivHex string `json:"recipient_private_hex"`
		InfoHex          string `json:"info_hex"`
		EncHex           string `json:"enc_hex"`
		CTHex            string `json:"ct_hex"`
		PlaintextHex     string `json:"plaintext_hex"`
	} `json:"envelopes"`
}

func checkSeal(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var f sealCheckFile
	if err := json.Unmarshal(raw, &f); err != nil {
		panic(err)
	}
	for i, e := range f.Envelopes {
		kem := hpke.KEM_X25519_HKDF_SHA256
		if e.KEM == "P-256" {
			kem = hpke.KEM_P256_HKDF_SHA256
		}
		priv, err := kem.Scheme().UnmarshalBinaryPrivateKey(mustHex(e.RecipientPrivHex))
		if err != nil {
			panic(err)
		}
		receiver, err := hpke.NewSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM).NewReceiver(priv, mustHex(e.InfoHex))
		if err != nil {
			panic(err)
		}
		opener, err := receiver.Setup(mustHex(e.EncHex))
		if err != nil {
			panic(err)
		}
		pt, err := opener.Open(mustHex(e.CTHex), nil)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(pt, mustHex(e.PlaintextHex)) {
			panic(fmt.Sprintf("envelope %d (%s): plaintext mismatch", i, e.KEM))
		}
		fmt.Printf("envelope %d (%s): OK\n", i, e.KEM)
	}
}

func main() {
	out := flag.String("out", "", "output JSON path")
	check := flag.String("check-seal", "", "verify Swift-produced envelopes with circl")
	flag.Parse()
	if *check != "" {
		checkSeal(*check)
		return
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: vectordump -out <file> | -check-seal <file>")
		os.Exit(2)
	}

	ownerPriv, ownerPub := ownerKey()
	cliSeed := cliEd25519Seed
	cliPriv := ed25519.NewKeyFromSeed(cliSeed)
	cliPub := []byte(cliPriv.Public().(ed25519.PublicKey))

	// --- HPKE recipient keys -------------------------------------------------
	xSuite := hpke.KEM_X25519_HKDF_SHA256
	pSuite := hpke.KEM_P256_HKDF_SHA256
	cliXPriv, err := xSuite.Scheme().UnmarshalBinaryPrivateKey(cliX25519Priv)
	if err != nil {
		panic(err)
	}
	cliXPub, err := cliXPriv.Public().MarshalBinary()
	if err != nil {
		panic(err)
	}
	ownerPPriv, err := pSuite.Scheme().UnmarshalBinaryPrivateKey(ownerP256Priv)
	if err != nil {
		panic(err)
	}
	ownerPPub, err := ownerPPriv.Public().MarshalBinary()
	if err != nil {
		panic(err)
	}

	// --- info / AAD ----------------------------------------------------------
	infoItem, err := crypto.Info(crypto.PurposeItemKey, vaultID, cliDevID)
	if err != nil {
		panic(err)
	}
	requestCT := mustHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	infoOneTime, err := crypto.OneTimeItemKeyInfo(vaultID, cliDevID, itemID, approvalID, requestCT)
	if err != nil {
		panic(err)
	}
	aadSecret, err := crypto.SecretAAD(vaultID, itemID)
	if err != nil {
		panic(err)
	}
	aadMeta, err := crypto.MetaAAD(vaultID, itemID)
	if err != nil {
		panic(err)
	}
	aadVWM, err := crypto.VaultWrappedMetaKeyAAD(vaultID, itemID)
	if err != nil {
		panic(err)
	}
	aadVWI, err := crypto.VaultWrappedItemKeyAAD(vaultID, itemID)
	if err != nil {
		panic(err)
	}
	aadRec, err := crypto.RecoveryAAD(vaultID)
	if err != nil {
		panic(err)
	}
	aadAudit, err := crypto.AuditAAD(vaultID, cliDevID)
	if err != nil {
		panic(err)
	}
	aadWrongItem, _ := crypto.SecretAAD(vaultID, otherItemID)
	aadWrongVault, _ := crypto.SecretAAD("00000000000000000000000000000000", itemID)

	// --- AEAD blob -----------------------------------------------------------
	metaJSON := []byte(`{"v":1,"ref":"openai-prod","name":"OpenAI production","description":"vector fixture","type":"api_key","masked":"sk-****abcd","injectable":true,"policy":{"sensitivity":"standard","commandPolicy":"deny-shells","allowCommands":[],"allowedHosts":[],"allowArgv":false}}`)
	secretJSON := []byte(`{"v":1,"value":"` + secretText + `","username":"","notes":"","fields":{}}`)
	blobMeta := sealBlobAEAD(metaKey, aadMeta, nonceAEAD, metaJSON)

	// --- item row ------------------------------------------------------------
	vwMeta := sealBlobAEAD(vmk, aadVWM, nonceVWM, metaKey)
	vwItem := sealBlobAEAD(vmk, aadVWI, nonceVWI, itemKey)
	blobSecret := sealBlobAEAD(itemKey, aadSecret, nonceAEAD, secretJSON)

	// --- grants --------------------------------------------------------------
	// §3.2: a view grant wraps the meta key under purpose meta-key, a use
	// grant wraps the item key under purpose item-key.
	infoMeta, err := crypto.Info(crypto.PurposeMetaKey, vaultID, cliDevID)
	if err != nil {
		panic(err)
	}
	encView, wrapView := deterministicHPKE(xSuite, cliXPub, infoMeta, x25519EncapSeed, metaKey)
	encUse, wrapUse := deterministicHPKE(xSuite, cliXPub, infoItem, x25519EncapSeed, itemKey)

	grantView := wire.GrantTranscript{
		VaultID: vaultID, DeviceID: cliDevID, ItemID: itemID,
		Kind: wire.GrantKindView, Revision: 1, ExpiresAt: 1790000000000,
		HPKEEnc: encView, WrappedKey: wrapView,
	}
	grantUse := wire.GrantTranscript{
		VaultID: vaultID, DeviceID: cliDevID, ItemID: itemID,
		Kind: wire.GrantKindUse, Revision: 1, ExpiresAt: 1790000000000,
		HPKEEnc: encUse, WrappedKey: wrapUse,
	}
	grantDelete := wire.GrantTranscript{
		VaultID: vaultID, DeviceID: cliDevID, ItemID: itemID,
		Kind: wire.GrantKindUse, Revision: 2, ExpiresAt: 0,
	}

	build := func(t any) []byte {
		switch v := t.(type) {
		case wire.ItemTranscript:
			b, err := wire.BuildItemTranscript(v)
			if err != nil {
				panic(err)
			}
			return b
		case wire.GrantTranscript:
			b, err := wire.BuildGrantTranscript(v)
			if err != nil {
				panic(err)
			}
			return b
		case wire.DirectoryTranscript:
			b, err := wire.BuildDirectoryTranscript(v)
			if err != nil {
				panic(err)
			}
			return b
		case wire.PairTranscript:
			b, err := wire.BuildPairTranscript(v)
			if err != nil {
				panic(err)
			}
			return b
		default:
			panic("unhandled")
		}
	}
	signOwner := func(tb []byte) []byte {
		sig, err := wire.SignOwnerECDSA(tb, ownerPriv)
		if err != nil {
			panic(err)
		}
		return sig
	}

	itemTB := build(wire.ItemTranscript{
		VaultID: vaultID, ItemID: itemID, Revision: 4,
		MetaCiphertext: blobMeta, SecretCiphertext: blobSecret,
		VaultWrappedMetaKey: vwMeta, VaultWrappedItemKey: vwItem,
		WriterDeviceID: ownerDevID,
	})
	grantViewTB := build(grantView)
	grantUseTB := build(grantUse)
	grantDeleteTB := build(grantDelete)

	// --- directory -----------------------------------------------------------
	ownerRenewalPub := mustHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	cliDigest, err := wire.GrantsDigest([]wire.GrantTranscript{grantUse, grantView})
	if err != nil {
		panic(err)
	}
	emptyDigest := wire.EmptyGrantsDigest()
	dirTB := build(wire.DirectoryTranscript{
		VaultID: vaultID, DirectoryRevision: 7,
		Devices: []wire.DirectoryDevice{
			{
				DeviceID: cliDevID, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMX25519, HPKEPublicKey: cliXPub,
				SignAlg: wire.SignAlgEd25519, SignPublicKey: cliPub,
				GrantsDigest: cliDigest,
				ReceiverRole: wire.ReceiverRoleNone,
			},
			{
				DeviceID: ownerDevID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMP256, HPKEPublicKey: ownerPPub,
				SignAlg: wire.SignAlgECDSAP256, SignPublicKey: ownerPub,
				RenewalSignPublicKey: ownerRenewalPub,
				GrantsDigest:         emptyDigest,
				ReceiverRole:         wire.ReceiverRolePrimary,
			},
		},
	})

	// --- pair ----------------------------------------------------------------
	pairTB := build(wire.PairTranscript{
		VaultID: vaultID, OwnerSignPublicKey: ownerPub,
		Nonce: nonceHex, DeviceID: cliDevID,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: cliXPub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: cliPub,
		Label: labelCLI,
		Grants: []wire.GrantTranscript{grantView, grantUse},
	})

	pairRegTB, err := wire.BuildPairRegisterTranscript(mustHex(nonceHex), "proposed-name-0")
	if err != nil {
		panic(err)
	}
	pairRegSig := ed25519.Sign(cliPriv, pairRegTB)

	challenge := mustHex(challengeHex)
	sessionTB, err := wire.BuildSessionTranscript(cliDevID, challenge)
	if err != nil {
		panic(err)
	}
	sessionSig := ed25519.Sign(cliPriv, sessionTB)
	ownerSessionSig := signOwner(sessionTB)

	deleteTB, err := wire.BuildVaultDeleteTranscript(vaultID, challenge)
	if err != nil {
		panic(err)
	}

	// --- recovery ------------------------------------------------------------
	kek, recSignPriv, err := crypto.RecoveryKeysFromSeed(recoverySeed)
	if err != nil {
		panic(err)
	}
	recSignPub := []byte(recSignPriv.Public().(ed25519.PublicKey))
	recoveryWrap := sealBlobAEAD(kek, aadRec, nonceRec, vmk)
	recTB, err := wire.BuildVaultRecoveryTranscript(vaultID, recoveryWrap, kdfJSON, recSignPub)
	if err != nil {
		panic(err)
	}
	recSig := signOwner(recTB)
	// the recovery authority signs the same transcript during takeover
	recAuthSig := ed25519.Sign(recSignPriv, recTB)

	v := vectors{
		Generator: "tools/vectordump (circl v1.6.5, proto module, Go stdlib)",
		VaultID:   vaultID, OwnerDev: ownerDevID, CLIDev: cliDevID,
		ItemID: itemID, OtherItem: otherItemID, ApprovalID: approvalID,
		OwnerSignPubHex: hx(ownerPub), CLISignPubHex: hx(cliPub),

		InfoItemKey: infoVector{
			Input:   kvInput{Purpose: crypto.PurposeItemKey, VaultID: vaultID, DeviceID: cliDevID},
			InfoHex: hx(infoItem),
		},
		InfoOneTime: oneTimeInfoVector{
			VaultID: vaultID, RecipientDeviceID: cliDevID,
			ItemID: itemID, ApprovalID: approvalID,
			RequestCipherHex: hx(requestCT), InfoHex: hx(infoOneTime),
		},
		AAD: aadVector{
			VaultID: vaultID, ItemID: itemID, DeviceID: cliDevID,
			SecretHex: hx(aadSecret), MetaHex: hx(aadMeta),
			VaultMetaHex: hx(aadVWM), VaultItemHex: hx(aadVWI),
			RecoveryHex: hx(aadRec), AuditHex: hx(aadAudit),
			WrongItemHex: hx(aadWrongItem), WrongVaultHex: hx(aadWrongVault),
		},
		AEADBlob: aeadVector{
			KeyHex: hx(metaKey), AADHex: hx(aadMeta), NonceHex: hx(nonceAEAD),
			PlaintextHex: hx(metaJSON), BlobHex: hx(blobMeta),
		},
		HPKEX25519: hpkeVector{
			KEMName: "X25519",
			RecipientPrivHex: hx(cliX25519Priv), RecipientPubHex: hx(cliXPub),
			// The use-grant envelope: item-key info wrapping the item key.
			InfoHex: hx(infoItem), EncapSeedHex: hx(x25519EncapSeed),
			PlaintextHex: hx(itemKey), EncHex: hx(encUse), CTHex: hx(wrapUse),
		},
		HPKEP256: hpkeVector{
			KEMName: "P-256",
			RecipientPrivHex: hx(ownerP256Priv), RecipientPubHex: hx(ownerPPub),
			InfoHex: hx(infoOneTime), EncapSeedHex: hx(p256EncapSeed),
			PlaintextHex: hx(itemKey),
		},
		Recovery: recoveryVector{
			VaultIDHex: vaultID, SeedHex: hx(recoverySeed),
			Code:    crockfordEncode(append(mustHex(vaultID), recoverySeed...)),
			KEKHex:  hx(kek), SignPublicHex: hx(recSignPub), KDFJSON: kdfJSON,
			RecoveryWrapHex: hx(recoveryWrap), VMKHex: hx(vmk), RecoveryAADHex: hx(aadRec),
		},
	}

	// HPKE P-256 needs its seal too
	encP, ctP := deterministicHPKE(pSuite, ownerPPub, infoOneTime, p256EncapSeed, itemKey)
	v.HPKEP256.EncHex = hx(encP)
	v.HPKEP256.CTHex = hx(ctP)

	v.Item = tv(struct {
		VaultID             string `json:"vault_id"`
		ItemID              string `json:"item_id"`
		Revision            uint64 `json:"revision"`
		MetaCiphertextHex   string `json:"meta_ciphertext_hex"`
		SecretCiphertextHex string `json:"secret_ciphertext_hex"`
		VaultWrappedMetaHex string `json:"vault_wrapped_meta_key_hex"`
		VaultWrappedItemHex string `json:"vault_wrapped_item_key_hex"`
		WriterDeviceID      string `json:"writer_device_id"`
	}{vaultID, itemID, 4, hx(blobMeta), hx(blobSecret), hx(vwMeta), hx(vwItem), ownerDevID},
		itemTB, signOwner(itemTB), wire.SignAlgECDSAP256, hx(ownerPub), true)

	grantFieldsOf := func(g wire.GrantTranscript) any {
		return grantFields{
			DeviceID: g.DeviceID, ItemID: g.ItemID, Kind: g.Kind,
			HPKEEnc: hx(g.HPKEEnc), WrappedKey: hx(g.WrappedKey),
			ExpiresAt: g.ExpiresAt, Revision: g.Revision,
		}
	}
	v.GrantView = tv(grantFieldsOf(grantView), grantViewTB, signOwner(grantViewTB), wire.SignAlgECDSAP256, hx(ownerPub), true)
	v.GrantUse = tv(grantFieldsOf(grantUse), grantUseTB, signOwner(grantUseTB), wire.SignAlgECDSAP256, hx(ownerPub), false)
	v.GrantDelete = tv(grantFieldsOf(grantDelete), grantDeleteTB, signOwner(grantDeleteTB), wire.SignAlgECDSAP256, hx(ownerPub), false)

	dirFields := struct {
		VaultID            string `json:"vault_id"`
		DirectoryRevision  uint64 `json:"directory_revision"`
		Devices            []dirDeviceFields `json:"devices"`
	}{
		VaultID: vaultID, DirectoryRevision: 7,
		Devices: []dirDeviceFields{
			{DeviceID: cliDevID, Kind: "cli", Status: "active", HPKEKEM: "X25519",
				HPKEPubHex: hx(cliXPub), SignAlg: "ed25519", SignPubHex: hx(cliPub),
				RenewalPubHex: "", GrantsDigestHex: hx(cliDigest), ReceiverRole: 0},
			{DeviceID: ownerDevID, Kind: "ios", Status: "active", HPKEKEM: "P-256",
				HPKEPubHex: hx(ownerPPub), SignAlg: "ecdsa-p256", SignPubHex: hx(ownerPub),
				RenewalPubHex: hx(ownerRenewalPub), GrantsDigestHex: hx(emptyDigest), ReceiverRole: 1},
		},
	}
	v.Directory = tv(dirFields, dirTB, signOwner(dirTB), wire.SignAlgECDSAP256, hx(ownerPub), true)

	pairFields := struct {
		VaultID       string `json:"vault_id"`
		OwnerSignPub  string `json:"owner_sign_public_hex"`
		Nonce         string `json:"nonce"`
		DeviceID      string `json:"device_id"`
		HPKEKEM       string `json:"hpke_kem"`
		HPKEPub       string `json:"hpke_public_key_hex"`
		SignAlg       string `json:"sign_alg"`
		SignPub       string `json:"sign_public_key_hex"`
		Label         string `json:"label"`
		GrantCount    int    `json:"grant_count"`
	}{
		VaultID: vaultID, OwnerSignPub: hx(ownerPub), Nonce: nonceHex,
		DeviceID: cliDevID, HPKEKEM: "X25519", HPKEPub: hx(cliXPub),
		SignAlg: "ed25519", SignPub: hx(cliPub), Label: labelCLI, GrantCount: 2,
	}
	v.Pair = tv(pairFields, pairTB, signOwner(pairTB), wire.SignAlgECDSAP256, hx(ownerPub), false)

	v.PairRegister = tv(struct {
		NonceRawHex  string `json:"nonce_raw_hex"`
		ProposedName string `json:"proposed_name"`
	}{nonceHex, "proposed-name-0"}, pairRegTB, pairRegSig, wire.SignAlgEd25519, hx(cliPub), false)

	v.Session = tv(struct {
		DeviceID     string `json:"device_id"`
		ChallengeHex string `json:"challenge_hex"`
	}{cliDevID, challengeHex}, sessionTB, sessionSig, wire.SignAlgEd25519, hx(cliPub), false)
	v.OwnerSessionSigHex = hx(ownerSessionSig)

	v.VaultDelete = tv(struct {
		VaultID      string `json:"vault_id"`
		ChallengeHex string `json:"challenge_hex"`
	}{vaultID, challengeHex}, deleteTB, signOwner(deleteTB), wire.SignAlgECDSAP256, hx(ownerPub), false)

	v.VaultRecovery = tv(struct {
		VaultID       string `json:"vault_id"`
		RecoveryWrap  string `json:"recovery_wrap_hex"`
		KDFJSON       string `json:"kdf_json"`
		RecoverySignPub string `json:"recovery_sign_pub_hex"`
		// both signatures cover the same bytes (protocol §6.3/D13)
		OwnerSignature    string `json:"owner_signature_hex"`
		RecoverySignature string `json:"recovery_signature_hex"`
	}{vaultID, hx(recoveryWrap), kdfJSON, hx(recSignPub), hx(recSig), hx(recAuthSig)},
		recTB, recSig, wire.SignAlgECDSAP256, hx(ownerPub), true)

	v.GrantsDigestHex = hx(cliDigest)
	v.EmptyDigestHex = hx(emptyDigest)

	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*out, append(raw, '\n'), 0o644); err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
}

type dirDeviceFields struct {
	DeviceID       string `json:"device_id"`
	Kind           string `json:"kind"`
	Status         string `json:"status"`
	HPKEKEM        string `json:"hpke_kem"`
	HPKEPubHex     string `json:"hpke_public_key_hex"`
	SignAlg        string `json:"sign_alg"`
	SignPubHex     string `json:"sign_public_key_hex"`
	RenewalPubHex  string `json:"renewal_sign_public_key_hex"`
	GrantsDigestHex string `json:"grants_digest_hex"`
	ReceiverRole   uint8  `json:"receiver_role"`
}
