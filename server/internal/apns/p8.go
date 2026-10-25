package apns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseP8Key parses an Apple .p8 provider signing key: a PEM-encoded
// PKCS#8 ECDSA P-256 private key, the format exported from the Apple
// developer console. Standard library only (x509 / crypto/ecdsa).
// SEC1 "EC PRIVATE KEY" blocks are accepted as a courtesy. Any other key
// type or curve is rejected — ES256 provider tokens require P-256.
func ParseP8Key(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("apns: no PEM block in .p8 key")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("apns: parse PKCS#8 key: %w", err)
		}
		k, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("apns: PKCS#8 key is not ECDSA")
		}
		key = k
	case "EC PRIVATE KEY": // SEC1
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("apns: parse SEC1 key: %w", err)
		}
		key = k
	default:
		return nil, fmt.Errorf("apns: unexpected PEM block %q", block.Type)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("apns: key curve is %s, want P-256", key.Curve.Params().Name)
	}
	return key, nil
}
