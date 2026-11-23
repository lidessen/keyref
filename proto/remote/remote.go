// Package remote defines the hosted account vault wire format.
package remote

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

const (
	Path        = "/v1/remote/"
	MaxSecret   = 64 << 10
	MaxMetadata = 1024
	MaxItems    = 128
	MaxBody     = 256 << 10
)

func ItemID(key []byte, ref string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("keyref-account-item-v1\x00"))
	mac.Write([]byte(ref))
	return hex.EncodeToString(mac.Sum(nil))
}

func CipherKey(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("keyref-account-encryption-v1"))
	return mac.Sum(nil)
}

func ItemAAD(id, field string) []byte {
	return []byte("keyref-account-v1\x00" + field + "\x00" + id)
}

type Device struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type Poll struct {
	DeviceCode string `json:"device_code"`
}

type Session struct {
	Token    string `json:"token"`
	VaultKey []byte `json:"vault_key"`
}

type Item struct {
	ID       string `json:"id"`
	Metadata []byte `json:"metadata"`
	Value    []byte `json:"value,omitempty"`
}

type Metadata struct {
	Description string `json:"description,omitempty"`
	Ref         string `json:"ref"`
	Mask        string `json:"masked"`
	Size        int    `json:"size"`
}
