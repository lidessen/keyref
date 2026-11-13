package store

import "database/sql"

// Domain row types mirroring the §6.3 schema. All timestamps are Unix
// milliseconds. Ciphertext and key blobs are opaque to the server; the
// server stores and relays them but never decrypts them (design §10.1).

// Vault is a row of the vaults table.
type Vault struct {
	ID                 string // hex vault_id
	CreatedAt          int64
	RecoveryWrap       []byte // AES-256-GCM(recovery-kek, VMK); opaque
	RecoveryKDFJSON    string // KDF descriptor JSON; passed through uninterpreted
	RecoverySignPub    []byte // Ed25519 public key derived from the recovery code
	DirectoryRevision  int64
	DirectorySigned    []byte // owner-signed directory transcript bytes
	DirectorySignature []byte // owner signature over DirectorySigned (schema v2)
	Plan               string // free | plus | unlimited
	PlanExpiresAt      sql.NullInt64
	FrozenAt           sql.NullInt64 // hosted-only idle freeze; NULL on self-hosted
}

// Device is a row of the devices table.
type Device struct {
	ID            string // hex device_id
	VaultID       string
	Kind          string // ios | cli
	Status        string // pending | active | revoked
	HPKEKEM       string // P-256 | X25519
	HPKEPublicKey []byte
	SignAlg       string // ecdsa-p256 | ed25519
	SignPublicKey []byte
	Label         string // plaintext device label shown on other devices
	CreatedAt     int64
	RevokedAt     sql.NullInt64
	PushToken     sql.NullString // APNs token (schema v3); NULL = not registered
	ReceiverRole  int            // 0 none, 1 primary receiver, 2 inbox (schema v5, §14.4)
}

// Item is a row of the items table. Tombstone rows carry NULL
// ciphertext columns; live rows carry opaque AES-256-GCM blobs.
type Item struct {
	VaultID             string
	ItemID              string
	Revision            int64
	Tombstone           bool
	MetaCiphertext      []byte
	SecretCiphertext    []byte
	VaultWrappedMetaKey []byte
	VaultWrappedItemKey []byte
	WriterDeviceID      string
	Signature           []byte // owner ECDSA over the §3.1 transcript
	UpdatedAt           int64
}

// Grant is a row of the grants table. kind view wraps the meta key,
// kind use wraps the item key (design §6.3).
type Grant struct {
	VaultID    string
	DeviceID   string
	ItemID     string
	Kind       string // view | use
	HPKEEnc    []byte
	WrappedKey []byte
	ExpiresAt  sql.NullInt64 // NULL = never expires
	Revision   int64
	Signature  []byte // owner signature over the §3.2 transcript
}

// Approval is a row of the approvals table.
type Approval struct {
	ID                    string // hex approval_id
	VaultID               string
	CLIDeviceID           string
	ItemID                string // item-subject rows; message-subject rows carry the message_id here too (schema v4 keeps the NOT NULL column)
	Subject               string // "item:<item_id>" or "message:<message_id>" (schema v4, protocol D16)
	CLIEphemeralPublicKey []byte // message subjects only: request's one-time X25519 public key (design §14.8); nil for item subjects
	RequestCiphertext     []byte
	RequestSignature      []byte // CLI Ed25519 over the request ciphertext bytes
	Status                string // pending | approved | denied | expired | consumed
	OneTimeWrap           []byte // NULL until the owner approves
	DecisionDeviceID      string // device that signed the decision (kind=ios or kind=decider); "" = none yet (schema v6, design §14.5/§14.8)
	DecisionSignature     []byte // decision device's signature over the approval-decision transcript (schema v7, protocol §3.12)
	ExpiresAt             int64
	CreatedAt             int64
}

// Message is a row of the messages table (design v0.8 §14.3): one SMS
// verification code, end-to-end encrypted to the owner devices and any
// delegated decider. Everything is opaque to the server.
type Message struct {
	VaultID          string
	MessageID        string // hex message_id
	SourceDeviceID   string
	Status           string // active | consumed
	Envelope         []byte // §3.9 envelope
	RequestSignature []byte // source Ed25519 over the upload transcript
	ReceivedAt       int64  // device-reported arrival time; advisory only
	CreatedAt        int64  // server clock; cursor and age-policy basis
	ExpiresAt        int64  // server-stamped: created_at + 24h
}

// AuditEvent is a row of the audit_events table. The ciphertext is
// encrypted to the owner; the server cannot read the body (design §7.7).
type AuditEvent struct {
	VaultID    string
	Seq        int64
	DeviceID   string
	CreatedAt  int64
	Ciphertext []byte
}

// Change is a row of the changes log.
type Change struct {
	Seq       int64
	VaultID   string
	Entity    string // item | grant | device | directory | approval
	EntityID  string // typed entity_id string (protocol §8.2)
	CreatedAt int64
}

// Session is a row of the sessions table. Only the SHA-256 hash of the
// bearer token is stored (design §8.2).
type Session struct {
	TokenHash string // hex SHA-256 of the 32-byte token
	DeviceID  string
	ExpiresAt int64
}

// DailyUsage is a row of the usage_daily table.
type DailyUsage struct {
	VaultID  string
	Day      string // UTC YYYY-MM-DD
	Requests int64
}

// PairSession is a row of the pair_sessions table. Only the SHA-256
// hash of the pairing nonce is stored (protocol §6.16).
type PairSession struct {
	NonceHash     string // hex SHA-256 of the 16-byte nonce
	HPKEPublicKey []byte
	SignPublicKey []byte
	ProposedName  string
	ExpiresAt     int64
	ConsumedAt    sql.NullInt64
	ResultJSON    sql.NullString // §6.18 pairing result (schema v2)
}
