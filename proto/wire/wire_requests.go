package wire

// Request and response shapes for the /v1 endpoints (docs/protocol.md
// §6). Kept in the shared proto module so the server and the CLI decode
// and encode the same fields. Pointer fields distinguish "absent" from
// "present but empty" on the two-step endpoints (session, vault delete).

// PoWSolution is the pow object of POST /v1/vaults (protocol §6.1, §10.1).
type PoWSolution struct {
	Challenge Blob `json:"challenge"`
	Nonce     Blob `json:"nonce"` // 8 bytes, u64be
}

// DeviceInput is the structured device object carried by vault creation
// and pair completion (protocol §6.1, §6.17).
type DeviceInput struct {
	DeviceID             string `json:"device_id"`
	Kind                 string `json:"kind"`
	HPKEKEM              string `json:"hpke_kem"`
	HPKEPublicKey        Blob   `json:"hpke_public_key"`
	SignAlg              string `json:"sign_alg"`
	SignPublicKey        Blob   `json:"sign_public_key"`
	Label                string `json:"label,omitempty"`
	RenewalSignPublicKey Blob   `json:"renewal_sign_public_key,omitempty"`
}

// CreateVaultRequest is the body of POST /v1/vaults (protocol §6.1).
type CreateVaultRequest struct {
	VaultID           string       `json:"vault_id"`
	Device            DeviceInput  `json:"device"`
	RecoveryWrap      Blob         `json:"recovery_wrap"`
	RecoveryKDFJSON   string       `json:"recovery_kdf_json"`
	RecoverySignPub   Blob         `json:"recovery_sign_pub"`
	DirectoryRevision uint64       `json:"directory_revision"`
	DirectorySigned   Blob         `json:"directory_signed"`
	Signature         Blob         `json:"signature"`
	PoW               *PoWSolution `json:"pow,omitempty"`
}

// CreateVaultResponse is the 201 body of POST /v1/vaults.
type CreateVaultResponse struct {
	VaultID string `json:"vault_id"`
}

// RecoveryMaterialsResponse is the body of GET /v1/vaults/:vault_id/recovery
// (protocol §6.2).
type RecoveryMaterialsResponse struct {
	VaultID            string `json:"vault_id"`
	RecoveryWrap       Blob   `json:"recovery_wrap"`
	RecoveryKDFJSON    string `json:"recovery_kdf_json"`
	RecoverySignPub    Blob   `json:"recovery_sign_pub"`
	DirectoryRevision  uint64 `json:"directory_revision"`
	DirectorySigned    Blob   `json:"directory_signed"`
	DirectorySignature Blob   `json:"directory_signature"`
}

// RecoveryDirectoryRequest is the body of POST /v1/recovery/directory
// (protocol §6.3): both signatures cover the same §3.3 directory
// transcript bytes.
type RecoveryDirectoryRequest struct {
	VaultID           string `json:"vault_id"`
	DirectoryRevision uint64 `json:"directory_revision"`
	DirectorySigned   Blob   `json:"directory_signed"`
	RecoverySignature Blob   `json:"recovery_signature"`
	OwnerSignature    Blob   `json:"owner_signature"`
}

// PutVaultRecoveryRequest is the body of PUT /v1/vault/recovery
// (protocol §6.4). Signature covers the §3.6 vault-recovery transcript.
type PutVaultRecoveryRequest struct {
	RecoveryWrap    Blob   `json:"recovery_wrap"`
	RecoveryKDFJSON string `json:"recovery_kdf_json"`
	RecoverySignPub Blob   `json:"recovery_sign_pub"`
	Signature       Blob   `json:"signature"`
}

// DeleteVaultRequest is the DELETE /v1/vaults/:vault_id body. Step one
// sends no body at all; step two sends both fields (protocol §6.5).
type DeleteVaultRequest struct {
	Challenge *Blob `json:"challenge,omitempty"`
	Signature *Blob `json:"signature,omitempty"`
}

// SessionRequest is the POST /v1/session body for both steps
// (protocol §6.7). Step one carries only device_id.
type SessionRequest struct {
	DeviceID  string `json:"device_id"`
	Challenge *Blob  `json:"challenge,omitempty"`
	Signature *Blob  `json:"signature,omitempty"`
}

// SessionChallengeResponse is the step-one response (protocol §6.7).
type SessionChallengeResponse struct {
	Challenge Blob  `json:"challenge"`
	ExpiresAt int64 `json:"expires_at"`
}

// PlanLimits is the limits object of session and account responses
// (protocol §6.3, §6.25). Null fields mean "not enforced" (unlimited
// self-hosted deployments).
type PlanLimits struct {
	Items              *int64 `json:"items"`
	DevicesIOS         *int64 `json:"devices_ios"`
	DevicesCLI         *int64 `json:"devices_cli"`
	StorageBytes       *int64 `json:"storage_bytes"`
	AuditRetentionDays *int64 `json:"audit_retention_days"`
	AuditMaxEvents     *int64 `json:"audit_max_events"`
	RequestsPerDay     *int64 `json:"requests_per_day"`
	RequestsPerMinute  *int64 `json:"requests_per_minute"`
}

// SessionResponse is the step-two session body (protocol §6.7) and the
// recovery takeover response (protocol §6.3).
type SessionResponse struct {
	Token     string      `json:"token"`
	ExpiresAt int64       `json:"expires_at"`
	Origin    string      `json:"origin"`
	Plan      string      `json:"plan"`
	Limits    *PlanLimits `json:"limits"`
}

// PutItemRequest is the body of PUT /v1/items/:item_id (protocol §6.10).
// tombstone must be false: deletion goes through DELETE (§6.11).
type PutItemRequest struct {
	Revision            uint64 `json:"revision"`
	Tombstone           bool   `json:"tombstone"`
	MetaCiphertext      Blob   `json:"meta_ciphertext"`
	SecretCiphertext    Blob   `json:"secret_ciphertext"`
	VaultWrappedMetaKey Blob   `json:"vault_wrapped_meta_key"`
	VaultWrappedItemKey Blob   `json:"vault_wrapped_item_key"`
	WriterDeviceID      string `json:"writer_device_id"`
	Signature           Blob   `json:"signature"`
}

// PutItemResponse is the 200 body of PUT /v1/items/:item_id.
type PutItemResponse struct {
	Revision  uint64 `json:"revision"`
	UpdatedAt int64  `json:"updated_at"`
}

// DeleteItemRequest is the body of DELETE /v1/items/:item_id
// (protocol §6.11). The signature covers the §3.1 transcript with four
// zero-length ciphertext fields.
type DeleteItemRequest struct {
	Revision  uint64 `json:"revision"`
	Signature Blob   `json:"signature"`
}

// PutGrantsRequest is the body of PUT /v1/grants (protocol §6.12).
type PutGrantsRequest struct {
	Grants []GrantData `json:"grants"`
}

// PutGrantsResponse is the 200 body of PUT /v1/grants.
type PutGrantsResponse struct {
	Applied int `json:"applied"`
}

// DeleteGrantRequest is the body of DELETE /v1/grants (protocol §6.13).
// The signature covers the §3.2 deletion-form transcript.
type DeleteGrantRequest struct {
	DeviceID  string `json:"device_id"`
	ItemID    string `json:"item_id"`
	Kind      string `json:"kind"`
	Revision  uint64 `json:"revision"`
	Signature Blob   `json:"signature"`
}

// GrantsSelfResponse is the body of GET /v1/grants/self (protocol §6.14).
type GrantsSelfResponse struct {
	Grants            []GrantData `json:"grants"`
	GrantsDigest      Blob        `json:"grants_digest"`
	DirectoryRevision uint64      `json:"directory_revision"`
}

// PutDirectoryRequest is the body of PUT /v1/directory (protocol §6.15).
type PutDirectoryRequest struct {
	DirectoryRevision uint64 `json:"directory_revision"`
	DirectorySigned   Blob   `json:"directory_signed"`
	Signature         Blob   `json:"signature"`
}

// PutDirectoryResponse is the 200 body of PUT /v1/directory.
type PutDirectoryResponse struct {
	DirectoryRevision uint64 `json:"directory_revision"`
}

// PairRegisterRequest is the body of POST /v1/pair/register
// (protocol §6.16). Signature covers the §3.5 pair-register transcript.
type PairRegisterRequest struct {
	Nonce         string `json:"nonce"`
	HPKEKEM       string `json:"hpke_kem"`
	HPKEPublicKey Blob   `json:"hpke_public_key"`
	SignAlg       string `json:"sign_alg"`
	SignPublicKey Blob   `json:"sign_public_key"`
	ProposedName  string `json:"proposed_name"`
	Signature     Blob   `json:"signature"`
}

// PairRegisterResponse is the 201 body of POST /v1/pair/register.
type PairRegisterResponse struct {
	ExpiresAt int64 `json:"expires_at"`
}

// PairCompleteRequest is the body of POST /v1/pair/complete
// (protocol §6.17). Signature covers the §3.4 pair transcript rebuilt
// from these fields.
type PairCompleteRequest struct {
	Nonce     string      `json:"nonce"`
	Device    DeviceInput `json:"device"`
	Grants    []GrantData `json:"grants"`
	Signature Blob        `json:"signature"`
}

// PairStatusResponse is the body of GET /v1/pair/status (protocol §6.18).
type PairStatusResponse struct {
	Status             string      `json:"status"`
	VaultID            string      `json:"vault_id,omitempty"`
	DeviceID           string      `json:"device_id,omitempty"`
	OwnerSignPublicKey Blob        `json:"owner_sign_public_key,omitempty"`
	PairingSignature   Blob        `json:"pairing_signature,omitempty"`
	DirectoryRevision  uint64      `json:"directory_revision,omitempty"`
	DirectorySigned    Blob        `json:"directory_signed,omitempty"`
	DirectorySignature Blob        `json:"directory_signature,omitempty"`
	Grants             []GrantData `json:"grants,omitempty"`
}

// Approval status values carried by the approvals table and the polling
// response (design §6.3, §8.3).
const (
	ApprovalStatusPending  = "pending"
	ApprovalStatusApproved = "approved"
	ApprovalStatusDenied   = "denied"
	ApprovalStatusExpired  = "expired"
	ApprovalStatusConsumed = "consumed"
)

// ApprovalCreateRequest is the body of POST /v1/approvals (protocol
// §6.19). request_ciphertext = HPKE enc ‖ ct (encapsulated to an owner
// device, info purpose=approval-request); request_signature is the CLI
// device's Ed25519 over the raw request_ciphertext bytes.
type ApprovalCreateRequest struct {
	ItemID            string `json:"item_id"`
	RequestCiphertext Blob   `json:"request_ciphertext"`
	RequestSignature  Blob   `json:"request_signature"`
	ExpiresAt         int64  `json:"expires_at"`
}

// ApprovalCreateResponse is the 201 body of POST /v1/approvals.
type ApprovalCreateResponse struct {
	ApprovalID string `json:"approval_id"`
	ExpiresAt  int64  `json:"expires_at"`
}

// ApprovalRow is one entry of GET /v1/approvals (protocol §6.20). The
// owner verifies the CLI signature over request_ciphertext BEFORE
// decrypting and displaying the request (design §8.3).
type ApprovalRow struct {
	ApprovalID        string `json:"approval_id"`
	CLIDeviceID       string `json:"cli_device_id"`
	ItemID            string `json:"item_id"`
	RequestCiphertext Blob   `json:"request_ciphertext"`
	RequestSignature  Blob   `json:"request_signature"`
	CreatedAt         int64  `json:"created_at"`
	ExpiresAt         int64  `json:"expires_at"`
}

// ApprovalListResponse is the body of GET /v1/approvals (protocol §6.20).
type ApprovalListResponse struct {
	Approvals []ApprovalRow `json:"approvals"`
}

// ApprovalDecisionRequest is the body of POST /v1/approvals/:id/decision
// (protocol §6.21). An approved decision carries the one-time HPKE wrap
// of the item key to the request's ephemeral public key (info purpose
// one-time-item-key, binding item, approval and request digest); a
// denied decision carries neither blob.
type ApprovalDecisionRequest struct {
	Decision          string `json:"decision"`
	OneTimeEnc        Blob   `json:"one_time_enc,omitempty"`
	OneTimeWrappedKey Blob   `json:"one_time_wrapped_key,omitempty"`
}

// ApprovalPollResponse is the body of GET /v1/approvals/:approval_id
// (protocol §6.22). The first poll that observes status approved
// atomically returns the one-time wrap and flips the row to consumed.
type ApprovalPollResponse struct {
	ApprovalID        string `json:"approval_id"`
	Status            string `json:"status"`
	OneTimeEnc        Blob   `json:"one_time_enc,omitempty"`
	OneTimeWrappedKey Blob   `json:"one_time_wrapped_key,omitempty"`
	ExpiresAt         int64  `json:"expires_at,omitempty"`
}

// ApprovalStatusData is the sync "approval" entity data (protocol §8.2,
// D8): a status summary for devices related to the approval, without any
// ciphertext.
type ApprovalStatusData struct {
	ApprovalID string `json:"approval_id"`
	Status     string `json:"status"`
}

// AuditRequest is the body of POST /v1/audit (protocol §6.23).
type AuditRequest struct {
	Ciphertext Blob `json:"ciphertext"`
}

// AuditResponse is the 201 body of POST /v1/audit.
type AuditResponse struct {
	Seq int64 `json:"seq"`
}

// AuditEvent is one row of the GET /v1/audit page (protocol §6.24).
type AuditEvent struct {
	Seq        int64  `json:"seq"`
	DeviceID   string `json:"device_id"`
	CreatedAt  int64  `json:"created_at"`
	Ciphertext Blob   `json:"ciphertext"`
}

// AuditPageResponse is the body of GET /v1/audit (protocol §6.24).
type AuditPageResponse struct {
	Events  []AuditEvent `json:"events"`
	Cursor  int64        `json:"cursor"`
	HasMore bool         `json:"has_more"`
}

// AccountResponse is the body of GET /v1/account (protocol §6.25).
type AccountResponse struct {
	Plan          string       `json:"plan"`
	PlanExpiresAt *int64       `json:"plan_expires_at"`
	Limits        *PlanLimits  `json:"limits"`
	Usage         AccountUsage `json:"usage"`
}

// AccountUsage is the usage object of GET /v1/account.
type AccountUsage struct {
	Items         int64 `json:"items"`
	DevicesActive int64 `json:"devices_active"`
	StorageBytes  int64 `json:"storage_bytes"`
	AuditEvents   int64 `json:"audit_events"`
	RequestsToday int64 `json:"requests_today"`
}
