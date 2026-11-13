package store

import (
	"context"
	"fmt"
)

// SchemaVersion is the schema version stamp kept in PRAGMA user_version.
const SchemaVersion = 7

type migration struct {
	version int
	stmts   []string
}

// migrations holds the forward-only DDL steps applied at startup (design
// §10.4: migrations move forward at startup). Each step runs in a single
// transaction together with its user_version bump; SQLite DDL is
// transactional, so a crashed start either applies a step fully or not
// at all.
//
// v2 additions (registered as a contract-driven schema supplement in the
// segment report): vaults.directory_signature stores the owner signature
// that GET /v1/vaults/:id/recovery and pair/status must return
// (protocol §6.2/§6.18 — the §6.3 base schema has no column for it, and
// ECDSA signatures cannot be recomputed); pair_sessions.result_json
// stores the pairing result that GET /v1/pair/status serves (protocol
// §6.18 — the §6.3 base schema has no nonce→result linkage).
//
// v3 addition: devices.push_token stores the APNs device token an iOS
// device registers for approval notifications (design §8.3 Phase 2;
// PUT /v1/devices/push-token). NULL = push not registered. Directory
// upserts never touch the column, so a re-signed directory cannot
// silently unregister pushes.
var migrations = []migration{
	{
		version: 1,
		stmts: []string{
			`CREATE TABLE vaults (
  vault_id            TEXT PRIMARY KEY,
  created_at          INTEGER NOT NULL,
  recovery_wrap       BLOB,
  recovery_kdf_json   TEXT,
  recovery_sign_pub   BLOB NOT NULL, -- Ed25519 public key derived from the recovery code; verifies takeover transcripts only (design §8.5)
  directory_revision  INTEGER NOT NULL,
  directory_signed    BLOB NOT NULL,
  plan                TEXT NOT NULL DEFAULT 'unlimited', -- free | plus | unlimited
  plan_expires_at     INTEGER,
  frozen_at           INTEGER -- hosted-only idle freeze timestamp; always NULL on self-hosted
)`,
			`CREATE TABLE devices (
  device_id       TEXT PRIMARY KEY,
  vault_id        TEXT NOT NULL,
  kind            TEXT NOT NULL, -- ios | cli
  status          TEXT NOT NULL, -- pending | active | revoked
  hpke_kem        TEXT NOT NULL, -- P-256 | X25519
  hpke_public_key BLOB NOT NULL,
  sign_alg        TEXT NOT NULL, -- ecdsa-p256 | ed25519
  sign_public_key BLOB NOT NULL,
  label           TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  revoked_at      INTEGER
)`,
			`CREATE TABLE items (
  vault_id                 TEXT NOT NULL,
  item_id                  TEXT NOT NULL,
  revision                 INTEGER NOT NULL,
  tombstone                INTEGER NOT NULL,
  meta_ciphertext          BLOB,
  secret_ciphertext        BLOB,
  vault_wrapped_meta_key   BLOB,
  vault_wrapped_item_key   BLOB,
  writer_device_id         TEXT NOT NULL,
  signature                BLOB NOT NULL,
  updated_at               INTEGER NOT NULL,
  PRIMARY KEY (vault_id, item_id)
)`,
			`CREATE TABLE grants (
  vault_id    TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  item_id     TEXT NOT NULL,
  kind        TEXT NOT NULL, -- view | use
  hpke_enc    BLOB NOT NULL,
  wrapped_key BLOB NOT NULL,
  expires_at  INTEGER,
  revision    INTEGER NOT NULL, -- owner-side monotonic, covered by the signed transcript (design §9.1)
  signature   BLOB NOT NULL,
  PRIMARY KEY (vault_id, device_id, item_id, kind)
)`,
			`CREATE TABLE approvals (
  approval_id          TEXT PRIMARY KEY,
  vault_id             TEXT NOT NULL,
  cli_device_id        TEXT NOT NULL,
  item_id              TEXT NOT NULL,
  request_ciphertext   BLOB NOT NULL,
  request_signature    BLOB NOT NULL, -- CLI Ed25519 over the request ciphertext (design §8.3)
  status               TEXT NOT NULL, -- pending | approved | denied | expired | consumed
  one_time_wrap        BLOB,
  expires_at           INTEGER NOT NULL,
  created_at           INTEGER NOT NULL
)`,
			`CREATE TABLE audit_events (
  vault_id    TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  device_id   TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  ciphertext  BLOB NOT NULL,
  PRIMARY KEY (vault_id, seq)
)`,
			`CREATE TABLE changes (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  vault_id   TEXT NOT NULL,
  entity     TEXT NOT NULL,
  entity_id  TEXT NOT NULL,
  created_at INTEGER NOT NULL
)`,
			`CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  device_id  TEXT NOT NULL,
  expires_at INTEGER NOT NULL
)`,
			`CREATE TABLE usage_daily (
  vault_id TEXT NOT NULL,
  day      TEXT NOT NULL, -- UTC YYYY-MM-DD
  requests INTEGER NOT NULL,
  PRIMARY KEY (vault_id, day)
)`,
			`CREATE TABLE pair_sessions (
  nonce_hash      TEXT PRIMARY KEY,
  hpke_public_key BLOB NOT NULL,
  sign_public_key BLOB NOT NULL,
  proposed_name   TEXT NOT NULL,
  expires_at      INTEGER NOT NULL,
  consumed_at     INTEGER
)`,
			// Indexes required by design §6.3 so the single-writer SQLite
			// process never answers these lookups with a table scan.
			`CREATE INDEX idx_changes_vault_seq ON changes (vault_id, seq)`,
			`CREATE INDEX idx_grants_vault_device ON grants (vault_id, device_id)`,
			`CREATE INDEX idx_devices_vault_status ON devices (vault_id, status)`,
			`CREATE INDEX idx_approvals_vault_status ON approvals (vault_id, status)`,
			`CREATE INDEX idx_approvals_cli_status ON approvals (cli_device_id, status)`,
		},
	},
	{
		version: 2,
		stmts: []string{
			`ALTER TABLE vaults ADD COLUMN directory_signature BLOB`,
			`ALTER TABLE pair_sessions ADD COLUMN result_json TEXT`,
		},
	},
	{
		version: 3,
		stmts: []string{
			`ALTER TABLE devices ADD COLUMN push_token TEXT`,
		},
	},
	// v4 additions (design v0.8 §14, protocol v1.2 §5.28–§5.32): the SMS
	// verification-code inbox.
	//
	//   - vaults.delegation_* store the owner-signed auto-approval
	//     delegation policy (§14.8); NULL delegation_signed = no
	//     delegation. The server only verifies and serves the bytes.
	//   - approvals.subject is the D16 subject form ("item:<id>" /
	//     "message:<id>"); item rows are backfilled so old and new rows
	//     read uniformly. The wire keeps the v1.1 item_id field for
	//     item subjects (protocol D16).
	//   - approvals.cli_ephemeral_public_key carries the request's
	//     one-time X25519 public key as plaintext for MESSAGE subjects
	//     only: the decider never decrypts request_ciphertext (design
	//     §14.8). Item approvals keep extracting it from the ciphertext.
	//   - messages holds the encrypted verification-code inbox; messages
	//     deliberately do NOT participate in the changes log (design
	//     §14.3: a 90-day rolling log must not be polluted by 24h rows).
	//   - message_usage_daily counts per-source-device uploads for the
	//     hosted daily ceiling (design §14.7); inert on self-hosted.
	{
		version: 4,
		stmts: []string{
			`ALTER TABLE vaults ADD COLUMN delegation_signed BLOB`,
			`ALTER TABLE vaults ADD COLUMN delegation_signature BLOB`,
			`ALTER TABLE vaults ADD COLUMN delegation_revision INTEGER NOT NULL DEFAULT 0`,
			`ALTER TABLE approvals ADD COLUMN subject TEXT`,
			`UPDATE approvals SET subject = 'item:' || item_id WHERE subject IS NULL`,
			`ALTER TABLE approvals ADD COLUMN cli_ephemeral_public_key BLOB`,
			`CREATE TABLE messages (
  vault_id          TEXT NOT NULL,
  message_id        TEXT NOT NULL,
  source_device_id  TEXT NOT NULL,
  status            TEXT NOT NULL, -- active | consumed (design §14.3)
  envelope          BLOB NOT NULL, -- §3.9 envelope: per-owner/decider wraps + AES blob
  request_signature BLOB NOT NULL, -- source Ed25519 over the message-upload transcript
  received_at       INTEGER NOT NULL, -- device-reported SMS arrival time; advisory
  created_at        INTEGER NOT NULL, -- server clock; cursor + age policy basis
  expires_at        INTEGER NOT NULL  -- server-stamped: created_at + 24h
)`,
			`CREATE INDEX idx_messages_vault_expires ON messages (vault_id, expires_at, status)`,
			`CREATE INDEX idx_messages_vault_device ON messages (vault_id, source_device_id)`,
			`CREATE TABLE message_usage_daily (
  device_id TEXT NOT NULL,
  day       TEXT NOT NULL, -- UTC YYYY-MM-DD
  uploads   INTEGER NOT NULL,
  PRIMARY KEY (device_id, day)
)`,
		},
	},
	{
		// v5 addition (design v0.8 §14.4): devices.receiver_role mirrors
		// the receiver_role byte of the signed directory record (0 none,
		// 1 primary receiver — at most one per vault, 2 inbox). The
		// directory is the authority; this column only serves push
		// targeting (push the primary receiver).
		version: 5,
		stmts: []string{
			`ALTER TABLE devices ADD COLUMN receiver_role INTEGER NOT NULL DEFAULT 0`,
		},
	},
	// v6 addition (design v0.8 §14.5/§14.8, protocol §6.22/D19): the
	// approval row remembers WHICH device signed the decision — the owner
	// (kind=ios) or the delegated decider (kind=decider). The CLI's poll
	// response carries it (absent while pending) so the exec audit event
	// can name the decider. NULL (rows written before v6) or '' = no
	// decision yet; both read as the empty string on the wire.
	{
		version: 6,
		stmts: []string{
			`ALTER TABLE approvals ADD COLUMN decision_device_id TEXT`,
		},
	},
	{
		// v7 addition (protocol v2 B): the decision device's signature
		// over the approval-decision transcript. HPKE base mode has no
		// sender authentication, so without it a malicious server could
		// hand the CLI a wrap it fabricated.
		version: 7,
		stmts: []string{
			`ALTER TABLE approvals ADD COLUMN decision_signature BLOB`,
		},
	},
}

// Migrate applies pending migrations and is idempotent: a database
// already at SchemaVersion is left untouched.
func (s *Store) Migrate(ctx context.Context) error {
	for {
		version, err := s.userVersion(ctx)
		if err != nil {
			return err
		}
		if version >= SchemaVersion {
			return nil
		}
		var m *migration
		for i := range migrations {
			if migrations[i].version == version+1 {
				m = &migrations[i]
				break
			}
		}
		if m == nil {
			return fmt.Errorf("store: no migration from schema version %d", version)
		}
		if err := s.applyMigration(ctx, *m); err != nil {
			return err
		}
	}
}

func (s *Store) userVersion(ctx context.Context) (int, error) {
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("store: read user_version: %w", err)
	}
	return v, nil
}

func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: migration v%d: begin: %w", m.version, err)
	}
	defer tx.Rollback()
	for _, stmt := range m.stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: migration v%d: %w", m.version, err)
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
		return fmt.Errorf("store: migration v%d: stamp user_version: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: migration v%d: commit: %w", m.version, err)
	}
	return nil
}
