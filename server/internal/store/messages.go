package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lidessen/keyref/proto/wire"
)

// Message inbox queries (design v0.8 §14, protocol v1.2 §6.28–§6.30).
// Messages are couriered like every other blob: the server stores the
// envelope, never decrypts it, and stamps the fixed TTL itself. Rows
// deliberately do NOT append changes-log entries — the 90-day rolling
// log must not be polluted by 24-hour rows (design §14.3).

const messageCols = `vault_id, message_id, source_device_id, status,
envelope, request_signature, received_at, created_at, expires_at`

// ErrDuplicateEnvelopeTarget: PUT /v1/messages/:id/wraps named a
// decider that already has a record in the envelope (protocol §6.30,
// mapped to revision_conflict by the API layer).
var ErrDuplicateEnvelopeTarget = errors.New("store: duplicate envelope target")

func scanMessage(row interface{ Scan(...any) error }) (*Message, error) {
	var m Message
	err := row.Scan(&m.VaultID, &m.MessageID, &m.SourceDeviceID, &m.Status,
		&m.Envelope, &m.RequestSignature, &m.ReceivedAt, &m.CreatedAt, &m.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan message: %w", err)
	}
	return &m, nil
}

// InsertMessage stores a freshly verified upload.
func (s *Store) InsertMessage(ctx context.Context, m *Message) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO messages (`+messageCols+`) VALUES (?,?,?,?,?,?,?,?,?)`,
		m.VaultID, m.MessageID, m.SourceDeviceID, m.Status,
		m.Envelope, m.RequestSignature, m.ReceivedAt, m.CreatedAt, m.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: insert message: %w", err)
	}
	return nil
}

// GetMessage loads one message row; ErrNotFound when absent.
func (s *Store) GetMessage(ctx context.Context, vaultID, messageID string) (*Message, error) {
	return scanMessage(s.db.QueryRowContext(ctx,
		`SELECT `+messageCols+` FROM messages WHERE vault_id = ? AND message_id = ?`,
		vaultID, messageID))
}

// ListMessagesSince returns the vault's messages newer than the
// `since` cursor (server created_at, ascending), excluding rows that
// have already expired at `now`. Page size is the caller's concern.
func (s *Store) ListMessagesSince(ctx context.Context, vaultID string, since, now int64, limit int) ([]Message, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+messageCols+` FROM messages
WHERE vault_id = ? AND created_at > ? AND expires_at > ?
ORDER BY created_at, message_id LIMIT ?`,
		vaultID, since, now, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list messages: %w", err)
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// DeleteMessage removes one row immediately (the inbox's manual delete,
// design §14.4); ErrNotFound when absent.
func (s *Store) DeleteMessage(ctx context.Context, vaultID, messageID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM messages WHERE vault_id = ? AND message_id = ?`, vaultID, messageID)
	if err != nil {
		return fmt.Errorf("store: delete message: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteExpiredMessages sweeps rows past their TTL — the same lazy
// cleanup class as audit retention (design §10.5). Called
// opportunistically from the read path; the (vault_id, expires_at,
// status) index keeps it cheap.
func (s *Store) DeleteExpiredMessages(ctx context.Context, vaultID string, now int64) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM messages WHERE vault_id = ? AND expires_at <= ?`, vaultID, now)
	if err != nil {
		return fmt.Errorf("store: delete expired messages: %w", err)
	}
	return nil
}

// CountActiveMessagesByDevice counts a source device's active rows for
// the per-device pending ceiling (design §14.7; hosted only).
// Rows already past expires_at do not count.
func (s *Store) CountActiveMessagesByDevice(ctx context.Context, vaultID, deviceID string, now int64) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages WHERE vault_id = ? AND source_device_id = ? AND status = ? AND expires_at > ?`,
		vaultID, deviceID, wire.MessageStatusActive, now).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count active messages: %w", err)
	}
	return n, nil
}

// CountMessageUploads sums a device's uploads for one UTC day (the
// hosted per-device daily ceiling, design §14.7).
func (s *Store) CountMessageUploads(ctx context.Context, deviceID, day string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(uploads), 0) FROM message_usage_daily WHERE device_id = ? AND day = ?`,
		deviceID, day).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count message uploads: %w", err)
	}
	return n, nil
}

// AddMessageUploads accumulates the per-device daily upload counter.
func (s *Store) AddMessageUploads(ctx context.Context, deviceID, day string, n int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO message_usage_daily (device_id, day, uploads) VALUES (?,?,?)
ON CONFLICT (device_id, day) DO UPDATE SET uploads = uploads + excluded.uploads`,
		deviceID, day, n)
	if err != nil {
		return fmt.Errorf("store: add message uploads: %w", err)
	}
	return nil
}

// AppendMessageWraps merges decider backfill records into a stored
// envelope (protocol §6.30, D17). The body blob trails the records, so
// appending is a pure re-encode of (old records + new records) — the
// server never inspects key bytes.
func (s *Store) AppendMessageWraps(ctx context.Context, vaultID, messageID string, records [][]byte, now int64) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		var envelope []byte
		var expiresAt int64
		err := tx.QueryRowContext(ctx,
			`SELECT envelope, expires_at FROM messages WHERE vault_id = ? AND message_id = ?`,
			vaultID, messageID).Scan(&envelope, &expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("store: append message wraps: read: %w", err)
		}
		if expiresAt <= now {
			return ErrNotFound // expired messages accept no new wraps
		}
		merged, err := MergeEnvelopeRecords(envelope, records)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE messages SET envelope = ? WHERE vault_id = ? AND message_id = ?`,
			merged, vaultID, messageID)
		if err != nil {
			return fmt.Errorf("store: append message wraps: %w", err)
		}
		return nil
	})
}

// MergeEnvelopeRecords re-encodes a §3.9 envelope after appending the
// given raw records. Existing and new records are sorted together by
// device_id; duplicates are rejected. The trailing body blob is
// preserved byte-for-byte. The server treats every record as opaque
// except its leading device_id (needed for ordering and dedup).
func MergeEnvelopeRecords(envelope []byte, newRecords [][]byte) ([]byte, error) {
	rec, body, err := splitEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	type entry struct {
		id  string
		raw []byte
	}
	entries := make([]entry, 0, len(rec)+len(newRecords))
	for _, r := range rec {
		id, err := envelopeRecordDevice(r)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{id, r})
	}
	for _, r := range newRecords {
		id, err := envelopeRecordDevice(r)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{id, r})
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[e.id] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateEnvelopeTarget, e.id)
		}
		seen[e.id] = true
	}
	// Sort by device_id ascending (§3.9). Volumes are tiny; an insertion
	// sort keeps the dependency surface at zero.
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].id < entries[j-1].id; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
	if len(entries) > 0xFF {
		return nil, fmt.Errorf("store: too many envelope targets")
	}
	out := make([]byte, 0, len(envelope)+256)
	out = append(out, byte(len(entries)))
	for _, e := range entries {
		out = append(out, e.raw...)
	}
	return append(out, body...), nil
}

// splitEnvelope separates the §3.9 envelope into its record region and
// the trailing body blob.
func splitEnvelope(envelope []byte) (records [][]byte, body []byte, err error) {
	if len(envelope) < 1 {
		return nil, nil, fmt.Errorf("store: envelope truncated")
	}
	n := int(envelope[0])
	p := 1
	records = make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		start := p
		if p+2 > len(envelope) {
			return nil, nil, fmt.Errorf("store: envelope truncated")
		}
		idLen := int(envelope[p])<<8 | int(envelope[p+1])
		p += 2
		if p+idLen+2 > len(envelope) {
			return nil, nil, fmt.Errorf("store: envelope truncated")
		}
		p += idLen
		encLen := int(envelope[p])<<8 | int(envelope[p+1])
		p += 2
		p += encLen + wire.SizeMessageWrappedKey // enc ‖ HPKE ct of the 32B message key
		if p > len(envelope) {
			return nil, nil, fmt.Errorf("store: envelope truncated")
		}
		records = append(records, envelope[start:p])
	}
	return records, envelope[p:], nil
}

// envelopeRecordDevice extracts the device_id of one §3.9 record.
func envelopeRecordDevice(rec []byte) (string, error) {
	if len(rec) < 2+32 {
		return "", fmt.Errorf("store: envelope record truncated")
	}
	idLen := int(rec[0])<<8 | int(rec[1])
	if idLen != 32 || len(rec) < 2+idLen {
		return "", fmt.Errorf("store: envelope record truncated")
	}
	return string(rec[2 : 2+idLen]), nil
}

// MessageEnvelopeBytes sums stored envelope bytes — the message part of
// the storage quota (design §10.5 v0.8 口径).
func (s *Store) MessageEnvelopeBytes(ctx context.Context, vaultID string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(length(envelope)), 0) FROM messages WHERE vault_id = ?`,
		vaultID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: message bytes: %w", err)
	}
	return n, nil
}
