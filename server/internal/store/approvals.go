package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lidessen/keyref/proto/wire"
)

// Approval status-transition errors mapped onto protocol error codes by
// the API layer (§1.3): approval_not_pending for decisions against a row
// that already moved, and the expired status when a pending or approved
// row's deadline has passed.
var (
	ErrApprovalNotPending = errors.New("store: approval is not pending")
	ErrApprovalExpired    = errors.New("store: approval expired")
)

const approvalCols = `approval_id, vault_id, cli_device_id, item_id,
request_ciphertext, request_signature, status, one_time_wrap, expires_at, created_at`

func scanApproval(row interface{ Scan(...any) error }) (*Approval, error) {
	var a Approval
	err := row.Scan(&a.ID, &a.VaultID, &a.CLIDeviceID, &a.ItemID,
		&a.RequestCiphertext, &a.RequestSignature, &a.Status, &a.OneTimeWrap,
		&a.ExpiresAt, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan approval: %w", err)
	}
	return &a, nil
}

// GetApproval loads one approval row; ErrNotFound when absent.
func (s *Store) GetApproval(ctx context.Context, vaultID, approvalID string) (*Approval, error) {
	return scanApproval(s.db.QueryRowContext(ctx,
		`SELECT `+approvalCols+` FROM approvals WHERE approval_id = ? AND vault_id = ?`,
		approvalID, vaultID))
}

// CountApprovalsByStatus counts a vault's approval rows in one status
// (pending count enforces the per-vault ceiling, design §8.3).
func (s *Store) CountApprovalsByStatus(ctx context.Context, vaultID, status string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM approvals WHERE vault_id = ? AND status = ?`,
		vaultID, status).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count approvals: %w", err)
	}
	return n, nil
}

// ListApprovals returns a vault's approval rows, filtered by status when
// status is non-empty, oldest first (the owner's pending queue).
func (s *Store) ListApprovals(ctx context.Context, vaultID, status string) ([]Approval, error) {
	q := `SELECT ` + approvalCols + ` FROM approvals WHERE vault_id = ?`
	args := []any{vaultID}
	if status != "" {
		q += ` AND status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY created_at, approval_id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list approvals: %w", err)
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// InsertApproval stores a freshly verified approval request.
func (s *Store) InsertApproval(ctx context.Context, a *Approval) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO approvals (`+approvalCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.VaultID, a.CLIDeviceID, a.ItemID, a.RequestCiphertext,
		a.RequestSignature, a.Status, a.OneTimeWrap, a.ExpiresAt, a.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: insert approval: %w", err)
	}
	return nil
}

// txAppendApprovalChange records the approval entity change of D8
// (protocol §8.2: a status summary, no ciphertext).
func txAppendApprovalChange(ctx context.Context, tx *sql.Tx, vaultID, approvalID string, at int64) error {
	eid, err := wire.EntityIDApproval(approvalID)
	if err != nil {
		return err
	}
	return txAppendChange(ctx, tx, vaultID, wire.EntityApproval, eid, at)
}

// DecideApproval applies the owner's decision atomically (protocol
// §6.21): only a pending row accepts a decision; an approved decision
// stores the one-time wrap (enc ‖ wrapped, length-prefixed by the
// caller) and sets the 60-second wrap expiry; both paths append the
// approval change.
func (s *Store) DecideApproval(ctx context.Context, vaultID, approvalID string,
	approved bool, oneTimeWrap []byte, expiresAt int64, now int64) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRowContext(ctx,
			`SELECT status FROM approvals WHERE approval_id = ? AND vault_id = ?`,
			approvalID, vaultID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("store: decide approval: read: %w", err)
		}
		if status != wire.ApprovalStatusPending {
			return ErrApprovalNotPending
		}
		newStatus := wire.ApprovalStatusDenied
		if approved {
			newStatus = wire.ApprovalStatusApproved
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE approvals SET status = ?, one_time_wrap = ?, expires_at = ?
WHERE approval_id = ? AND vault_id = ? AND status = ?`,
			newStatus, oneTimeWrap, expiresAt, approvalID, vaultID, wire.ApprovalStatusPending); err != nil {
			return fmt.Errorf("store: decide approval: %w", err)
		}
		return txAppendApprovalChange(ctx, tx, vaultID, approvalID, now)
	})
}

// ExpireApproval flips one pending row to expired and appends the
// change. Rows already moved on return ErrApprovalNotPending.
func (s *Store) ExpireApproval(ctx context.Context, vaultID, approvalID string, now int64) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE approvals SET status = ? WHERE approval_id = ? AND vault_id = ? AND status = ?`,
			wire.ApprovalStatusExpired, approvalID, vaultID, wire.ApprovalStatusPending)
		if err != nil {
			return fmt.Errorf("store: expire approval: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrApprovalNotPending
		}
		return txAppendApprovalChange(ctx, tx, vaultID, approvalID, now)
	})
}

// ConsumeApprovalWrap atomically returns the one-time wrap on the FIRST
// poll that sees status approved, flips the row to consumed and clears
// the wrap bytes (protocol §6.22). An approved row past its 60-second
// wrap window is marked expired instead — the wrap is dead.
func (s *Store) ConsumeApprovalWrap(ctx context.Context, vaultID, approvalID string, now int64) (enc, wrapped []byte, expiresAt int64, err error) {
	err = s.WithTx(ctx, func(tx *sql.Tx) error {
		var status string
		var wrap []byte
		err := tx.QueryRowContext(ctx,
			`SELECT status, one_time_wrap, expires_at FROM approvals
WHERE approval_id = ? AND vault_id = ?`, approvalID, vaultID).Scan(&status, &wrap, &expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("store: consume approval: read: %w", err)
		}
		if status == wire.ApprovalStatusApproved && expiresAt < now {
			// The 60-second window closed before the CLI picked the wrap
			// up: mark it expired and report that.
			if _, err := tx.ExecContext(ctx,
				`UPDATE approvals SET status = ?, one_time_wrap = NULL
WHERE approval_id = ? AND vault_id = ? AND status = ?`,
				wire.ApprovalStatusExpired, approvalID, vaultID, wire.ApprovalStatusApproved); err != nil {
				return fmt.Errorf("store: consume approval: expire: %w", err)
			}
			if err := txAppendApprovalChange(ctx, tx, vaultID, approvalID, now); err != nil {
				return err
			}
			return ErrApprovalExpired
		}
		if status != wire.ApprovalStatusApproved {
			return ErrApprovalNotPending
		}
		enc, wrapped, err = SplitOneTimeWrap(wrap)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE approvals SET status = ?, one_time_wrap = NULL
WHERE approval_id = ? AND vault_id = ? AND status = ?`,
			wire.ApprovalStatusConsumed, approvalID, vaultID, wire.ApprovalStatusApproved)
		if err != nil {
			return fmt.Errorf("store: consume approval: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrApprovalNotPending
		}
		return txAppendApprovalChange(ctx, tx, vaultID, approvalID, now)
	})
	if err != nil {
		return nil, nil, 0, err
	}
	return enc, wrapped, expiresAt, nil
}

// SplitOneTimeWrap splits the stored one_time_wrap blob back into the
// HPKE encapsulation and the ciphertext: u16be enc_len ‖ enc ‖ wrapped.
func SplitOneTimeWrap(wrap []byte) (enc, wrapped []byte, err error) {
	if len(wrap) < 2 {
		return nil, nil, fmt.Errorf("store: one_time_wrap truncated")
	}
	n := int(wrap[0])<<8 | int(wrap[1])
	if 2+n > len(wrap) {
		return nil, nil, fmt.Errorf("store: one_time_wrap truncated")
	}
	return wrap[2 : 2+n], wrap[2+n:], nil
}

// PackOneTimeWrap stores enc ‖ wrapped with a u16be length prefix so the
// two HPKE parts survive the round trip through the single BLOB column.
func PackOneTimeWrap(enc, wrapped []byte) ([]byte, error) {
	if len(enc) > 0xFFFF {
		return nil, fmt.Errorf("store: one_time_enc too long")
	}
	out := make([]byte, 0, 2+len(enc)+len(wrapped))
	out = append(out, byte(len(enc)>>8), byte(len(enc)))
	out = append(out, enc...)
	return append(out, wrapped...), nil
}

// PendingApprovalBytes sums the request ciphertext bytes of pending
// approvals — the "待审批密文" part of the storage quota (design §10.5).
func (s *Store) PendingApprovalBytes(ctx context.Context, vaultID string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(length(request_ciphertext)), 0) FROM approvals
WHERE vault_id = ? AND status = ?`, vaultID, wire.ApprovalStatusPending).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: pending approval bytes: %w", err)
	}
	return n, nil
}
