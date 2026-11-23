package accountvault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/remote"
)

// Remove the historical command policy without rewriting the secret value
// or discarding any other metadata fields.
func stripCommandPolicy(key []byte, id string, metadata []byte) ([]byte, bool, error) {
	cipherKey := remote.CipherKey(key)
	defer clear(cipherKey)
	aad := remote.ItemAAD(id, "meta")
	raw, err := crypto.OpenBlob(cipherKey, aad, metadata)
	if err != nil {
		return nil, false, err
	}
	defer clear(raw)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, false, errors.New("invalid account item metadata")
	}
	if _, exists := fields["allow_commands"]; !exists {
		return metadata, false, nil
	}
	delete(fields, "allow_commands")
	data, err := json.Marshal(fields)
	if err != nil {
		return nil, false, err
	}
	defer clear(data)
	result, err := crypto.SealBlob(cipherKey, aad, data)
	return result, true, err
}

func (v *Vault) migrateCommandPolicy(ctx context.Context) error {
	var done int
	if err := v.store.DB().QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM account_vault_migrations WHERE name='remove_command_policy')").Scan(&done); err != nil || done != 0 {
		return err
	}
	return v.store.WithTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "INSERT INTO account_vault_migrations VALUES ('remove_command_policy') ON CONFLICT DO NOTHING")
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n == 0 {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT i.account,i.id,i.metadata,v.wrapped_key
			FROM account_items i JOIN account_vaults v ON v.account=i.account`)
		if err != nil {
			return err
		}
		defer rows.Close()
		type update struct {
			account  int64
			id       string
			metadata []byte
		}
		var updates []update
		for rows.Next() {
			var entry update
			var wrapped []byte
			if err := rows.Scan(&entry.account, &entry.id, &entry.metadata, &wrapped); err != nil {
				return err
			}
			key, err := v.unwrapAccountKey(entry.account, wrapped)
			if err != nil {
				return err
			}
			data, changed, err := stripCommandPolicy(key, entry.id, entry.metadata)
			clear(key)
			if err != nil {
				return err
			}
			if changed {
				entry.metadata = data
				updates = append(updates, entry)
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, entry := range updates {
			if _, err := tx.ExecContext(ctx, "UPDATE account_items SET metadata=? WHERE account=? AND id=?", entry.metadata, entry.account, entry.id); err != nil {
				return err
			}
		}
		return nil
	})
}
