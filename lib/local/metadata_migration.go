package local

import (
	"encoding/json"

	keycrypto "github.com/lidessen/keyref/proto/crypto"
)

// Migrate only encrypted metadata. Preserve missing metadata on pre-meta
// rows and leave value ciphertext and the value write budget untouched.
func (s *Store) migrateCommandPolicy() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 1 {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Take the write reservation before scanning so concurrent openers
	// don't have to upgrade a read transaction while another holds a lock.
	if _, err := tx.Exec("PRAGMA user_version = 1"); err != nil {
		return err
	}
	rows, err := tx.Query("SELECT id, meta FROM entries WHERE length(meta) > 0")
	if err != nil {
		return err
	}
	defer rows.Close()
	type update struct {
		id   string
		blob []byte
	}
	var updates []update
	for rows.Next() {
		var row update
		if err := rows.Scan(&row.id, &row.blob); err != nil {
			return err
		}
		blob, err := s.stripCommandPolicy(row.id, row.blob)
		if err != nil {
			return err
		}
		if blob != nil {
			updates = append(updates, update{row.id, blob})
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, row := range updates {
		if _, err := tx.Exec("UPDATE entries SET meta=? WHERE id=?", row.blob, row.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) stripCommandPolicy(id string, blob []byte) ([]byte, error) {
	aad, err := keycrypto.MetaAAD(s.id, id)
	if err != nil {
		return nil, err
	}
	raw, err := keycrypto.OpenBlob(s.metaKey, aad, blob)
	if err != nil {
		return nil, err
	}
	defer keycrypto.WipeKey(raw)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var policy map[string]json.RawMessage
	if src, ok := fields["policy"]; ok {
		if err := json.Unmarshal(src, &policy); err != nil {
			return nil, err
		}
	}
	if _, exists := policy["allowCommands"]; !exists {
		return nil, nil
	}
	delete(policy, "allowCommands")
	fields["policy"], err = json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	defer keycrypto.WipeKey(data)
	return keycrypto.SealBlob(s.metaKey, aad, data)
}
