package settings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PostgresStore is the real store, over migrations/013_settings.up.sql.
// Constructed once in main.go with the same *sql.DB every other store in
// this repo gets.
type PostgresStore struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

var _ Store = (*PostgresStore)(nil)

func (s *PostgresStore) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE key = $1`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (s *PostgresStore) Put(ctx context.Context, key string, value []byte) error {
	// []byte against a BYTEA column is the right pairing, unlike the
	// JSONB columns elsewhere in this repo where a []byte param would be
	// sent as bytea hex and rejected — there, params go as string(raw).
	// Here the column IS bytea, so the driver's default encoding is the
	// one the column wants.
	//
	// The upsert is one statement rather than a SELECT-then-INSERT, so
	// two operators saving the same setting at the same moment cannot
	// lose one of the writes.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
	`, key, value)
	return err
}

func (s *PostgresStore) Delete(ctx context.Context, key string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key = $1`, key)
	if err != nil {
		return err
	}
	// Reported from the statement's own row count rather than a prior
	// SELECT, so "was there one" and "delete it" cannot disagree because
	// another operator deleted it in between.
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	return nil
}

func (s *PostgresStore) Keys(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]string, 0, 8)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}
