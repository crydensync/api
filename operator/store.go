// Package operator answers who may use the admin console.
//
// This is deliberately not part of cryden at all — cryden's own
// store.User has no role or permission concept by design (see
// cryden's docs/design-decisions.md: authorization is a host
// decision, the engine only owns authentication mechanics). Which
// cryden users are console operators, and what role they hold, is a
// decision this api layer makes on top, backed by its own table
// (migrations/003_operators.up.sql) keyed off cryden's own user id.
//
// It is its own package, not a file in package main, so both the
// running server (main.go) and the standalone bootstrap command
// (cmd/grant-operator) can use it without one importing the other's
// package main, which Go does not allow.
package operator

import (
	"context"
	"database/sql"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// RoleFor returns the operator role for userID, and isOperator=false
// if userID holds no row at all — an ordinary end user, the common
// case. Never returns sql.ErrNoRows to the caller; that distinction
// is folded into the bool so callers don't need errors.Is for it.
func (s *Store) RoleFor(ctx context.Context, userID string) (role string, isOperator bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT role FROM operators WHERE user_id = $1`, userID).Scan(&role)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return role, true, nil
}

// Grant makes userID an operator with the given role, or updates their
// existing role — idempotent either way, so re-running a bootstrap
// script is always safe.
func (s *Store) Grant(ctx context.Context, userID, role string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO operators (user_id, role) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role
	`, userID, role)
	return err
}

// Revoke removes userID's operator status entirely. Idempotent —
// revoking someone who was never an operator is not an error.
func (s *Store) Revoke(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM operators WHERE user_id = $1`, userID)
	return err
}
