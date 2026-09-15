// Package usermeta stores the per-user metadata that becomes JWT claims,
// and owns the rule about which keys may exist.
//
// It is this repo's own, not cryden's. cryden's store.User has no
// metadata concept on purpose — authorization and app-specific attributes
// are host decisions, the engine owns authentication mechanics — so the
// table (migrations/009_user_metadata.up.sql) and this package exist on
// top of it, keyed off the engine's own user id, the same way
// operator/store.go is.
//
// What the storage is FOR shapes the design: main.go merges every key in
// here into the claims of the access token it issues, so a key is not
// just a label, it is a claim name. That is why values are JSON (a claim
// must marshal), why reserved claim names are refused at write time (a
// key of "sub" would not be ignored at login, it would fail the login),
// and why "role" is refused alongside them (see RoleClaim).
package usermeta

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/crydensync/cryden/v2/token"
)

// The three ways a call here can be refused.
var (
	// ErrReservedKey means the key names a claim that is not this repo's
	// to set.
	ErrReservedKey = errors.New("usermeta: this key is reserved")
	// ErrInvalidKey means the key is not a usable claim name at all.
	ErrInvalidKey = errors.New("usermeta: invalid metadata key")
	// ErrNotFound means there is no such key on that user. Deleting an
	// absent key is reported rather than ignored, so a console that
	// removed the wrong field says so instead of showing success.
	ErrNotFound = errors.New("usermeta: no such metadata key")
)

// RoleClaim is this repo's own authorization claim — the one
// httpapi.RequireAdmin reads to decide whether a caller may use the admin
// console (see middleware.go and main.go's AccessTokenClaims provider).
//
// It is refused as a metadata key, and that is not a technicality. Every
// key in this package is merged into the access token's claims, so
// without this rule setting metadata key "role" to "admin" would mint an
// operator token for a user the operators table has never heard of —
// a second, hidden way to hand out console access that revoking an
// operator (operator.Store.Revoke) would not take away. Anyone who can
// reach the metadata endpoints is already an operator, so this is not an
// escalation across a privilege boundary; it is the removal of a way to
// grant a privilege that nothing else in the system can see.
const RoleClaim = "role"

// maxKeyLength bounds a key. It is a claim name, so it is bounded by
// what a token can reasonably carry rather than by anything in the
// database.
const maxKeyLength = 64

// keyPattern is the shape a metadata key must have. It is deliberately
// stricter than JSON object keys and than Postgres identifiers:
//
//   - It starts with a letter or underscore, so a key can never be
//     mistaken for a number or collide with a JSON literal.
//   - It allows dots, because the csax+ prototype's own metadata
//     references are written "user.metadata.field" and a console
//     exposing that spelling should be able to store it.
//
// The length is spelled inside the pattern rather than checked
// separately so there is one expression to read rather than two places
// the rule lives.
var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// Store is the persistence this package offers. It is an interface with
// two implementations for the same reason cryden keeps store/postgres and
// store/memory apart: the handlers and the claims provider have to be
// testable without a database, and a double that is written against the
// same contract is the only way to test them that way honestly.
type Store interface {
	// AllFor returns every key set on userID. Always non-nil, so a
	// caller can range over it without a nil check and a JSON response
	// renders {} rather than null.
	AllFor(ctx context.Context, userID string) (map[string]any, error)

	// Set creates or replaces one key. The key is validated here, not by
	// the caller — see ValidateKey for why that direction matters.
	Set(ctx context.Context, userID, key string, value any) error

	// Delete removes one key, or returns ErrNotFound. Unlike Set it does
	// not validate the key: see PostgresStore.Delete.
	Delete(ctx context.Context, userID, key string) error
}

// ReservedKeys returns every key Set refuses, sorted: the seven claim
// names from RFC 7519 that cryden will not let a host provider set, plus
// this repo's own RoleClaim.
//
// Exported so GET /v1/admin/users/{id}/metadata can hand the list to a
// console's claim-mapping UI. An operator who can see which names are
// taken does not have to discover the rule by being rejected, and a UI
// that greys them out cannot be the reason someone picks "aud".
func ReservedKeys() []string {
	keys := append(token.ReservedClaimNames(), RoleClaim)
	sort.Strings(keys)
	return keys
}

// ValidateKey is the rule, in one place. Both stores call it before they
// write, which is what makes "the rule lives in the store, not the
// handler" true rather than aspirational: any future caller — a second
// endpoint, a bootstrap command, a migration — goes through a Store and
// gets the same answer, with no way to bypass it by not knowing about it.
func ValidateKey(key string) error {
	if !keyPattern.MatchString(key) {
		return fmt.Errorf("%w: %q must start with a letter or underscore, contain only letters, digits, underscores, dots and dashes, and be at most %d characters",
			ErrInvalidKey, key, maxKeyLength)
	}
	if token.IsReservedClaim(key) {
		return fmt.Errorf("%w: %q is a registered JWT claim name", ErrReservedKey, key)
	}
	if key == RoleClaim {
		return fmt.Errorf("%w: %q is this api's own operator claim", ErrReservedKey, key)
	}
	return nil
}

// PostgresStore is the real store. Constructed once in main.go with the
// same *sql.DB every other store in this repo gets.
type PostgresStore struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

var _ Store = (*PostgresStore)(nil)

func (s *PostgresStore) AllFor(ctx context.Context, userID string) (map[string]any, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT key, value FROM user_metadata WHERE user_id = $1 ORDER BY key`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]any)
	for rows.Next() {
		var (
			key string
			raw []byte
		)
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			// A JSONB column can only hold valid JSON, so this is not a
			// data problem a caller caused — it means the column holds
			// something that did not come through this package.
			return nil, fmt.Errorf("decoding metadata %q: %w", key, err)
		}
		out[key] = value
	}
	return out, rows.Err()
}

func (s *PostgresStore) Set(ctx context.Context, userID, key string, value any) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	raw, err := marshalValue(key, value)
	if err != nil {
		return err
	}
	// raw is passed as a string rather than a []byte, which is not
	// cosmetic: lib/pq sends a []byte as bytea hex, which a JSONB column
	// rejects, while a string arrives as text and Postgres parses it as
	// the jsonb the parameter's target type says it is.
	//
	// The upsert is one statement rather than a SELECT-then-INSERT, so
	// two operators saving the same key at the same moment cannot lose
	// one of the writes.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO user_metadata (user_id, key, value) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
	`, userID, key, string(raw))
	return err
}

func (s *PostgresStore) Delete(ctx context.Context, userID, key string) error {
	// Deliberately NOT validated, unlike Set. Deletion is the one
	// operation that has to keep working on data the current rules would
	// refuse to create: if a name is ever added to the reserved list
	// after rows already exist under it — by a future migration, a
	// direct write, or a relaxed rule — a validating Delete would make
	// those rows permanently unclearable through the API. A key that is
	// not there answers ErrNotFound either way, which is the honest
	// answer for a reserved name that was never stored.
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM user_metadata WHERE user_id = $1 AND key = $2`, userID, key)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	return nil
}

// marshalValue enforces the one contract the storage has to keep: a value
// that cannot be a JWT claim cannot be stored. Both stores marshal, so a
// test double refuses exactly what the real one does.
func marshalValue(key string, value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("the value for %q must be JSON-encodable: %w", key, err)
	}
	return raw, nil
}
