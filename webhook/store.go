// Package webhook delivers engine events to a host endpoint and keeps a
// queryable record of every delivery.
//
// It exists because cryden deliberately ships no webhook implementation
// (see notify.WebhookSender's own doc comment): the engine surfaces the
// event and knows nothing about an endpoint, a signing scheme or a retry
// policy. Those are all this repo's, along with the table
// (migrations/010_webhook_deliveries.up.sql), which per CLAUDE.md's
// ownership rule is this repo's own infrastructure and not cryden's.
//
// The shape of this package follows from ONE property of how cryden calls
// it: SendWebhook runs SYNCHRONOUSLY on the request path, in the same
// goroutine as the login that triggered it. So:
//
//   - Sender does an INSERT and nothing else. It makes no HTTP call, so a
//     login pays one insert and returns. The database row is the queue; the
//     channel it nudges is only a hint that there is work.
//   - Worker makes the HTTP calls, out of band, with retries and backoff.
//   - Store is what both of them talk to, and is an interface with a
//     Postgres implementation and an in-memory double for the same reason
//     cryden keeps store/postgres and store/memory apart: the worker's
//     claim/backoff/terminal behaviour has to be testable without a
//     database, and a double written against the same contract is the only
//     honest way to do that.
package webhook

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Status is where a delivery has got to. The four values are exhaustive:
// every row is in exactly one of them at all times, which is what makes
// "was that lockout announced?" answerable from this table alone.
type Status string

const (
	// StatusPending is waiting for a worker to pick it up. A row that has
	// failed and is waiting out its backoff is also pending — the difference
	// is next_attempt_at, not the status.
	StatusPending Status = "pending"

	// StatusInFlight has been claimed by a worker that has not resolved it
	// yet. A row left here past the staleness bound is one whose worker
	// stopped mid-delivery, and is reclaimed rather than stranded.
	StatusInFlight Status = "in_flight"

	// StatusDelivered got a 2xx.
	StatusDelivered Status = "delivered"

	// StatusFailed is terminal: either the attempts ran out, or the row was
	// abandoned by a process that died mid-delivery one time too many.
	// Terminal and readable, deliberately — a delivery log that deletes its
	// failures is a delivery log nobody can act on.
	StatusFailed Status = "failed"
)

// Statuses returns every status, in the order a console would offer them
// as filters. Fresh each call so a caller cannot edit the set.
func Statuses() []Status {
	return []Status{StatusPending, StatusInFlight, StatusDelivered, StatusFailed}
}

// ParseStatus validates a status a caller supplied — a query parameter, in
// practice — against the four that exist. Anything else is an error rather
// than being passed through to a query that would return an empty list and
// look like "no deliveries" instead of "no such status".
func ParseStatus(s string) (Status, error) {
	for _, known := range Statuses() {
		if s == string(known) {
			return known, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrInvalidStatus, s)
}

// The two ways a call here can be refused.
var (
	// ErrInvalidStatus means a status filter named something that is not a
	// status.
	ErrInvalidStatus = errors.New("webhook: unknown delivery status")
	// ErrNotFound means there is no such delivery row.
	ErrNotFound = errors.New("webhook: no such delivery")
)

// Delivery is one row: an event this deployment chose to deliver, and
// everything known about the attempt(s) to deliver it.
type Delivery struct {
	// ID is the row's identity and the queue's ordering. See the migration
	// for why this is a surrogate key and not the engine's event id.
	ID int64

	// EventID is the engine's idempotency key for this occurrence, sent to
	// the receiver as X-Cryden-Event-Id. It may be empty: cryden generates
	// it with crypto/rand and, on a generator failure, deliberately
	// delivers the event without one rather than not at all.
	EventID string

	// EventType is the recorded store.AuditEventType as a string, so this
	// package needs no import from the engine's internals.
	EventType string

	// UserID and IP are empty where the event had neither.
	UserID string
	IP     string

	// Payload is the event body exactly as it goes on the wire. The worker
	// sends these bytes unchanged; see the migration for why reading a
	// JSONB column back is byte-exact.
	Payload json.RawMessage

	Status Status

	// Attempts counts attempts STARTED, incremented when a row is claimed
	// rather than when it fails — a process that died mid-delivery still
	// made the attempt, and at-least-once is the only promise a queue can
	// make. It can therefore exceed the configured maximum after a crash;
	// see the migration for why that is preferred to a stranded row.
	Attempts int

	// ResponseCode is the receiver's HTTP status, or 0 where no response
	// was received at all (a connection failure, a timeout, a DNS error).
	// 0 is never a real code, so it is unambiguous as "nothing came back".
	ResponseCode int

	// Error is the failure that was recorded, or empty.
	Error string

	// DurationMS is how long the last attempt took.
	DurationMS int

	CreatedAt     time.Time
	NextAttemptAt time.Time
	ClaimedAt     *time.Time
	DeliveredAt   *time.Time
}

// Result is what a worker learned by making one delivery attempt.
type Result struct {
	// Code is the receiver's HTTP status, 0 if no response arrived.
	Code int
	// Duration is how long the attempt took.
	Duration time.Duration
	// Err is the failure to record, empty on success.
	Err string
}

// Store is the persistence behind both halves of this package. Both
// implementations are expected to keep the same promises, which are not all
// obvious from the signatures:
//
//   - Enqueue never overwrites or dedupes. Two events are two rows, even if
//     the engine handed over the same event id twice.
//   - ClaimDue hands a row to exactly one caller. It is the only place a
//     row goes from pending to in_flight, and it must be safe with several
//     workers running at once — the Postgres one is a single statement
//     using FOR UPDATE SKIP LOCKED for exactly that reason.
//   - ClaimDue has two branches: a pending row that is due and inside its
//     attempt budget, and an in_flight row whose worker went away. The
//     second ignores the budget on purpose, so a crash cannot strand a row
//     that nothing will ever finish or report on.
//   - ClaimDue increments Attempts. That is a write, so a caller must not
//     expect to call it twice for the same claim.
type Store interface {
	// Enqueue records a delivery as pending and immediately due.
	Enqueue(ctx context.Context, d Delivery) error

	// ClaimDue claims up to limit rows that are ready to be attempted:
	// pending and due and under maxAttempts, or in_flight and claimed
	// before now-staleAfter. now is passed in rather than read from the
	// database so the caller's clock is the only clock.
	ClaimDue(ctx context.Context, now time.Time, limit, maxAttempts int, staleAfter time.Duration) ([]Delivery, error)

	// MarkDelivered records a 2xx and makes the row terminal.
	MarkDelivered(ctx context.Context, id int64, r Result) error

	// MarkFailed records a failed attempt. A nil retryAt gives up and makes
	// the row terminal; a non-nil one re-queues it for that time. The
	// caller decides which, because whether the budget is spent is a
	// property of the attempt it just made.
	MarkFailed(ctx context.Context, id int64, r Result, retryAt *time.Time) error

	// List returns deliveries newest first. An empty status means all of
	// them.
	List(ctx context.Context, status Status, limit int) ([]Delivery, error)
}

// PostgresStore is the real store, on the same *sql.DB every other store in
// this repo gets.
type PostgresStore struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

var _ Store = (*PostgresStore)(nil)

// deliveryColumns is the select list and scan order, written once so the
// three reads below cannot drift apart from each other.
const deliveryColumns = `
	id, event_id, event_type, COALESCE(user_id::text, ''), COALESCE(ip, ''),
	payload, status, attempts, COALESCE(response_code, 0), COALESCE(error, ''),
	COALESCE(duration_ms, 0), created_at, next_attempt_at, claimed_at, delivered_at
`

// scanDelivery reads one row in deliveryColumns order. The nullable columns
// are coalesced in SQL rather than handled with sql.Null* here: this repo
// has no use for the distinction between "NULL" and "empty" for any of
// them, and a Scan target that can be NULL crashes the read rather than
// defaulting.
func scanDelivery(row interface{ Scan(...any) error }) (Delivery, error) {
	var d Delivery
	err := row.Scan(
		&d.ID, &d.EventID, &d.EventType, &d.UserID, &d.IP,
		&d.Payload, &d.Status, &d.Attempts, &d.ResponseCode, &d.Error,
		&d.DurationMS, &d.CreatedAt, &d.NextAttemptAt, &d.ClaimedAt, &d.DeliveredAt,
	)
	return d, err
}

func (s *PostgresStore) Enqueue(ctx context.Context, d Delivery) error {
	// The payload is passed as a string, not a []byte, which is not
	// cosmetic: lib/pq sends a []byte as bytea hex, which a JSONB column
	// rejects, while a string arrives as text and Postgres parses it as the
	// jsonb the parameter's target type says it is. Same trap documented in
	// usermeta/store.go.
	//
	// user_id and ip are passed as nil rather than "" when empty, so the
	// columns hold NULL and COALESCE above has something to coalesce. An
	// empty user id is a real case: a failed login naming an email nobody
	// registered has no user behind it.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webhook_deliveries (event_id, event_type, user_id, ip, payload)
		VALUES ($1, $2, $3, $4, $5)
	`, d.EventID, d.EventType, nullIfEmpty(d.UserID), nullIfEmpty(d.IP), string(d.Payload))
	return err
}

// ClaimDue is one statement, which is the point: a read-then-write in Go
// would let two workers claim the same row between the SELECT and the
// UPDATE, and the receiver would get the event twice with only one of them
// recorded. FOR UPDATE SKIP LOCKED is what makes a second worker safe
// rather than merely unlikely to collide.
//
// The two branches are deliberately asymmetric — see the Store doc.
func (s *PostgresStore) ClaimDue(ctx context.Context, now time.Time, limit, maxAttempts int, staleAfter time.Duration) ([]Delivery, error) {
	rows, err := s.db.QueryContext(ctx, `
		UPDATE webhook_deliveries
		   SET status = 'in_flight', claimed_at = $1, attempts = attempts + 1
		 WHERE id IN (
		     SELECT id FROM webhook_deliveries
		      WHERE (status = 'pending' AND attempts < $2 AND next_attempt_at <= $1)
		         OR (status = 'in_flight' AND claimed_at < $3)
		      ORDER BY next_attempt_at
		      LIMIT $4
		      FOR UPDATE SKIP LOCKED
		 )
		 RETURNING `+deliveryColumns,
		now, maxAttempts, now.Add(-staleAfter), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Delivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *PostgresStore) MarkDelivered(ctx context.Context, id int64, r Result) error {
	// The recorded error is cleared: a row that failed twice and then
	// succeeded is delivered, and leaving the last failure next to a
	// delivered status reads as though something is still wrong. The
	// attempts count and the response code tell the story instead.
	res, err := s.db.ExecContext(ctx, `
		UPDATE webhook_deliveries
		   SET status = 'delivered', delivered_at = now(), claimed_at = NULL,
		       response_code = $2, duration_ms = $3, error = NULL
		 WHERE id = $1
	`, id, nullIfZero(r.Code), int(r.Duration.Milliseconds()))
	if err != nil {
		return err
	}
	return mustHaveHit(res, id)
}

func (s *PostgresStore) MarkFailed(ctx context.Context, id int64, r Result, retryAt *time.Time) error {
	// Two statements rather than one with a CASE: the branch is a decision
	// the worker makes about the attempt it just made, and keeping it in Go
	// keeps it readable and testable. Both are still single statements, so
	// neither has a read-modify-write window.
	query := `
		UPDATE webhook_deliveries
		   SET status = 'failed', claimed_at = NULL,
		       response_code = $2, duration_ms = $3, error = $4
		 WHERE id = $1
	`
	args := []any{id, nullIfZero(r.Code), int(r.Duration.Milliseconds()), nullIfEmpty(r.Err)}
	if retryAt != nil {
		query = `
			UPDATE webhook_deliveries
			   SET status = 'pending', claimed_at = NULL, next_attempt_at = $5,
			       response_code = $2, duration_ms = $3, error = $4
			 WHERE id = $1
		`
		args = append(args, *retryAt)
	}

	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	return mustHaveHit(res, id)
}

func (s *PostgresStore) List(ctx context.Context, status Status, limit int) ([]Delivery, error) {
	query := `SELECT ` + deliveryColumns + ` FROM webhook_deliveries`
	args := []any{limit}
	if status != "" {
		// Two statements rather than one with ($1 = '' OR status = $1), so
		// the filtered form can use idx_webhook_deliveries_due instead of
		// scanning the delivered history it is trying to exclude.
		query += ` WHERE status = $1 ORDER BY created_at DESC, id DESC LIMIT $2`
		args = []any{string(status), limit}
	} else {
		query += ` ORDER BY created_at DESC, id DESC LIMIT $1`
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Delivery, 0, limit)
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// mustHaveHit turns "the UPDATE matched no row" into ErrNotFound. A worker
// marking a row that is not there is not a normal case — it means the row
// was deleted underneath it — and reporting it keeps that visible rather
// than letting the worker believe it resolved something.
func mustHaveHit(res sql.Result, id int64) error {
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("%w: id %d", ErrNotFound, id)
	}
	return nil
}

// nullIfEmpty maps an empty string to a SQL NULL, and anything else
// through unchanged. Returned as any so it can be passed straight as a
// parameter.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullIfZero maps a zero to a SQL NULL. Used for response_code, where 0
// means "no response arrived" and a stored 0 would read as a real code.
func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
