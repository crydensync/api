// Package anomalyreview records what a human decided about an event
// cryden flagged, and owns the rule about which decisions exist.
//
// It exists because the engine stops one step short of it. cryden
// records that a login tripped anomaly signals, or that one IP sprayed
// many accounts, and it says so in prose: an anomaly event "annotates a
// login that was allowed to proceed, it is never a rejection". What it
// has no concept of is a person having read one — so "we looked at this
// and it was fine" lives here, in this repo's own table
// (migrations/014_reviewed_anomalies.up.sql), keyed on the audit event
// id.
//
// Two properties are the whole design, and both are about not losing
// evidence:
//
//   - A review is a row in this table, never a write to cryden's audit
//     history. The event reads exactly the same before and after
//     somebody dismisses it.
//   - Nothing here deletes. Dismissing sets a status; withdrawing a
//     judgement sets it back to StatusUnreviewed, which is stored rather
//     than represented by a missing row, so the record that someone
//     looked and who they were survives the change of mind.
//
// This is a write, and it is deliberately not in tension with CLAUDE.md's
// read-only rule. That rule is about the AI-assisted tools, which are
// read-only because the interfaces they are built from carry no method
// that can act. This package is not reachable from any of them: it is
// the console's own record of an operator's judgement, the same shape as
// the per-user metadata endpoints beside it.
package anomalyreview

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// The three ways a call here can be refused.
var (
	// ErrNoSuchEvent means there is no audit event with that id, so
	// there is nothing to review. Reported rather than stored, so a
	// console that acted on a stale list is told instead of being shown
	// a success that annotates nothing.
	ErrNoSuchEvent = errors.New("anomalyreview: no audit event with that id")
	// ErrInvalidStatus means the status is not one this api defines.
	ErrInvalidStatus = errors.New("anomalyreview: unknown review status")
	// ErrNoteTooLong means the note is longer than a note needs to be.
	ErrNoteTooLong = errors.New("anomalyreview: note is too long")
)

// Status is one reviewer's judgement about one flagged event.
type Status string

const (
	// StatusUnreviewed is "nobody has called this, or the last call was
	// withdrawn". It is a stored value rather than the absence of a row,
	// which is what lets a withdrawn judgement keep its attribution
	// instead of erasing itself.
	StatusUnreviewed Status = "unreviewed"

	// StatusConfirmed means an operator read the event and judged it a
	// real incident. It records the judgement and nothing else — no
	// action follows from it automatically, because there is nothing in
	// this repo that can act on an account beyond what an operator does
	// by hand.
	StatusConfirmed Status = "confirmed"

	// StatusDismissed means an operator read the event and judged it
	// noise. The event stays exactly where it was; only this table
	// changes.
	StatusDismissed Status = "dismissed"
)

// Statuses returns every status this api defines, in the order a console
// should offer them.
func Statuses() []Status {
	return []Status{StatusUnreviewed, StatusConfirmed, StatusDismissed}
}

// maxNoteLength bounds a note. Bounded because an unbounded free-text
// field on an admin endpoint is a way to fill a table through a form,
// and generous because the point of the field is that an operator can
// explain themselves.
const maxNoteLength = 500

// ValidateStatus is the rule about which decisions exist, in one place.
// Both stores call it before they write, the same discipline
// usermeta.ValidateKey uses: a future caller — a second endpoint, a
// bootstrap command, a migration — goes through a Store and cannot get a
// different answer by not knowing about this function.
//
// It does not trust the CHECK constraint to be the rule. The constraint
// is the backstop that no writer can bypass; this is the version that can
// say which value was wrong and why.
func ValidateStatus(status Status) error {
	switch status {
	case StatusUnreviewed, StatusConfirmed, StatusDismissed:
		return nil
	default:
		return fmt.Errorf("%w: %q must be one of %q, %q or %q",
			ErrInvalidStatus, status, StatusUnreviewed, StatusConfirmed, StatusDismissed)
	}
}

// Review is one recorded decision about one flagged event.
type Review struct {
	// EventID is cryden's audit event id — the primary key here, and the
	// only key the console ever shows an operator.
	EventID string

	Status Status

	// Note is the reviewer's own words. Empty is normal.
	Note string

	// ReviewerID is the operator who made the call, empty when the
	// account behind it has since been deleted (the column is ON DELETE
	// SET NULL). An empty value here therefore means "attributed to an
	// account that no longer exists", never "unattributed" — a review is
	// only ever written by an authenticated operator.
	ReviewerID string

	// UpdatedAt is when this decision replaced the previous one.
	UpdatedAt time.Time
}

// Store is the persistence this package offers. An interface with two
// implementations for the same reason every other store in this repo
// has one: the handlers have to be testable without a database, and a
// double written against the same contract is the only honest way to do
// that.
type Store interface {
	// StatusesFor returns the review of each id in eventIDs that has
	// one. An id with no row is absent from the map, and absent means
	// unreviewed — the same thing a missing row has always meant here.
	//
	// Takes a slice rather than one id because its only caller is a list
	// endpoint annotating a page of events; a per-event call would be
	// one query per row on the busiest read on this surface.
	StatusesFor(ctx context.Context, eventIDs []string) (map[string]Review, error)

	// Set records one decision, creating it or replacing the previous
	// one. Returns the stored review, so a caller can answer with what
	// actually landed rather than with what it hoped would.
	//
	// A status of StatusUnreviewed is a real write, not a delete: it
	// records that this operator withdrew the last judgement, and when.
	Set(ctx context.Context, eventID string, status Status, note, reviewerID string) (Review, error)
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

func (s *PostgresStore) StatusesFor(ctx context.Context, eventIDs []string) (map[string]Review, error) {
	// Short-circuited rather than sent as an empty array: `= ANY('{}')`
	// is a valid query that matches nothing, so this is not a
	// correctness fix, it is a round trip an empty page does not need.
	if len(eventIDs) == 0 {
		return map[string]Review{}, nil
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, status, note, reviewer_id, updated_at
		FROM reviewed_anomalies
		WHERE event_id = ANY($1)
	`, pq.Array(eventIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]Review, len(eventIDs))
	for rows.Next() {
		review, err := scanReview(rows)
		if err != nil {
			return nil, err
		}
		out[review.EventID] = review
	}
	return out, rows.Err()
}

func (s *PostgresStore) Set(ctx context.Context, eventID string, status Status, note, reviewerID string) (Review, error) {
	if err := ValidateStatus(status); err != nil {
		return Review{}, err
	}
	if len(note) > maxNoteLength {
		return Review{}, fmt.Errorf("%w: %d characters, the limit is %d", ErrNoteTooLong, len(note), maxNoteLength)
	}

	// Empty is stored as SQL NULL rather than as an empty uuid, matching
	// cryden's own audit store: "" is not a uuid, and a real NULL is the
	// honest representation of "this account is gone".
	var reviewer sql.NullString
	if reviewerID != "" {
		reviewer = sql.NullString{String: reviewerID, Valid: true}
	}

	// One statement rather than a read-then-write, so two operators
	// deciding on the same event at the same moment cannot lose one of
	// the decisions. RETURNING is what makes the answer the stored row
	// rather than a reconstruction of it.
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO reviewed_anomalies (event_id, status, note, reviewer_id, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (event_id) DO UPDATE
		SET status = EXCLUDED.status, note = EXCLUDED.note,
		    reviewer_id = EXCLUDED.reviewer_id, updated_at = now()
		RETURNING event_id, status, note, reviewer_id, updated_at
	`, eventID, string(status), note, reviewer)

	review, err := scanReview(row)
	if err != nil {
		// The foreign key doing the job this repo cannot do in Go:
		// cryden exposes no lookup-by-event-id, so "does this event
		// exist" is answered by the database refusing the write. A
		// caller reads it as a 404.
		//
		// Note what this does NOT catch: an id that is not a uuid at all
		// fails as an invalid-input-syntax error, not as a foreign-key
		// violation, so it stays a 500 here. That is deliberate — a
		// malformed path segment is refused by looksLikeUUID in the
		// handler, where it is an input-shape question, and reaching
		// Postgres with one is a bug in this repo rather than a bad
		// request.
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == foreignKeyViolation {
			return Review{}, fmt.Errorf("%w: %s", ErrNoSuchEvent, eventID)
		}
		return Review{}, err
	}
	return review, nil
}

// foreignKeyViolation is SQLSTATE 23503, matched by code rather than by
// message — the same reason aiprovider's privilege check matches 42501
// by code: the message is localized and version-dependent, the code is
// specified.
const foreignKeyViolation = "23503"

// rowScanner is the part of *sql.Row and *sql.Rows that scanReview
// needs, so one scan serves both the SELECT and the INSERT ... RETURNING.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanReview(src rowScanner) (Review, error) {
	var (
		review   Review
		status   string
		reviewer sql.NullString
	)
	if err := src.Scan(&review.EventID, &status, &review.Note, &reviewer, &review.UpdatedAt); err != nil {
		return Review{}, err
	}
	review.Status = Status(status)
	if reviewer.Valid {
		review.ReviewerID = reviewer.String
	}
	return review, nil
}
