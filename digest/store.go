// Package digest keeps the history of the reports this deployment's
// weekly digest produced, and runs the schedule that produces them.
//
// # Why this is here and not in the engine
//
// cryden's WeeklyDigest/DigestSince build a report out of the audit table
// and hand back a string. There is no scheduler in the engine, no run
// record, and nothing that remembers a digest was ever generated — that
// is deliberate on cryden's side, because "when should this fire" and
// "where should it be kept" are deployment questions, not authentication
// ones. So the history table, the background job that fills it, and the
// endpoint that reads it back are all this repo's own.
//
// # Read-only, like everything else on the admin surface
//
// GET /v1/admin/digest and GET /v1/admin/digest/history only ever read,
// and neither of them writes a row: the on-demand endpoint deliberately
// does NOT record what it built, so asking for a digest twice does not
// fabricate two entries in a history an operator reads as a record of
// what was scheduled. Only Scheduler writes, and it is a process
// component rather than a request handler — see CLAUDE.md's hard rule.
//
// # The row is the report, not a recipe for one
//
// Text is stored rather than the counts behind it. A digest covers a
// window that has ended, so re-running its query later would not
// reproduce it: "the last seven days" is anchored to when the digest was
// built. Storing what was actually reported is what makes reading a past
// digest the same experience as reading a fresh one.
package digest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Entry is one recorded digest.
type Entry struct {
	// ID is assigned by the store and is zero on the value handed to
	// Insert.
	ID int64

	// WindowStart and WindowEnd bound the report: everything counted
	// happened at or after WindowStart, and WindowEnd is the instant the
	// digest was built. Carried as fields rather than parsed back out of
	// Text, so a listing can sort and describe runs without reading
	// English out of a report.
	WindowStart time.Time
	WindowEnd   time.Time

	// GeneratedAt is when the row was written. Distinct from WindowEnd on
	// purpose: a run replayed after an outage covers a window that closed
	// before the digest was made.
	GeneratedAt time.Time

	// Text is the rendered report, exactly as the engine returned it.
	// Stored verbatim and never re-rendered — this repo does not format
	// cryden's reports, and a copy reformatted here would be a second
	// implementation of a report the engine already owns.
	Text string
}

// Store is the persistence seam. Two implementations: PostgresStore and
// MemoryStore, the in-memory double the tests use — the same split every
// repo-owned store in this repo follows.
type Store interface {
	// Insert records one run and returns it with its assigned ID.
	//
	// Unlike webhook deliveries there is no dedupe and no "already
	// recorded" case: two runs of the same window are two things that
	// happened, and the second one is exactly what an operator wants to
	// see when they suspect the schedule fired twice.
	Insert(ctx context.Context, e Entry) (Entry, error)

	// List returns runs newest first, at most limit of them. Ordered by
	// GeneratedAt with ID as the tiebreak, so the order is total and two
	// runs sharing a timestamp do not swap places between requests.
	List(ctx context.Context, limit int) ([]Entry, error)
}

// ErrNotFound is returned when a run is asked for by an ID that is not
// there. Nothing in this repo reads by ID today — the history is listed,
// never fetched — so this exists for a caller that grows one, and for the
// in-memory double to mean the same thing the Postgres store means.
var ErrNotFound = errors.New("digest run not found")

// DefaultHistoryLimit bounds a history listing that does not ask for a
// size, and MaxHistoryLimit is the ceiling a request may ask for. A
// digest is at most one row per interval — 52 a year on the weekly
// default — so this is a bound against a caller looping with a large
// limit, not against ordinary volume.
const (
	DefaultHistoryLimit = 20
	MaxHistoryLimit     = 200
)

// Columns is one const so the scan and the query cannot drift apart — the
// same reason shiplog's logColumns is one.
const runColumns = `id, window_start, window_end, generated_at, digest_text`

// resolveTimes applies the zero-value rule both stores share: an entry
// that does not carry its own timestamps is stamped by whichever clock
// the store owns, so Postgres stamps with the database host's clock and
// the in-memory double stamps with the test's.
//
// WindowEnd falls back to GeneratedAt rather than to the fallback clock
// directly: the two are the same instant for every run this package
// writes, and deriving one from the other keeps them equal even for a
// caller that supplied only a GeneratedAt.
func resolveTimes(e Entry, fallback time.Time) Entry {
	if e.GeneratedAt.IsZero() {
		e.GeneratedAt = fallback
	}
	if e.WindowEnd.IsZero() {
		e.WindowEnd = e.GeneratedAt
	}
	return e
}

// PostgresStore is the durable Store.
type PostgresStore struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

var _ Store = (*PostgresStore)(nil)

func (s *PostgresStore) Insert(ctx context.Context, e Entry) (Entry, error) {
	e = resolveTimes(e, time.Now().UTC())

	err := s.db.QueryRowContext(ctx,
		`INSERT INTO digest_runs (window_start, window_end, generated_at, digest_text)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id`,
		e.WindowStart, e.WindowEnd, e.GeneratedAt, e.Text,
	).Scan(&e.ID)
	if err != nil {
		return Entry{}, err
	}
	return e, nil
}

func (s *PostgresStore) List(ctx context.Context, limit int) ([]Entry, error) {
	// Clamped inside the store rather than only at the handler, because
	// `LIMIT $1` with a zero returns nothing and with a negative is a
	// Postgres error — so an unclamped store answers a caller that
	// reached it directly with either a broken listing or a driver fault,
	// while the in-memory double would have answered sensibly. Applying
	// the same rule in both is what keeps them the same store.
	limit = ClampLimit(limit)

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+runColumns+`
		   FROM digest_runs
		  ORDER BY generated_at DESC, id DESC
		  LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	runs := make([]Entry, 0, limit)
	for rows.Next() {
		e, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, e)
	}
	return runs, rows.Err()
}

// scanRun reads one row. Kept as a function so the column list and the
// scan order are read together.
func scanRun(rows *sql.Rows) (Entry, error) {
	var e Entry
	if err := rows.Scan(&e.ID, &e.WindowStart, &e.WindowEnd, &e.GeneratedAt, &e.Text); err != nil {
		return Entry{}, fmt.Errorf("scanning a digest run: %w", err)
	}
	return e, nil
}

// ClampLimit narrows a requested history limit into range. Shared by both
// implementations, so the bound is applied in one place rather than
// restated at each of the two.
//
// A non-positive limit means "the default" rather than "none", because
// `LIMIT 0` is a listing that looks broken while a negative limit is a
// driver error — so without this, a caller reaching the store directly
// would get an answer the endpoint would never give.
//
// The endpoint itself does not rely on the clamp: it bounds the parameter
// and answers 400 outside 1..MaxHistoryLimit, so a console asking for
// limit=0 is told its request was wrong rather than handed a default it
// did not ask for (see httpapi's queryInt and the same rule in the logging
// endpoint). This is what a direct caller gets.
func ClampLimit(limit int) int {
	switch {
	case limit <= 0:
		return DefaultHistoryLimit
	case limit > MaxHistoryLimit:
		return MaxHistoryLimit
	default:
		return limit
	}
}
