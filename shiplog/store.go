// Package shiplog is this repo's implementation of the "shipped events"
// half of cryden's logger seam — the log records a deployment would have
// sent to a hosted aggregator, kept in a table the console can read.
//
// It exists because of the boundary logger's own package doc draws:
// cryden holds a logger.Logger and calls it, and everything that leaves
// the machine belongs to the host app. There is no vendor client in the
// engine and there will not be one. This repo has no vendor client
// either — so "shipped" means "recorded in the log this repo can show an
// operator", the same convention templates/ set for email: a dev
// stand-in for a provider, wired through exactly the seam a real one
// would use, so swapping in a hosted sink later is a change to one line
// of main.go and not to the engine's wiring.
//
// # What lands in the table
//
// The sink sits INSIDE the composition logger's doc comment prescribes:
//
//	logger.NewMultiLogger(
//	    logger.NewConsoleJSONLogger(),                     // full detail, stdout
//	    logger.NewLevelFilter(                             // and the shipped copy
//	        logger.NewMaskingRedactor(shipSink),
//	        level,
//	    ),
//	)
//
// so a row here holds what a vendor would have received — the IP address
// replaced by a marker or a keyed digest, and every record below
// LOG_LEVEL never reaching the sink at all — while stdout keeps the full
// detail that makes an incident debuggable. That placement is the whole
// reason this is a stand-in rather than a second, different log beside
// one: it is the same bytes, minus what would not have left the building.
//
// # The write is synchronous, deliberately
//
// Every record is written on the calling goroutine, which is the request
// path the engine logged from. That is a real cost — one insert per
// record, and a login emits many — and it is not the shape a busy
// deployment wants. It is the shape this one can have: making it
// asynchronous needs a buffer, a flush policy and a shutdown path, and
// this repo has no graceful shutdown anywhere yet (main.go ends at
// log.Fatal(ListenAndServe)). An asynchronous sink whose buffer is never
// flushed is a log that silently drops the last records before a crash,
// which for a log is the failure that matters most. So the honest choice
// is a bounded synchronous write now, and async logging as its own
// change alongside the shutdown path, not smuggled in behind this one.
//
// The level filter in front of the sink is what keeps the volume sane:
// LOG_LEVEL defaults to info and the engine's debug records — the bulk of
// them — never reach here.
//
// # Read-only, like everything else on the admin surface
//
// Nothing here writes through an endpoint. The console reads; whether a
// record should not have been written is a question about a LOG_LEVEL,
// which is configuration, and configuration changes go through the
// settings path like every other one (see CLAUDE.md's hard rule).
package shiplog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/crydensync/cryden/v2/logger"
)

// SinkName is the value recorded in the sink column by the Logger in this
// package. Exported because the admin response reports it back, and a
// console filtering on a string it guessed would be filtering on nothing.
const SinkName = "database"

// Entry is one shipped record.
//
// Fields is a map[string]string rather than anything richer because that
// is exactly what logger.Logger hands over — the engine's own field
// vocabulary is flat and string-valued, and widening it here would be
// this repo inventing a shape the engine does not produce.
type Entry struct {
	ID        int64
	Level     logger.Level
	Message   string
	Fields    map[string]string
	Sink      string
	ShippedAt time.Time
}

// Store is the persistence seam. Two implementations: PostgresStore and
// MemoryStore, the in-memory double the tests use.
type Store interface {
	// Insert records one entry. It is called on the request path, once
	// per log record, so it must be a single statement and must not
	// dedupe or aggregate: two identical records are two things that
	// happened, and a "helpful" unique constraint here would turn a
	// retry loop into one row.
	//
	// A zero ShippedAt is stamped by the store, so a caller that does not
	// care about the timestamp does not have to invent one.
	Insert(ctx context.Context, e Entry) error

	// List returns entries at or above minLevel, newest first, at most
	// limit of them.
	//
	// "At or above" is the same meaning logger.LevelFilter gives the word
	// when it drops records below a threshold — one direction of reading
	// for one word, in one feature. level=warn returning only warnings
	// while the filter above meant "warn and worse" is exactly the kind
	// of second meaning this repo does not want to have.
	List(ctx context.Context, minLevel logger.Level, limit int) ([]Entry, error)
}

var ErrNotFound = errors.New("shipped log event not found")

// levelNames returns the level names at or above min, in ascending order
// of severity. It is what the Postgres query filters on: an index on a
// TEXT level column answers equality, not rank, so the caller passes the
// set rather than asking SQL to compare severities it has no ordering
// for.
//
// min outside the four constants is clamped, which is what everything in
// logger does with a Level. A caller passing garbage therefore gets
// everything rather than an error, and the same clamping in
// logger.ParseLevel is what stops garbage arriving in the first place.
func levelNames(min logger.Level) []string {
	names := make([]string, 0, 4)
	for l := logger.LevelDebug; l <= logger.LevelError; l++ {
		if l >= min {
			names = append(names, l.String())
		}
	}
	return names
}

// Levels returns the four level names, least severe first. Exported for
// the same reason webhook.Statuses is: the admin response lists them so a
// console can offer the filter without keeping a second copy of the
// vocabulary that could drift from this one.
func Levels() []string {
	return levelNames(logger.LevelDebug)
}

// parseLevel reads a level back off a stored row. Our own rows always
// hold one of the four canonical names, so the only way this fails is a
// hand-written row — and failing the whole listing over one of those
// would be a log an operator cannot read because of a typo in a row they
// were trying to inspect. So an unrecognized name is filed at the most
// severe end: it surfaces in every filtered view rather than being
// hideable, and the record is never lost.
//
// logger.ParseLevel's error return is not usable as a fallback here — its
// own doc comment says the value it returns on error is the zero value,
// chosen to be wrong in neither direction precisely because it refuses to
// choose.
func parseLevel(name string) logger.Level {
	l, err := logger.ParseLevel(name)
	if err != nil {
		return logger.LevelError
	}
	return l
}

// resolveShippedAt is the zero-value rule shared by both stores: an entry
// that does not carry a time is stamped by whichever clock the store
// owns, so Postgres uses the database's and the in-memory double uses the
// test's.
func resolveShippedAt(e Entry, fallback time.Time) time.Time {
	if e.ShippedAt.IsZero() {
		return fallback
	}
	return e.ShippedAt
}

// logColumns is one const so the scan and the query cannot drift apart —
// the same reason webhook's deliveryColumns is one.
const logColumns = `id, level, message, fields, sink, shipped_at`

// PostgresStore is the durable Store.
type PostgresStore struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

var _ Store = (*PostgresStore)(nil)

func (s *PostgresStore) Insert(ctx context.Context, e Entry) error {
	// A nil map marshals to the JSON literal "null", which a JSONB column
	// with a NOT NULL constraint accepts happily and a reader then has to
	// treat as a fourth case. Normalized here so the column has one
	// representation of "no fields".
	fields := e.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	// Marshaled, then handed over as a string: a Go []byte goes to lib/pq
	// as bytea hex, which a JSONB column rejects outright. See
	// usermeta/store.go, where the same trap cost the same debugging time.
	raw, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("encoding fields for a %s record: %w", e.Level, err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO shipped_log_events (level, message, fields, sink, shipped_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		e.Level.String(), e.Message, string(raw), sinkOr(e.Sink), resolveShippedAt(e, time.Now().UTC()),
	)
	return err
}

func (s *PostgresStore) List(ctx context.Context, minLevel logger.Level, limit int) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+logColumns+`
		   FROM shipped_log_events
		  WHERE level = ANY($1)
		  ORDER BY shipped_at DESC, id DESC
		  LIMIT $2`,
		pq.Array(levelNames(minLevel)), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]Entry, 0, limit)
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// scanEntry reads one row. Shared with nothing else today, but kept as a
// function so the column list and the scan order are read together.
func scanEntry(rows *sql.Rows) (Entry, error) {
	var (
		e     Entry
		level string
		raw   []byte
	)
	if err := rows.Scan(&e.ID, &level, &e.Message, &raw, &e.Sink, &e.ShippedAt); err != nil {
		return Entry{}, err
	}
	e.Level = parseLevel(level)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &e.Fields); err != nil {
			return Entry{}, fmt.Errorf("decoding fields of shipped log event %d: %w", e.ID, err)
		}
	}
	return e, nil
}

// sinkOr names the sink on an entry that does not name itself, so a row
// written through this package is always attributable to it.
func sinkOr(sink string) string {
	if sink == "" {
		return SinkName
	}
	return sink
}
