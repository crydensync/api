package shiplog

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/logger"
)

// newTestStore is a store whose clock a test moves by hand, so a listing's
// ordering is decided rather than hoped for.
func newTestStore() (*MemoryStore, *testClock) {
	clock := &testClock{t: time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)}
	store := NewMemoryStore()
	store.Clock = clock.now
	return store, clock
}

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func insert(t *testing.T, store Store, level logger.Level, message string) {
	t.Helper()
	if err := store.Insert(context.Background(), Entry{Level: level, Message: message}); err != nil {
		t.Fatalf("Insert(%q): %v", message, err)
	}
}

// "At or above" is the same direction logger.LevelFilter reads the word,
// and the two have to agree: a sink that shipped warn-and-worse while the
// listing answered "exactly warn" would be a filter whose meaning depended
// on which end you were standing at.
func TestListMeansAtOrAbove(t *testing.T) {
	store, _ := newTestStore()
	for _, level := range []logger.Level{logger.LevelDebug, logger.LevelInfo, logger.LevelWarn, logger.LevelError} {
		insert(t, store, level, level.String())
	}

	for _, tc := range []struct {
		min  logger.Level
		want []string
	}{
		{logger.LevelDebug, []string{"debug", "info", "warn", "error"}},
		{logger.LevelInfo, []string{"info", "warn", "error"}},
		{logger.LevelWarn, []string{"warn", "error"}},
		{logger.LevelError, []string{"error"}},
	} {
		rows, err := store.List(context.Background(), tc.min, 10)
		if err != nil {
			t.Fatalf("List(%s): %v", tc.min, err)
		}
		if len(rows) != len(tc.want) {
			t.Errorf("List(%s) returned %d rows, want %d", tc.min, len(rows), len(tc.want))
			continue
		}
		for i, name := range tc.want {
			// Newest first, and the inserts above happened in ascending
			// severity, so the expected order is reversed.
			if got := rows[len(rows)-1-i].Message; got != name {
				t.Errorf("List(%s) row %d = %q, want %q", tc.min, i, got, name)
			}
		}
	}
}

func TestListOrdersNewestFirstAndBounds(t *testing.T) {
	store, clock := newTestStore()
	insert(t, store, logger.LevelInfo, "first")
	clock.advance(time.Minute)
	insert(t, store, logger.LevelInfo, "second")
	clock.advance(time.Minute)
	insert(t, store, logger.LevelInfo, "third")

	rows, err := store.List(context.Background(), logger.LevelDebug, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("listed %d rows, want 3", len(rows))
	}
	if rows[0].Message != "third" || rows[2].Message != "first" {
		t.Errorf("rows = %q...%q, want the newest first", rows[0].Message, rows[2].Message)
	}

	limited, _ := store.List(context.Background(), logger.LevelDebug, 2)
	if len(limited) != 2 {
		t.Fatalf("listed %d rows with limit 2", len(limited))
	}
	if limited[0].Message != "third" || limited[1].Message != "second" {
		t.Errorf("limited rows = %q, %q, want the two newest", limited[0].Message, limited[1].Message)
	}
}

// Two records written in the same instant are two things that happened,
// and the tie is broken by id rather than arbitrarily — the SQL's
// ORDER BY shipped_at DESC, id DESC.
func TestListBreaksTiesByID(t *testing.T) {
	store, _ := newTestStore()
	insert(t, store, logger.LevelInfo, "first")
	insert(t, store, logger.LevelInfo, "second")

	rows, _ := store.List(context.Background(), logger.LevelDebug, 10)
	if rows[0].Message != "second" || rows[1].Message != "first" {
		t.Errorf("rows = %q, %q, want insertion order reversed", rows[0].Message, rows[1].Message)
	}
}

// A returned entry is a copy, so a caller cannot rewrite a stored record
// by editing the map it was handed — the same thing a value read out of
// JSONB cannot do to a row.
func TestListHandsOutCopies(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Insert(context.Background(), Entry{
		Level:   logger.LevelInfo,
		Message: "login: completed",
		Fields:  map[string]string{"user_id": "u1"},
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, _ := store.List(context.Background(), logger.LevelDebug, 10)
	rows[0].Fields["user_id"] = "somebody-else"

	again, _ := store.List(context.Background(), logger.LevelDebug, 10)
	if again[0].Fields["user_id"] != "u1" {
		t.Errorf("user_id = %q after a caller edited its copy, want the stored value", again[0].Fields["user_id"])
	}
}

// The store stamps an entry that carries no time, so the sink does not have
// to invent one and the two implementations still agree on what a record
// with no timestamp means.
func TestInsertStampsAnEntryWithNoTime(t *testing.T) {
	store, clock := newTestStore()
	before := clock.now()

	insert(t, store, logger.LevelWarn, "login: rate limited")

	rows, _ := store.List(context.Background(), logger.LevelDebug, 10)
	if !rows[0].ShippedAt.Equal(before) {
		t.Errorf("shipped_at = %v, want the store's own clock %v", rows[0].ShippedAt, before)
	}
	if rows[0].Sink != SinkName {
		t.Errorf("sink = %q, want the store to name itself when the caller did not", rows[0].Sink)
	}
}

// The vocabulary the API's level= filter and the console both read, in one
// place and in severity order.
func TestLevelsAreTheFourCanonicalNames(t *testing.T) {
	if got := strings.Join(Levels(), ","); got != "debug,info,warn,error" {
		t.Errorf("Levels() = %s, want debug,info,warn,error", got)
	}
}

func TestLevelNamesAtOrAbove(t *testing.T) {
	for _, tc := range []struct {
		min  logger.Level
		want string
	}{
		{logger.LevelDebug, "debug,info,warn,error"},
		{logger.LevelInfo, "info,warn,error"},
		{logger.LevelWarn, "warn,error"},
		{logger.LevelError, "error"},
		// Out of range clamps rather than producing an empty set that
		// would silently mean "nothing" for a value that means "all".
		{logger.Level(-1), "debug,info,warn,error"},
		{logger.Level(99), ""},
	} {
		if got := strings.Join(levelNames(tc.min), ","); got != tc.want {
			t.Errorf("levelNames(%d) = %q, want %q", tc.min, got, tc.want)
		}
	}
}

// A row written by hand can hold a level this package never writes. Failing
// the whole listing over it would be a log an operator cannot read because
// of a typo in a row they were trying to inspect, so it is filed at the
// most severe end — visible in every filtered view rather than hideable.
func TestParseLevelFilesAnUnknownNameAtTheMostSevereEnd(t *testing.T) {
	for _, name := range []string{"fatal", "", "trace", "notice"} {
		if got := parseLevel(name); got != logger.LevelError {
			t.Errorf("parseLevel(%q) = %s, want error so the record is never lost", name, got)
		}
	}
	// Case and the "warning"/"err" aliases are logger.ParseLevel's own
	// leniency, so a hand-written row holding "INFO" reads as info rather
	// than being filed as an error. Asserted here because the test above
	// would otherwise read as "anything unusual becomes an error".
	for raw, want := range map[string]logger.Level{
		"INFO":      logger.LevelInfo,
		"warning":   logger.LevelWarn,
		" Warning ": logger.LevelWarn,
	} {
		if got := parseLevel(raw); got != want {
			t.Errorf("parseLevel(%q) = %s, want %s", raw, got, want)
		}
	}

	// And the names this package writes come back as themselves, which is
	// the case that has to work for the endpoint to mean anything.
	for _, want := range []logger.Level{logger.LevelDebug, logger.LevelInfo, logger.LevelWarn, logger.LevelError} {
		if got := parseLevel(want.String()); got != want {
			t.Errorf("parseLevel(%q) = %s, want %s", want, got, want)
		}
	}
}
