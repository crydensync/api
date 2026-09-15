package shiplog

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/crydensync/cryden/v2/logger"
)

// The four bare methods are what the engine calls when the Logger it holds
// is not context-aware, and the whole reason this type exists. Each one has
// to land a row with its own severity — a Debug routed to Info would make
// the level filter above meaningless.
func TestLoggerRecordsEveryLevel(t *testing.T) {
	store := NewMemoryStore()
	l := NewLogger(store)
	ctx := context.Background()

	l.Debug("cache miss", map[string]string{"key": "a"})
	l.Info("login: completed", map[string]string{"user_id": "u1"})
	l.Warn("login: rate limited", map[string]string{"ip": "203.0.113.9"})
	l.Error("token reuse detected", map[string]string{"user_id": "u1"})

	if n := store.Count(); n != 4 {
		t.Fatalf("recorded %d rows, want 4", n)
	}

	all, err := store.List(ctx, logger.LevelDebug, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// Newest first, so the order of the listing is the reverse of the
	// order they were logged in.
	want := []string{"error", "warn", "info", "debug"}
	for i, name := range want {
		if got := all[i].Level.String(); got != name {
			t.Errorf("row %d level = %q, want %q", i, got, name)
		}
	}

	// The sink names itself, so a row read out of a table shared with a
	// second sink is still attributable to this one.
	for _, e := range all {
		if e.Sink != SinkName {
			t.Errorf("sink = %q, want %q", e.Sink, SinkName)
		}
		if e.ShippedAt.IsZero() {
			t.Errorf("%q was recorded with no timestamp", e.Message)
		}
	}

	// The fields are the record's own, which is what makes the listing
	// useful rather than a list of bare messages.
	if all[3].Fields["key"] != "a" {
		t.Errorf("debug record fields = %v, want the ones it was logged with", all[3].Fields)
	}
}

// The point of implementing logger.ContextLogger rather than only the four
// methods: ForContext sees the interface and hands over the context of the
// call being served, where a four-method sink would have been returned
// untouched and the context lost at the boundary.
func TestLoggerIsSeenAsAContextLogger(t *testing.T) {
	store := NewMemoryStore()
	l := NewLogger(store)

	// A cancelled request context — the request that logged has already
	// gone. The record must still land: it is most worth having exactly
	// when the request failed, which is the same reasoning the webhook
	// sender's enqueue is built on.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	bound := logger.ForContext(ctx, l)
	if _, ok := bound.(logger.ContextLogger); !ok {
		t.Fatal("ForContext did not recognise the sink as a ContextLogger, so the context never reaches it")
	}
	bound.Warn("login: rate limited", map[string]string{"ip": "203.0.113.9"})

	if n := store.Count(); n != 1 {
		t.Fatalf("recorded %d rows, want 1 — a cancelled request context must not drop the record", n)
	}
}

// A bare nil ctx is what the four methods themselves pass, and
// logger.ContextLogger requires every implementation to treat it as
// context.Background() rather than dereferencing it.
func TestLoggerTreatsANilContextAsBackground(t *testing.T) {
	store := NewMemoryStore()
	l := NewLogger(store)

	l.Log(nil, logger.LevelInfo, "login: completed", nil)

	if n := store.Count(); n != 1 {
		t.Errorf("recorded %d rows with a nil ctx, want 1", n)
	}
}

// The trap logger.NewMultiLogger's own doc comment names: a nil *Logger
// inside a Logger interface is not a nil interface, so a fan-out will call
// it like any other sink. The setting that produces this here is
// CLOUD_LOGGING being off, and a nil dereference inside a log statement
// would take down the login that was only trying to mention something.
func TestLoggerIsSilentWithoutAStore(t *testing.T) {
	var nilLogger *Logger
	nilLogger.Info("login: completed", nil)

	noStore := &Logger{}
	noStore.Info("login: completed", nil)

	// And inside the fan-out the engine actually holds, where the nil
	// sink would otherwise be reached on every record.
	combined := logger.NewMultiLogger(logger.NewConsoleJSONLogger(), noStore, nilLogger)
	combined.Info("login: completed", nil)
}

// A log that could fail the operation it was describing would be worse than
// a log with a hole in it, so a broken store must not panic and must not
// propagate. It has to be visible somewhere, though, or a sink that has
// never once succeeded looks exactly like a deployment that logs nothing.
func TestLoggerReportsAFailedInsertWithoutFailing(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{
		Store:  failingStore{err: errors.New("database is down")},
		Errors: log.New(&buf, "", 0),
	}

	l.Error("login: failed", map[string]string{"ip": "203.0.113.9"})

	got := buf.String()
	if !strings.Contains(got, "database is down") || !strings.Contains(got, "login: failed") {
		t.Errorf("error output = %q, want the store's error and the record that was lost", got)
	}

	// Nil Errors is a legitimate choice — a deployment willing to lose the
	// record rather than add a second failure mode to stderr — and must
	// not panic either.
	silent := &Logger{Store: failingStore{err: errors.New("database is down")}}
	silent.Error("login: failed", nil)
}

// failingStore is a Store whose writes always fail, for the error paths.
type failingStore struct{ err error }

func (s failingStore) Insert(context.Context, Entry) error { return s.err }
func (s failingStore) List(context.Context, logger.Level, int) ([]Entry, error) {
	return nil, s.err
}
