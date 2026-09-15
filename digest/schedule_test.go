package digest

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer collects log output written from a goroutine the test does not
// control. A bare bytes.Buffer would be a race the -race build is entitled
// to fail on, and the whole point of these tests is a loop running beside
// the assertion.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// builder is a Builder that counts its calls and hands back a fixed entry,
// so a test can ask whether it was called at all rather than infer it from
// a row.
type builder struct {
	mu    sync.Mutex
	calls int
	entry Entry
	err   error
}

func (b *builder) build(context.Context) (Entry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	return b.entry, b.err
}

func (b *builder) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// A scheduler with nothing to schedule does nothing at all: no goroutine
// left ticking, no row written. This is the state main.go avoids by only
// constructing a Scheduler when DIGEST_INTERVAL_HOURS asked for one, so
// what is asserted here is that a mistake there stays inert.
func TestSchedulerDoesNothingWithoutASchedule(t *testing.T) {
	for _, tc := range []struct {
		name      string
		interval  time.Duration
		withStore bool
		withBuild bool
	}{
		{name: "no interval", withStore: true, withBuild: true},
		{name: "no interval and nothing else either"},
		{name: "no store", interval: time.Hour, withBuild: true},
		{name: "no builder", interval: time.Hour, withStore: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryStore()
			build := &builder{entry: Entry{Text: "unreachable"}}

			s := &Scheduler{Interval: tc.interval}
			if tc.withStore {
				s.Store = store
			}
			if tc.withBuild {
				s.Build = build.build
			}

			// Run is expected back promptly rather than at the end of an
			// interval: an unconfigured scheduler must not hold a goroutine
			// open for an hour first.
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.Run(context.Background())
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Run is still going with nothing to run")
			}

			if n := store.Count(); n != 0 {
				t.Errorf("recorded %d runs, want 0", n)
			}
			if n := build.callCount(); n != 0 {
				t.Errorf("the builder was called %d times, want 0", n)
			}
		})
	}
}

// The first run is after a full interval, not at startup. Asserted against
// an hour-long interval, so this cannot pass by being slow: if the run
// happened at startup it would have happened within microseconds of Run
// being called, and the check below waits a hundred milliseconds.
//
// It is the property that keeps a crashlooping process from manufacturing
// one row per restart, which is the failure mode a history table is worst
// at showing — the rows look like a busy week.
func TestSchedulerWaitsAFullIntervalBeforeTheFirstRun(t *testing.T) {
	store := NewMemoryStore()
	build := &builder{entry: Entry{Text: "the first run"}}
	s := &Scheduler{Store: store, Build: build.build, Interval: time.Hour}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	if n := build.callCount(); n != 0 {
		t.Errorf("the builder ran %d times before the first interval elapsed, want 0", n)
	}
	if n := store.Count(); n != 0 {
		t.Errorf("recorded %d runs before the first interval elapsed, want 0", n)
	}

	// And it stops when the context is cancelled rather than at the next
	// tick, which is what a caller with a shutdown path would need.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// The positive half: one run per interval, each stored with the window the
// builder computed. The interval is deliberately tiny so the test is
// seconds-cheap; what is being asserted is that the loop records, not how
// often it does.
func TestSchedulerRecordsOneRunPerInterval(t *testing.T) {
	store := NewMemoryStore()
	since := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	build := &builder{entry: Entry{WindowStart: since, Text: "the weekly report"}}
	s := &Scheduler{Store: store, Build: build.build, Interval: 5 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitForRuns(t, store, 2)

	rows, err := store.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rows[0].Text != "the weekly report" {
		t.Errorf("text = %q, want the builder's report stored verbatim", rows[0].Text)
	}
	if !rows[0].WindowStart.Equal(since) {
		t.Errorf("window_start = %v, want the window the builder computed %v", rows[0].WindowStart, since)
	}
	if rows[0].ID == 0 {
		t.Error("a recorded run has no id")
	}
	if rows[0].GeneratedAt.IsZero() || rows[0].WindowEnd.IsZero() {
		t.Errorf("run %+v was stored without its times filled in", rows[0])
	}
}

// A failed build is logged and the loop keeps going. A scheduler that
// stopped at the first database blip would silently stop producing
// digests for the rest of the process's life — the exact failure a
// schedule exists to avoid — and one that retried instantly would spin.
func TestSchedulerSurvivesAFailedBuild(t *testing.T) {
	store := NewMemoryStore()
	logs := &syncBuffer{}

	var mu sync.Mutex
	attempts := 0
	build := func(context.Context) (Entry, error) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts == 1 {
			return Entry{}, errors.New("the audit table is unreachable")
		}
		return Entry{Text: "the second attempt"}, nil
	}

	s := &Scheduler{Store: store, Build: build, Interval: 5 * time.Millisecond, Log: log.New(logs, "", 0)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitForRuns(t, store, 1)

	if got := logs.String(); !strings.Contains(got, "the audit table is unreachable") {
		t.Errorf("log = %q, want the build failure recorded", got)
	}
	rows, err := store.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rows[0].Text != "the second attempt" {
		t.Errorf("text = %q, want the run that succeeded after the failure", rows[0].Text)
	}
}

// A builder that fails every time writes nothing rather than a row of
// empty text: an entry with no report in it is worse than no entry, because
// a history listing cannot tell it apart from a quiet week.
func TestSchedulerRecordsNothingWhenTheStoreRejectsTheRun(t *testing.T) {
	store := &refusingStore{}
	s := &Scheduler{Store: store, Build: func(context.Context) (Entry, error) {
		return Entry{Text: "never stored"}, nil
	}, Interval: 5 * time.Millisecond, Log: log.New(&syncBuffer{}, "", 0)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for store.insertAttempts() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := store.insertAttempts(); n < 3 {
		t.Fatalf("the scheduler made %d insert attempts in two seconds, want the loop to keep trying", n)
	}
	if n := store.count(); n != 0 {
		t.Errorf("%d runs were recorded by a store that refused every insert", n)
	}
}

// waitForRuns blocks until the store holds at least n runs, failing the
// test rather than hanging if the loop never gets there.
func waitForRuns(t *testing.T, store *MemoryStore, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for store.Count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("the scheduler recorded %d runs in five seconds, want %d", store.Count(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// refusingStore counts insert attempts and rejects all of them, which is
// what a database that is down looks like from the scheduler's side.
type refusingStore struct {
	mu       sync.Mutex
	attempts int
}

func (s *refusingStore) Insert(context.Context, Entry) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	return Entry{}, errors.New("the database is unreachable")
}

func (s *refusingStore) List(context.Context, int) ([]Entry, error) { return nil, nil }

func (s *refusingStore) insertAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func (s *refusingStore) count() int { return 0 }

var _ Store = (*refusingStore)(nil)
