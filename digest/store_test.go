package digest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// testClock is a hand-wound clock, so an ordering assertion is about the
// store's sort rather than about how far apart two time.Now() calls
// happened to land. The same idea as webhook's, in this package's own
// terms because a double is only worth having if it is the double the
// store under test actually reads.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock {
	// A fixed instant, not now: nothing here should depend on when the
	// suite runs.
	return &testClock{at: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// newTestStore is a MemoryStore on a clock the test controls.
func newTestStore() (*MemoryStore, *testClock) {
	clock := newTestClock()
	s := NewMemoryStore()
	s.Clock = clock.now
	return s, clock
}

func insert(t *testing.T, s Store, e Entry) Entry {
	t.Helper()
	saved, err := s.Insert(context.Background(), e)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	return saved
}

// The zero-value rule, in all three of its cases. The third is the one
// worth stating: WindowEnd falls back to the entry's own GeneratedAt
// rather than to the clock, so a caller that supplied a GeneratedAt gets
// a WindowEnd equal to it instead of one a few microseconds later.
func TestMemoryStoreStampsOnlyTheTimesItIsNotGiven(t *testing.T) {
	ctx := context.Background()
	s, clock := newTestStore()

	bare := insert(t, s, Entry{Text: "nothing given"})
	if bare.ID != 1 {
		t.Errorf("id = %d on the first insert, want 1", bare.ID)
	}
	if !bare.GeneratedAt.Equal(clock.now()) {
		t.Errorf("generated_at = %v, want the store's clock %v", bare.GeneratedAt, clock.now())
	}
	if !bare.WindowEnd.Equal(bare.GeneratedAt) {
		t.Errorf("window_end = %v with nothing given, want the generated_at %v", bare.WindowEnd, bare.GeneratedAt)
	}

	clock.advance(time.Hour)
	start := clock.now().Add(-7 * 24 * time.Hour)
	end := clock.now()
	partial := insert(t, s, Entry{WindowStart: start, WindowEnd: end, Text: "window given"})
	if !partial.WindowStart.Equal(start) || !partial.WindowEnd.Equal(end) {
		t.Errorf("window = %v..%v, want the one supplied %v..%v", partial.WindowStart, partial.WindowEnd, start, end)
	}
	if !partial.GeneratedAt.Equal(clock.now()) {
		t.Errorf("generated_at = %v, want the store's clock for a run that did not state one", partial.GeneratedAt)
	}

	// A GeneratedAt in the past with no WindowEnd: the fallback is the
	// entry's own timestamp, not the clock.
	past := clock.now().Add(-30 * time.Hour)
	derived := insert(t, s, Entry{GeneratedAt: past, Text: "generated given"})
	if !derived.WindowEnd.Equal(past) {
		t.Errorf("window_end = %v, want the supplied generated_at %v rather than the clock", derived.WindowEnd, past)
	}

	// And what was written is what List reads back: the stamping is the
	// store's, not a field the caller's copy got and the row did not.
	rows, err := s.List(ctx, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("listed %d runs, want 3", len(rows))
	}
	for _, row := range rows {
		if row.GeneratedAt.IsZero() || row.WindowEnd.IsZero() {
			t.Errorf("run %d read back with a zero timestamp: %+v", row.ID, row)
		}
	}
}

// Newest first, with ID as the tiebreak — the SQL's ORDER BY
// generated_at DESC, id DESC. A double that sorted on the timestamp alone
// would pass every other test in this file and still hand two runs
// sharing an instant back in an order the real query does not.
func TestMemoryStoreListsNewestFirstBreakingTiesByID(t *testing.T) {
	s, clock := newTestStore()

	for _, text := range []string{"first", "second", "third"} {
		insert(t, s, Entry{Text: text})
		clock.advance(time.Hour)
	}
	// Two runs in the same instant, which is what a replayed schedule or a
	// clock with second-granularity storage produces.
	same := clock.now()
	older := insert(t, s, Entry{GeneratedAt: same, Text: "same instant, lower id"})
	newer := insert(t, s, Entry{GeneratedAt: same, Text: "same instant, higher id"})

	rows, err := s.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("listed %d runs, want 5", len(rows))
	}
	if rows[0].ID != newer.ID || rows[1].ID != older.ID {
		t.Errorf("the tied pair came back as %d then %d, want %d then %d",
			rows[0].ID, rows[1].ID, newer.ID, older.ID)
	}
	if rows[2].Text != "third" {
		t.Errorf("third row = %q, want the next-newest timestamp", rows[2].Text)
	}
	if rows[4].Text != "first" {
		t.Errorf("last row = %q, want the oldest", rows[4].Text)
	}
}

// The listing is bounded, and a non-positive limit means the default
// rather than nothing. Both implementations clamp through ClampLimit; the
// Postgres one is not exercised here — this environment has no Postgres —
// so what is asserted is the rule they share.
func TestMemoryStoreBoundsTheListing(t *testing.T) {
	s, _ := newTestStore()
	for i := 0; i < DefaultHistoryLimit+5; i++ {
		insert(t, s, Entry{Text: fmt.Sprintf("run %d", i)})
	}

	rows, err := s.List(context.Background(), 3)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("listed %d runs with limit 3, want 3", len(rows))
	}
	if rows[0].Text != fmt.Sprintf("run %d", DefaultHistoryLimit+4) {
		t.Errorf("first row = %q, want the newest of the bounded set", rows[0].Text)
	}

	for _, limit := range []int{0, -1} {
		rows, err := s.List(context.Background(), limit)
		if err != nil {
			t.Fatalf("List(%d): %v", limit, err)
		}
		if len(rows) != DefaultHistoryLimit {
			t.Errorf("listed %d runs with limit %d, want the default %d — a non-positive limit means the default, not none",
				len(rows), limit, DefaultHistoryLimit)
		}
	}
}

func TestClampLimit(t *testing.T) {
	for _, tc := range []struct {
		in, want int
	}{
		{5, 5},
		{DefaultHistoryLimit, DefaultHistoryLimit},
		{MaxHistoryLimit, MaxHistoryLimit},
		{MaxHistoryLimit + 1, MaxHistoryLimit},
		{0, DefaultHistoryLimit},
		{-7, DefaultHistoryLimit},
	} {
		if got := ClampLimit(tc.in); got != tc.want {
			t.Errorf("ClampLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// A returned listing is a copy, so a caller cannot edit the history by
// editing what it was handed — the thing a scanned row cannot do to a
// database either.
func TestMemoryStoreHandsOutCopies(t *testing.T) {
	s, _ := newTestStore()
	insert(t, s, Entry{Text: "the real text"})

	rows, _ := s.List(context.Background(), 10)
	rows[0].Text = "edited by a caller"
	rows[0].ID = 999

	again, _ := s.List(context.Background(), 10)
	if again[0].Text != "the real text" || again[0].ID != 1 {
		t.Errorf("stored run is %+v after a caller edited its copy", again[0])
	}
}

// The store is written by the scheduler goroutine while HTTP handlers read
// it, which is the one piece of concurrency this feature actually has.
// Under -race this is what proves the mutex covers both paths.
func TestMemoryStoreIsSafeUnderConcurrentUse(t *testing.T) {
	s := NewMemoryStore()
	const writers, each = 8, 25

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if _, err := s.Insert(context.Background(), Entry{Text: fmt.Sprintf("w%d-%d", w, i)}); err != nil {
					t.Errorf("Insert: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < each; i++ {
			if _, err := s.List(context.Background(), 5); err != nil {
				t.Errorf("List: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	if got := s.Count(); got != writers*each {
		t.Errorf("recorded %d runs, want %d", got, writers*each)
	}
}
