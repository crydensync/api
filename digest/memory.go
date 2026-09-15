package digest

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryStore is the in-process Store, for tests and for any embedding
// host that wants the digest history without a database behind it.
//
// It is a faithful double rather than a convenient one where the two
// implementations could quietly disagree:
//
//   - List is ordered by GeneratedAt descending with ID as the tiebreak,
//     which is the SQL's ORDER BY generated_at DESC, id DESC. A double
//     that sorted only on the timestamp would pass every test while the
//     real query returned a stable order the double did not have.
//   - Insert applies the same zero-value stamping the Postgres store
//     does, through the same resolveTimes, so a test asserting "the store
//     filled in the clock" is asserting about real behaviour.
//
// What it does not reproduce is the database: there is no TIMESTAMPTZ
// round trip here, so a time that would not survive one is a difference
// this double cannot show. Postgres stores microseconds; Go's time.Time
// carries nanoseconds, and a monotonic reading is dropped on the way in.
// Nothing in flight depends on either — the window columns are compared
// against each other, never against a stored digest — but the gap is
// worth naming rather than assuming away.
type MemoryStore struct {
	mu   sync.Mutex
	runs []Entry
	next int64

	// Clock stamps an entry that does not carry its own GeneratedAt, so a
	// test can make a listing's ordering deterministic instead of hoping
	// the wall clock separated two inserts.
	Clock func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{Clock: func() time.Time { return time.Now().UTC() }}
}

var _ Store = (*MemoryStore)(nil)

func (s *MemoryStore) Insert(_ context.Context, e Entry) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.next++
	e.ID = s.next
	e = resolveTimes(e, s.Clock())
	s.runs = append(s.runs, e)
	return e, nil
}

func (s *MemoryStore) List(_ context.Context, limit int) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Entry, len(s.runs))
	copy(out, s.runs)
	// Newest first, ties broken by id descending — the SQL's
	// ORDER BY generated_at DESC, id DESC.
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].GeneratedAt.Equal(out[j].GeneratedAt) {
			return out[i].GeneratedAt.After(out[j].GeneratedAt)
		}
		return out[i].ID > out[j].ID
	})
	// Clamped here as well as by the handler, so a caller reaching the
	// store directly gets the same bounded answer the endpoint gives.
	limit = ClampLimit(limit)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Count returns how many runs have been recorded. A test helper: no
// production caller needs a total, and no endpoint reports one.
func (s *MemoryStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runs)
}
