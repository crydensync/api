package shiplog

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/logger"
)

// MemoryStore is the in-process Store, for tests and for any embedding
// host that wants the shipped-events log without a database behind it.
//
// It is a faithful double rather than a convenient one, on the two points
// where the two implementations could quietly disagree:
//
//   - List means "at or above", and means it the same way the Postgres
//     query does: by name against the set levelNames returns, not by a
//     rank comparison that happens to agree for the four real levels. A
//     double that returned only the exact level would make every filter
//     test pass while the real query answered a different question.
//   - Fields come back as copies. A caller editing the map it was handed
//     cannot reach the stored entry, the way a value read out of JSONB
//     cannot reach the row.
//
// What it does not reproduce is the database: there is no JSONB round
// trip here, so a field value that would not survive one is a difference
// this double cannot show. Nothing in flight produces such a value —
// logger.Logger's fields are strings, and every string is valid JSON — but
// the gap is worth naming rather than assuming away.
type MemoryStore struct {
	mu   sync.Mutex
	rows []Entry
	next int64

	// Clock stamps an entry that does not carry its own ShippedAt, so a
	// test can make the listing's ordering deterministic instead of
	// hoping the wall clock separated two inserts.
	Clock func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{Clock: func() time.Time { return time.Now().UTC() }}
}

var _ Store = (*MemoryStore)(nil)

func (s *MemoryStore) Insert(_ context.Context, e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.next++
	e.ID = s.next
	e.ShippedAt = resolveShippedAt(e, s.Clock())
	e.Sink = sinkOr(e.Sink)
	// A copy, so a caller reusing its map cannot rewrite the stored record.
	e.Fields = copyFields(e.Fields)
	s.rows = append(s.rows, e)
	return nil
}

func (s *MemoryStore) List(_ context.Context, minLevel logger.Level, limit int) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Filtering by name against the same set the SQL passes, rather than
	// by comparing levels, so the double means literally what the query
	// means. The two agree for any Level in range, and this is what makes
	// them agree out of range too: Level.String() clamps, so a Level of
	// -5 or 99 lands on a real name in both implementations instead of
	// being excluded here and included there.
	allowed := make(map[string]struct{}, 4)
	for _, name := range levelNames(minLevel) {
		allowed[name] = struct{}{}
	}

	out := make([]Entry, 0, len(s.rows))
	for _, e := range s.rows {
		if _, ok := allowed[e.Level.String()]; !ok {
			continue
		}
		out = append(out, copyEntry(e))
	}
	// Newest first, ties broken by id descending — the SQL's
	// ORDER BY shipped_at DESC, id DESC.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ShippedAt.Equal(out[j].ShippedAt) {
			return out[i].ShippedAt.After(out[j].ShippedAt)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Count returns how many records have been written. A test helper: no
// production caller needs a total, and no endpoint reports one.
func (s *MemoryStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows)
}

func copyEntry(e Entry) Entry {
	e.Fields = copyFields(e.Fields)
	return e
}

func copyFields(fields map[string]string) map[string]string {
	if fields == nil {
		return nil
	}
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	return out
}
