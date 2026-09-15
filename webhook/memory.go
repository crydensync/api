package webhook

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemoryStore is the in-process Store, for tests and for any embedding host
// that wants webhook delivery without a database behind it.
//
// It is a faithful double rather than a convenient one, because the worker
// tests it carries are the only tests the worker's claim/backoff/terminal
// behaviour gets in this repo — the Postgres path needs a live server, and
// FOR UPDATE SKIP LOCKED has no meaning without one. So it reproduces the
// three promises that are easy to get subtly wrong:
//
//   - ClaimDue's two branches, including that the in_flight branch ignores
//     the attempt budget. A double that only reclaimed by budget would let
//     a stranded row look fine here and stay stranded in production.
//   - ClaimDue increments Attempts, at claim time. A double that
//     incremented on failure would make every backoff test pass while the
//     real counter meant something else.
//   - Returned rows are copies. A caller holding a Delivery cannot reach
//     the stored one, the way a scanned row cannot reach the database. A
//     double that handed out its own pointers would let a worker "resolve"
//     a delivery by editing a struct.
//
// What it does NOT reproduce is concurrency: it is one mutex, so it can
// never actually exercise two workers racing for the same row. That is a
// real limitation of testing this way and is said out loud in PROGRESS.md
// rather than implied away.
type MemoryStore struct {
	mu   sync.Mutex
	rows map[int64]Delivery
	next int64

	// Clock is the store's own notion of "now", used for created_at and for
	// the timestamps it stamps itself. ClaimDue takes now as a parameter and
	// does not use this; it is here so a test can make created_at ordering
	// deterministic.
	Clock func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		rows:  make(map[int64]Delivery),
		Clock: func() time.Time { return time.Now().UTC() },
	}
}

var _ Store = (*MemoryStore)(nil)

func (s *MemoryStore) Enqueue(_ context.Context, d Delivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.next++
	d.ID = s.next
	d.Status = StatusPending
	d.Attempts = 0
	d.ResponseCode = 0
	d.Error = ""
	d.DurationMS = 0
	d.ClaimedAt = nil
	d.DeliveredAt = nil
	if d.CreatedAt.IsZero() {
		d.CreatedAt = s.Clock()
	}
	if d.NextAttemptAt.IsZero() {
		d.NextAttemptAt = d.CreatedAt
	}
	// A copy of the payload, so a caller reusing its buffer cannot rewrite
	// the stored body.
	d.Payload = append([]byte(nil), d.Payload...)
	s.rows[d.ID] = d
	return nil
}

func (s *MemoryStore) ClaimDue(_ context.Context, now time.Time, limit, maxAttempts int, staleAfter time.Duration) ([]Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	staleBefore := now.Add(-staleAfter)

	var due []Delivery
	for _, d := range s.rows {
		switch d.Status {
		case StatusPending:
			if d.Attempts < maxAttempts && !d.NextAttemptAt.After(now) {
				due = append(due, d)
			}
		case StatusInFlight:
			// No attempt-budget check here, deliberately — see the Store
			// doc. This is the branch that keeps a row whose worker died
			// from being stranded forever.
			if d.ClaimedAt != nil && d.ClaimedAt.Before(staleBefore) {
				due = append(due, d)
			}
		}
	}

	// Ordered the way the SQL is: oldest due first, ties broken by id so
	// the order is total and a test can rely on it.
	sort.Slice(due, func(i, j int) bool {
		if !due[i].NextAttemptAt.Equal(due[j].NextAttemptAt) {
			return due[i].NextAttemptAt.Before(due[j].NextAttemptAt)
		}
		return due[i].ID < due[j].ID
	})
	if len(due) > limit {
		due = due[:limit]
	}

	claimed := make([]Delivery, 0, len(due))
	for _, d := range due {
		stored := s.rows[d.ID]
		stored.Status = StatusInFlight
		stored.Attempts++
		claimedAt := now
		stored.ClaimedAt = &claimedAt
		s.rows[d.ID] = stored
		claimed = append(claimed, copyDelivery(stored))
	}
	return claimed, nil
}

func (s *MemoryStore) MarkDelivered(_ context.Context, id int64, r Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.rows[id]
	if !ok {
		return fmt.Errorf("%w: id %d", ErrNotFound, id)
	}
	d.Status = StatusDelivered
	d.ClaimedAt = nil
	deliveredAt := s.Clock()
	d.DeliveredAt = &deliveredAt
	d.ResponseCode = r.Code
	d.DurationMS = int(r.Duration.Milliseconds())
	d.Error = ""
	s.rows[id] = d
	return nil
}

func (s *MemoryStore) MarkFailed(_ context.Context, id int64, r Result, retryAt *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.rows[id]
	if !ok {
		return fmt.Errorf("%w: id %d", ErrNotFound, id)
	}
	d.ClaimedAt = nil
	d.ResponseCode = r.Code
	d.DurationMS = int(r.Duration.Milliseconds())
	d.Error = r.Err
	if retryAt != nil {
		d.Status = StatusPending
		d.NextAttemptAt = *retryAt
	} else {
		d.Status = StatusFailed
	}
	s.rows[id] = d
	return nil
}

func (s *MemoryStore) List(_ context.Context, status Status, limit int) ([]Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Delivery, 0, len(s.rows))
	for _, d := range s.rows {
		if status != "" && d.Status != status {
			continue
		}
		out = append(out, copyDelivery(d))
	}
	// Newest first, ties broken by id descending — the SQL's ORDER BY
	// created_at DESC, id DESC.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Get returns one delivery by id, for a test that wants to assert on a row
// it did not get back from a claim. Not part of Store: nothing in
// production needs it, and PostgresStore has no equivalent.
func (s *MemoryStore) Get(id int64) (Delivery, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.rows[id]
	return copyDelivery(d), ok
}

// Count returns how many rows exist, optionally filtered by status. A test
// helper, like Get.
func (s *MemoryStore) Count(status Status) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, d := range s.rows {
		if status == "" || d.Status == status {
			n++
		}
	}
	return n
}

func copyDelivery(d Delivery) Delivery {
	d.Payload = append([]byte(nil), d.Payload...)
	if d.ClaimedAt != nil {
		t := *d.ClaimedAt
		d.ClaimedAt = &t
	}
	if d.DeliveredAt != nil {
		t := *d.DeliveredAt
		d.DeliveredAt = &t
	}
	return d
}
