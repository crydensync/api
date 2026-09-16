package anomalyreview

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryStore is the in-process Store, for tests and for any embedding
// host that wants the review surface without a database behind it.
//
// It is a faithful double, which here means one specific thing: it has to
// refuse a review of an event that does not exist, because Postgres does
// — through the foreign key on audit_events. A double that accepted any
// id would let a test assert a 404 that production never produces, and
// the branch that actually runs in production would be the untested one.
//
// So it refuses, and it needs to be told what exists. RegisterEvents is
// how. That is a real seam rather than a wart: cryden's AuditStore has no
// lookup-by-event-id, so this package cannot ask the engine whether an
// event is real even in production — the database answers instead, and
// the double answers from what the test declared.
type MemoryStore struct {
	mu sync.RWMutex
	// rows is keyed by audit event id. A missing key is unreviewed.
	rows map[string]Review
	// known is the set of audit event ids that exist. Postgres reads this
	// from audit_events via the foreign key; here a test supplies it.
	known map[string]bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		rows:  make(map[string]Review),
		known: make(map[string]bool),
	}
}

var _ Store = (*MemoryStore)(nil)

// RegisterEvents declares that these audit event ids exist, so that Set
// will accept a review of them and refuse one of anything else. It is the
// memory store's stand-in for the foreign key, and is not part of Store
// because nothing in production needs it — Postgres answers the same
// question from the table itself.
func (s *MemoryStore) RegisterEvents(eventIDs ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range eventIDs {
		s.known[id] = true
	}
}

func (s *MemoryStore) StatusesFor(_ context.Context, eventIDs []string) (map[string]Review, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]Review, len(eventIDs))
	for _, id := range eventIDs {
		if review, ok := s.rows[id]; ok {
			out[id] = review
		}
	}
	return out, nil
}

func (s *MemoryStore) Set(_ context.Context, eventID string, status Status, note, reviewerID string) (Review, error) {
	// Validated with the same call the Postgres store makes, not a
	// reimplementation of it, so a status cannot hold in one store and
	// not the other.
	if err := ValidateStatus(status); err != nil {
		return Review{}, err
	}
	if len(note) > maxNoteLength {
		return Review{}, fmt.Errorf("%w: %d characters, the limit is %d", ErrNoteTooLong, len(note), maxNoteLength)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.known[eventID] {
		return Review{}, fmt.Errorf("%w: %s", ErrNoSuchEvent, eventID)
	}

	review := Review{
		EventID:    eventID,
		Status:     status,
		Note:       note,
		ReviewerID: reviewerID,
		UpdatedAt:  time.Now(),
	}
	s.rows[eventID] = review
	return review, nil
}

// Status is a test helper the PostgresStore has no equivalent for: the
// memory store can answer "what did we decide about this event" without a
// round trip, which keeps a failing assertion readable. Not part of
// Store, because nothing in production reads one row at a time.
func (s *MemoryStore) Status(eventID string) (Status, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	review, ok := s.rows[eventID]
	return review.Status, ok
}

// Len is how many events have a recorded review, of any status.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rows)
}
