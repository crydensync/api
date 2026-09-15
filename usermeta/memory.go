package usermeta

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// MemoryStore is the in-process Store, for tests and for any embedding
// host that wants the claims wiring without a database behind it.
//
// It is a faithful double rather than a convenient one, in the two places
// that is easy to get wrong:
//
//   - Values are round-tripped through JSON on the way in, exactly as the
//     Postgres column does. Storing the caller's `any` directly would let
//     a test pass an int where the real store would hand back a float64,
//     and a claims test would then be asserting something production
//     cannot reproduce.
//   - Validation is the same ValidateKey call, not a reimplementation of
//     it, so the reserved-key rule cannot hold in one store and not the
//     other.
type MemoryStore struct {
	mu sync.RWMutex
	// keyed by userID, then by metadata key.
	rows map[string]map[string]any
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{rows: make(map[string]map[string]any)}
}

var _ Store = (*MemoryStore)(nil)

func (s *MemoryStore) AllFor(_ context.Context, userID string) (map[string]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]any, len(s.rows[userID]))
	for k, v := range s.rows[userID] {
		out[k] = v
	}
	return out, nil
}

func (s *MemoryStore) Set(_ context.Context, userID, key string, value any) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	raw, err := marshalValue(key, value)
	if err != nil {
		return err
	}
	var roundTripped any
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		return fmt.Errorf("decoding metadata %q: %w", key, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[userID] == nil {
		s.rows[userID] = make(map[string]any)
	}
	s.rows[userID][key] = roundTripped
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, userID, key string) error {
	// Not validated, matching PostgresStore.Delete — see its comment for
	// why deletion is the one operation that must not re-check the rule.
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rows[userID][key]; !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	delete(s.rows[userID], key)
	return nil
}

// Keys is a test helper the PostgresStore has no equivalent for: the
// memory store can answer "what is set" in a stable order without a
// query, which keeps a failing assertion readable. Not part of Store,
// because nothing in production needs it.
func (s *MemoryStore) Keys(userID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]string, 0, len(s.rows[userID]))
	for k := range s.rows[userID] {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
