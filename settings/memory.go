package settings

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// MemoryStore is the in-process Store, for tests and for any embedding
// host that wants the settings wiring without a database behind it.
//
// It is a faithful double rather than a convenient one in the one place
// that matters here: the bytes are copied on the way in and on the way
// out, exactly as a driver round trip through BYTEA would leave them
// unrelated to the caller's slice. A double that stored the caller's
// slice directly would let a test mutate a "stored" value through the
// variable it wrote with, and then assert something the real store cannot
// reproduce.
type MemoryStore struct {
	mu   sync.RWMutex
	rows map[string][]byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{rows: make(map[string][]byte)}
}

var _ Store = (*MemoryStore)(nil)

func (s *MemoryStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, ok := s.rows[key]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	return append([]byte(nil), value...), nil
}

func (s *MemoryStore) Put(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rows[key] = append([]byte(nil), value...)
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.rows[key]; !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	delete(s.rows, key)
	return nil
}

func (s *MemoryStore) Keys(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.rows))
	for k := range s.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// Raw is a test-only accessor the PostgresStore has no equivalent for:
// it returns what is actually in the store, so a test can assert that a
// credential went in as ciphertext rather than taking Secrets' word for
// it. Deliberately not part of Store, which is the interface production
// code gets — the point of that interface is that nothing above it can
// read the stored bytes without decrypting them first.
func (s *MemoryStore) Raw(key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, ok := s.rows[key]
	return append([]byte(nil), value...), ok
}
