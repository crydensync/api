package settings

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newTestStore() *MemoryStore { return NewMemoryStore() }

// The store's contract is small, and both implementations have to agree
// on it — the PostgresStore is what production runs and the MemoryStore is
// what every handler test asserts against, so a divergence between them
// would make the tests pass for a store production does not use.
//
// What is asserted here is the rule both share. The PostgresStore's own
// SQL is not exercised: there is no Postgres in this sandbox, so its
// statements are a copy of a design rather than a verified query (see
// PROGRESS.md).
func TestMemoryStoreRoundTripsBytes(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	// Ciphertext, not text: arbitrary bytes including NULs, because that
	// is what an AES-GCM seal produces and a store that mangled them
	// would still pass a test written with ASCII.
	value := []byte{0x00, 0xff, 0x10, 0x00, 'h', 'i', 0x7f}

	if err := store.Put(ctx, KeyLLMProvider, value); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(ctx, KeyLLMProvider)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("Get = %v, want %v", got, value)
	}
}

func TestMemoryStoreReportsAMissingKey(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	if _, err := store.Get(ctx, KeyLLMProvider); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get on an empty store = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, KeyLLMProvider); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete on an empty store = %v, want ErrNotFound", err)
	}
}

func TestMemoryStoreReplacesRatherThanAppends(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	if err := store.Put(ctx, KeyLLMProvider, []byte("first")); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := store.Put(ctx, KeyLLMProvider, []byte("second")); err != nil {
		t.Fatalf("second Put: %v", err)
	}

	got, err := store.Get(ctx, KeyLLMProvider)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("Get = %q, want %q — the second write replaced the first", got, "second")
	}
	if keys, _ := store.Keys(ctx); len(keys) != 1 {
		t.Errorf("Keys = %v, want one entry after two writes to the same key", keys)
	}
}

// The store must not hand out its own memory. A caller that kept the
// slice it wrote with, and then mutated it, would otherwise be editing
// what the store holds — which for a double means a handler test could
// assert a value production cannot produce.
func TestMemoryStoreCopiesOnTheWayInAndOut(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	written := []byte("original")
	if err := store.Put(ctx, KeyLLMProvider, written); err != nil {
		t.Fatalf("Put: %v", err)
	}
	written[0] = 'X' // the caller's slice, after the write

	first, err := store.Get(ctx, KeyLLMProvider)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(first) != "original" {
		t.Errorf("Get = %q after the caller mutated its own slice, want %q", first, "original")
	}

	first[0] = 'Y' // the returned slice, after the read
	second, err := store.Get(ctx, KeyLLMProvider)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if string(second) != "original" {
		t.Errorf("Get = %q after the caller mutated the returned slice, want %q", second, "original")
	}
}

func TestMemoryStoreListsKeysSortedAndWithoutValues(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	for _, key := range []string{KeyLLMProvider, KeyAskAIWidget, KeyDatabaseProvider} {
		if err := store.Put(ctx, key, []byte("secret-value")); err != nil {
			t.Fatalf("Put(%s): %v", key, err)
		}
	}

	keys, err := store.Keys(ctx)
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	want := []string{KeyAskAIWidget, KeyDatabaseProvider, KeyLLMProvider}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("Keys = %v, want %v (sorted)", keys, want)
	}
	// Keys is names only. It is the one read an endpoint can make safely,
	// and that only holds while it cannot carry a value.
	for _, key := range keys {
		if strings.Contains(key, "secret") {
			t.Errorf("Keys returned %q, which looks like a value rather than a name", key)
		}
	}
}

func TestMemoryStoreDeleteRemovesIt(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	if err := store.Put(ctx, KeyLLMProvider, []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(ctx, KeyLLMProvider); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, KeyLLMProvider); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
}
