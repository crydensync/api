package usermeta

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The rule this whole package exists to enforce. Every one of these would
// otherwise be discovered at login: cryden's checkExtraClaims rejects a
// reserved name when it builds the token, so a stored key of "sub" would
// not be ignored — it would make every subsequent login for that user
// fail, with the cause sitting in a different table from the symptom.
func TestReservedClaimNamesAreRefusedAtWriteTime(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	for _, key := range ReservedKeys() {
		err := store.Set(ctx, "user-1", key, "whatever")
		if !errors.Is(err, ErrReservedKey) {
			t.Errorf("Set(%q) error = %v, want ErrReservedKey", key, err)
		}
	}

	// Nothing was stored, so nothing can reach a token.
	if keys := store.Keys("user-1"); len(keys) != 0 {
		t.Errorf("keys after refused writes = %v, want none", keys)
	}
}

// RoleClaim is the one reserved key that is not a JWT registered name,
// and the one with teeth: every metadata key becomes a claim, and
// RequireAdmin reads "role". A metadata key of "role" would mint an
// operator token for someone the operators table has never heard of —
// and operator.Store.Revoke would not take it away, because it never
// granted it.
func TestRoleCannotBeSetAsMetadata(t *testing.T) {
	store := NewMemoryStore()

	err := store.Set(context.Background(), "user-1", RoleClaim, "admin")
	if !errors.Is(err, ErrReservedKey) {
		t.Fatalf("Set(%q, %q) error = %v, want ErrReservedKey", RoleClaim, "admin", err)
	}
}

// The reserved list is what the admin endpoint hands a console to grey
// out, so it has to contain both halves: the engine's seven and this
// repo's one.
func TestReservedKeysCoversTheEngineSetAndRole(t *testing.T) {
	reserved := ReservedKeys()

	for _, want := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", RoleClaim} {
		var found bool
		for _, key := range reserved {
			if key == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ReservedKeys() = %v, missing %q", reserved, want)
		}
	}

	// Sorted, so the endpoint's response is stable and a diff of two
	// responses is meaningful.
	for i := 1; i < len(reserved); i++ {
		if reserved[i-1] > reserved[i] {
			t.Fatalf("ReservedKeys() = %v, want sorted", reserved)
		}
	}

	// A fresh slice each call: a caller appending to it must not be able
	// to edit what the check reads.
	reserved[0] = "mutated"
	if ReservedKeys()[0] == "mutated" {
		t.Error("ReservedKeys() shares its backing array between calls")
	}
}

func TestKeyShapeIsEnforced(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	valid := []string{"plan", "tenant_id", "user.metadata.field", "_private", "a", "A1-b_c.d"}
	for _, key := range valid {
		if err := store.Set(ctx, "user-1", key, 1); err != nil {
			t.Errorf("Set(%q) error = %v, want it accepted", key, err)
		}
	}

	invalid := []string{
		"",                      // empty
		"1st",                   // starts with a digit
		"has space",             // whitespace
		"has/slash",             // not in the allowed set
		"emoji🙂",                // non-ASCII
		strings.Repeat("a", 65), // one past the 64-character bound
	}
	for _, key := range invalid {
		if err := store.Set(ctx, "user-1", key, 1); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Set(%q) error = %v, want ErrInvalidKey", key, err)
		}
	}

	// And the bound itself is inclusive: 64 characters is a legal key.
	if err := store.Set(ctx, "user-1", strings.Repeat("a", 64), 1); err != nil {
		t.Errorf("Set with a 64-character key = %v, want it accepted", err)
	}
}

func TestValuesMustBeJSONEncodable(t *testing.T) {
	store := NewMemoryStore()

	// A channel is the simplest value encoding/json refuses. This is not
	// a hypothetical: the value ends up inside a JWT, so a value that
	// cannot marshal has to be refused here rather than at the next
	// login, where the failure would be one the user cannot act on.
	if err := store.Set(context.Background(), "user-1", "plan", make(chan int)); err == nil {
		t.Fatal("Set with an unmarshalable value returned nil, want an error")
	}
	if err := store.Set(context.Background(), "user-1", "plan", nil); err != nil {
		t.Errorf("Set with a null value = %v, want it accepted — null is valid JSON", err)
	}
}

// The double has to round-trip like the JSONB column does, or a claims
// test would assert a shape production cannot reproduce.
func TestMemoryStoreRoundTripsThroughJSON(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if err := store.Set(ctx, "user-1", "count", 7); err != nil {
		t.Fatalf("Set: %v", err)
	}

	all, err := store.AllFor(ctx, "user-1")
	if err != nil {
		t.Fatalf("AllFor: %v", err)
	}
	if _, isInt := all["count"].(int); isInt {
		t.Error("value came back as int — the real store returns what JSON decodes to (float64)")
	}
	if all["count"] != float64(7) {
		t.Errorf("count = %#v, want float64(7)", all["count"])
	}
}

func TestSetReplacesAndDeleteReportsAbsence(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if err := store.Set(ctx, "user-1", "plan", "free"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Set(ctx, "user-1", "plan", "pro"); err != nil {
		t.Fatalf("Set (replace): %v", err)
	}

	all, err := store.AllFor(ctx, "user-1")
	if err != nil {
		t.Fatalf("AllFor: %v", err)
	}
	if all["plan"] != "pro" {
		t.Errorf("plan = %#v, want \"pro\" — the second write must replace, not accumulate", all["plan"])
	}

	if err := store.Delete(ctx, "user-1", "plan"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Deleting twice is reported, not ignored: a console that removed the
	// wrong field should say so rather than show success.
	if err := store.Delete(ctx, "user-1", "plan"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete error = %v, want ErrNotFound", err)
	}
}

// AllFor is always non-nil, so a JSON response renders {} rather than
// null and the claims provider can range over it unconditionally.
func TestAllForIsNeverNil(t *testing.T) {
	all, err := NewMemoryStore().AllFor(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("AllFor: %v", err)
	}
	if all == nil {
		t.Fatal("AllFor returned a nil map, want an empty one")
	}
	if len(all) != 0 {
		t.Errorf("AllFor for an unknown user = %v, want empty", all)
	}
}

// One user's keys are not another's. The table is keyed by (user_id, key)
// and every statement carries the user_id predicate, so this is a check
// on the double rather than on the real store — but a double that leaked
// across users would make every handler test above it meaningless.
func TestStoresAreScopedPerUser(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if err := store.Set(ctx, "user-1", "plan", "pro"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	other, err := store.AllFor(ctx, "user-2")
	if err != nil {
		t.Fatalf("AllFor: %v", err)
	}
	if len(other) != 0 {
		t.Errorf("user-2 sees %v, want nothing", other)
	}
}
