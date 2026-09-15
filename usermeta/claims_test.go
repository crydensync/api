package usermeta

import (
	"context"
	"errors"
	"testing"
)

// stubRoles is a RoleLookup with one operator in it, so the merge can be
// tested without a database or an operators table.
type stubRoles struct {
	operatorID string
	role       string
	err        error
}

func (s stubRoles) RoleFor(_ context.Context, userID string) (string, bool, error) {
	if s.err != nil {
		return "", false, s.err
	}
	if userID == s.operatorID {
		return s.role, true, nil
	}
	return "", false, nil
}

func TestClaimsProviderMergesMetadataAndRole(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if err := store.Set(ctx, "user-1", "plan", "pro"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Set(ctx, "user-1", "tenant", "acme"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	provider := ClaimsProvider(store, stubRoles{operatorID: "user-1", role: "admin"})
	claims, err := provider.AccessTokenClaims(ctx, "user-1")
	if err != nil {
		t.Fatalf("AccessTokenClaims: %v", err)
	}

	if claims["plan"] != "pro" || claims["tenant"] != "acme" {
		t.Errorf("claims = %v, want the stored metadata", claims)
	}
	if claims[RoleClaim] != "admin" {
		t.Errorf("claims[%q] = %v, want \"admin\"", RoleClaim, claims[RoleClaim])
	}
}

// A user who is neither an operator nor has any metadata gets nil, not an
// empty map. That absence is what RequireAdmin reads as "ordinary user",
// and a test that accepted an empty map here would not notice the
// difference until an admin route started letting people through.
func TestClaimsProviderReturnsNothingForAPlainUser(t *testing.T) {
	claims, err := ClaimsProvider(NewMemoryStore(), stubRoles{operatorID: "someone-else"}).
		AccessTokenClaims(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("AccessTokenClaims: %v", err)
	}
	if claims != nil {
		t.Errorf("claims = %v, want nil for a user with neither metadata nor a role", claims)
	}
}

// Metadata alone is enough to produce claims — an ordinary user with a
// mapped field is the normal case this feature exists for.
func TestClaimsProviderReturnsMetadataForANonOperator(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Set(ctx, "user-1", "plan", "pro"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	claims, err := ClaimsProvider(store, stubRoles{operatorID: "someone-else"}).
		AccessTokenClaims(ctx, "user-1")
	if err != nil {
		t.Fatalf("AccessTokenClaims: %v", err)
	}
	if claims["plan"] != "pro" {
		t.Errorf("claims = %v, want the stored metadata", claims)
	}
	if _, hasRole := claims[RoleClaim]; hasRole {
		t.Error("a non-operator's token carries a role claim")
	}
}

// The second line of defence. Set refuses "role" outright (RoleClaim), so
// this can only be reached by a store that bypassed validation — but the
// merge order still has to put the real role last, because the day
// someone relaxes the write rule is the day this becomes the only thing
// standing between metadata and an operator token.
func TestClaimsProviderLetsTheRealRoleWinOverMetadata(t *testing.T) {
	ctx := context.Background()
	provider := ClaimsProvider(injectingStore{key: RoleClaim, value: "admin"},
		stubRoles{operatorID: "user-1", role: "support"})

	claims, err := provider.AccessTokenClaims(ctx, "user-1")
	if err != nil {
		t.Fatalf("AccessTokenClaims: %v", err)
	}
	if claims[RoleClaim] != "support" {
		t.Errorf("claims[%q] = %v, want the operator's real role", RoleClaim, claims[RoleClaim])
	}
}

// A store error must not be swallowed: a claims provider that returned a
// partial map on error would mint a token with fewer claims than the
// user has, which is worse than failing the login.
func TestClaimsProviderPropagatesStoreErrors(t *testing.T) {
	wantErr := errors.New("store is down")
	_, err := ClaimsProvider(failingStore{err: wantErr}, stubRoles{}).
		AccessTokenClaims(context.Background(), "user-1")
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want %v", err, wantErr)
	}

	_, err = ClaimsProvider(NewMemoryStore(), stubRoles{err: wantErr}).
		AccessTokenClaims(context.Background(), "user-1")
	if !errors.Is(err, wantErr) {
		t.Errorf("role lookup error = %v, want %v", err, wantErr)
	}
}

// A host with no operator table at all is a real configuration; nil must
// not panic.
func TestClaimsProviderAllowsNoOperatorLookup(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Set(ctx, "user-1", "plan", "pro"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	claims, err := ClaimsProvider(store, nil).AccessTokenClaims(ctx, "user-1")
	if err != nil {
		t.Fatalf("AccessTokenClaims: %v", err)
	}
	if claims["plan"] != "pro" {
		t.Errorf("claims = %v, want the stored metadata", claims)
	}
}

// injectingStore is a Store that hands back a key Set would have refused.
// It exists only to reach the merge-order defence above, which is
// otherwise unreachable by design.
type injectingStore struct{ key, value string }

func (s injectingStore) AllFor(context.Context, string) (map[string]any, error) {
	return map[string]any{s.key: s.value}, nil
}
func (s injectingStore) Set(context.Context, string, string, any) error { return nil }
func (s injectingStore) Delete(context.Context, string, string) error   { return nil }

type failingStore struct{ err error }

func (s failingStore) AllFor(context.Context, string) (map[string]any, error) { return nil, s.err }
func (s failingStore) Set(context.Context, string, string, any) error         { return s.err }
func (s failingStore) Delete(context.Context, string, string) error           { return s.err }
