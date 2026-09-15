package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crydensync/cryden/v2"

	"github.com/crydensync/api/config"
)

// apiKeyFixture is one signed-up, logged-in user plus the router built on
// the engine they live in. Every test below works through the real route
// table rather than calling a handler directly, because the routes are
// half of what these endpoints are: RequireAuth derives the user ID and
// cryden scopes every store call from it, so a handler called in
// isolation would prove neither.
type apiKeyFixture struct {
	engine *cryden.Engine
	router http.Handler
	userID string
	token  string
}

func newAPIKeyFixture(t *testing.T, email string) apiKeyFixture {
	t.Helper()
	return newAPIKeyFixtureOn(t, newTestEngine(t), email)
}

// newAPIKeyFixtureOn is newAPIKeyFixture against an engine the caller
// already holds. Two accounts sharing one engine is what makes the
// ownership assertion below a real one: a second store would answer 404
// for a key that simply isn't there, which proves nothing about the
// user_id predicate the store call actually carries.
func newAPIKeyFixtureOn(t *testing.T, engine *cryden.Engine, email string) apiKeyFixture {
	t.Helper()
	ctx := context.Background()

	user, err := cryden.SignUp(ctx, engine, email, testPassword, "203.0.113.10")
	if err != nil {
		t.Fatalf("signup (%s): %v", email, err)
	}
	tokens, err := cryden.Login(ctx, engine, email, testPassword, "203.0.113.10", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (%s): %v", email, err)
	}

	return apiKeyFixture{
		engine: engine,
		router: NewRouter(Deps{Engine: engine, Config: config.Config{}}),
		userID: user.ID,
		token:  tokens.AccessToken,
	}
}

func (f apiKeyFixture) call(t *testing.T, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// createResponse is the creation envelope: the raw key, the stored
// record, and the notice saying the raw key cannot be shown again.
type createResponse struct {
	Data struct {
		Key    string    `json:"key"`
		Notice string    `json:"notice"`
		APIKey apiKeyDTO `json:"api_key"`
	} `json:"data"`
}

func decodeCreate(t *testing.T, rec *httptest.ResponseRecorder) createResponse {
	t.Helper()
	var resp createResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// The one-time-display contract. A caller that loses the raw key has to
// mint a new one, so the response has to say so — and the key itself has
// to be absent from every later read, which is the half the engine
// guarantees by storing only its hash.
func TestAPIKeyCreateReturnsTheRawKeyExactlyOnce(t *testing.T) {
	f := newAPIKeyFixture(t, "dana@example.com")

	rec := f.call(t, http.MethodPost, "/v1/api-keys", `{"name":"ci deploy","scopes":["read"]}`, f.token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	created := decodeCreate(t, rec)

	if created.Data.Key == "" {
		t.Fatal("no raw key in the creation response — it is the only place it can ever appear")
	}
	if !strings.HasPrefix(created.Data.Key, "ck_") {
		t.Errorf("raw key %q does not carry the configured prefix", created.Data.Key)
	}
	if created.Data.Notice == "" {
		t.Error("no notice, so a client can render the key without telling the user it is unretrievable")
	}
	// The stored Prefix is the label plus a short fragment of the secret
	// ("ck_9f3a1c02") — cryden derives it from the raw key so the two can
	// never disagree, and it is what a list shows in place of the secret.
	if !strings.HasPrefix(created.Data.APIKey.Prefix, "ck_") {
		t.Errorf("stored prefix = %q, want a ck_<fragment> label", created.Data.APIKey.Prefix)
	}
	if created.Data.APIKey.ID == "" {
		t.Error("no id on the stored record, so there is nothing to revoke by")
	}
	// Scopes is an array in the response even when it was not sent, so a
	// client can iterate it without a nil check.
	if created.Data.APIKey.Scopes == nil {
		t.Error("scopes came back null, want an array")
	}

	// The listing is where a raw key would leak if the engine ever kept
	// one. It must not appear anywhere in the body — not as a field, not
	// as a prefix, not at all.
	listRec := f.call(t, http.MethodGet, "/v1/api-keys", "", f.token)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 (body %s)", listRec.Code, listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), created.Data.Key) {
		t.Errorf("the raw key appears in the listing: %s", listRec.Body.String())
	}

	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decoding list %s: %v", listRec.Body.String(), err)
	}
	if len(list.Data) != 1 {
		t.Fatalf("got %d keys, want the one that was just created", len(list.Data))
	}
	if _, present := list.Data[0]["key"]; present {
		t.Error("the listing carries a \"key\" field; only the creation response may")
	}
	if _, present := list.Data[0]["key_hash"]; present {
		t.Error("the listing carries a key_hash field")
	}
}

// Revocation is scoped by cryden itself: the store statement is
// WHERE id = $1 AND user_id = $2, so someone else's key and a key that
// does not exist answer identically. A caller must never be able to learn
// whether another account's key ID is real.
func TestAPIKeyRevokeIsScopedToTheCallingUser(t *testing.T) {
	owner := newAPIKeyFixture(t, "owner@example.com")
	// Both accounts live in ONE engine, so the 404 below is the store's
	// own "WHERE id = $1 AND user_id = $2" coming back empty rather than a
	// key that was never in a second store to begin with.
	other := newAPIKeyFixtureOn(t, owner.engine, "other@example.com")

	created := decodeCreate(t, owner.call(t, http.MethodPost, "/v1/api-keys", `{"name":"deploy"}`, owner.token))
	keyID := created.Data.APIKey.ID

	rec := other.call(t, http.MethodDelete, "/v1/api-keys/"+keyID, "", other.token)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "api_key_not_found") {
		t.Errorf("body = %s, want api_key_not_found", rec.Body.String())
	}

	// And the failed attempt changed nothing: the key is still live for
	// its actual owner.
	var list struct {
		Data []apiKeyDTO `json:"data"`
	}
	listRec := owner.call(t, http.MethodGet, "/v1/api-keys", "", owner.token)
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decoding owner's list %s: %v", listRec.Body.String(), err)
	}
	if len(list.Data) != 1 || list.Data[0].ID != keyID {
		t.Errorf("owner's keys = %+v, want the key another account failed to revoke", list.Data)
	}

	// The owner can, and afterwards it is gone from the listing rather
	// than listed as revoked — a revoked key is dealt with, and the list
	// is what is still live.
	ownRec := owner.call(t, http.MethodDelete, "/v1/api-keys/"+keyID, "", owner.token)
	if ownRec.Code != http.StatusOK {
		t.Fatalf("owner revoke status = %d, want 200 (body %s)", ownRec.Code, ownRec.Body.String())
	}
	if !strings.Contains(ownRec.Body.String(), "api key revoked") {
		t.Errorf("body = %s, want the status body DELETE /v1/sessions/{id} also returns", ownRec.Body.String())
	}

	listRec = owner.call(t, http.MethodGet, "/v1/api-keys", "", owner.token)
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decoding owner's list %s: %v", listRec.Body.String(), err)
	}
	if len(list.Data) != 0 {
		t.Errorf("after revoking, the listing still has %d keys: %+v", len(list.Data), list.Data)
	}

	// Revoking a second time is the same 404 — an already-revoked key is
	// indistinguishable from one that never existed.
	if again := owner.call(t, http.MethodDelete, "/v1/api-keys/"+keyID, "", owner.token); again.Code != http.StatusNotFound {
		t.Errorf("re-revoking status = %d, want 404", again.Code)
	}
}

// expires_in_days is the one field a caller supplies that can be wrong in
// a way the engine would report confusingly: it is multiplied by 24h
// before it reaches cryden, so a large enough value overflows into a
// negative duration and comes back as invalid_api_key_ttl. Bounding it
// here means the 400 says what is actually wrong.
func TestAPIKeyExpiryBounds(t *testing.T) {
	f := newAPIKeyFixture(t, "dana@example.com")

	t.Run("absent means never expires", func(t *testing.T) {
		created := decodeCreate(t, f.call(t, http.MethodPost, "/v1/api-keys", `{"name":"forever"}`, f.token))
		if created.Data.APIKey.ExpiresAt != nil {
			t.Errorf("expires_at = %v, want null", *created.Data.APIKey.ExpiresAt)
		}
		if created.Data.APIKey.Expired {
			t.Error("a key with no expiry reported itself as expired")
		}
	})

	t.Run("a positive value sets a future expiry", func(t *testing.T) {
		created := decodeCreate(t, f.call(t, http.MethodPost, "/v1/api-keys", `{"name":"90 days","expires_in_days":90}`, f.token))
		if created.Data.APIKey.ExpiresAt == nil {
			t.Fatal("expires_at = null, want the requested expiry")
		}
		if created.Data.APIKey.Expired {
			t.Error("a key minted with a 90-day expiry is already expired")
		}
	})

	for _, tc := range []struct {
		name string
		body string
	}{
		{"negative", `{"name":"past","expires_in_days":-1}`},
		{"absurd", `{"name":"forever","expires_in_days":4000}`},
		{"not a number", `{"name":"soon","expires_in_days":"90"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.call(t, http.MethodPost, "/v1/api-keys", tc.body, f.token)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "bad_request") {
				t.Errorf("body = %s, want a bad_request error", rec.Body.String())
			}
		})
	}

	t.Run("an over-long name is refused", func(t *testing.T) {
		body := `{"name":"` + strings.Repeat("x", 101) + `"}`
		if rec := f.call(t, http.MethodPost, "/v1/api-keys", body, f.token); rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

// Every route on this surface is behind RequireAuth, and the user ID the
// handlers act on comes from the token — never from a body or a path, so
// there is no parameter a caller could tamper with to reach another
// account's keys.
func TestAPIKeyRoutesRequireAuth(t *testing.T) {
	f := newAPIKeyFixture(t, "dana@example.com")

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/api-keys", `{"name":"x"}`},
		{http.MethodGet, "/v1/api-keys", ""},
		{http.MethodDelete, "/v1/api-keys/some-id", ""},
	} {
		rec := f.call(t, tc.method, tc.path, tc.body, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: status = %d, want 401", tc.method, tc.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "missing_auth_header") {
			t.Errorf("%s %s body = %s, want missing_auth_header", tc.method, tc.path, rec.Body.String())
		}
	}

	rec := f.call(t, http.MethodGet, "/v1/api-keys", "", "not-a-real-token")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a garbage token: status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
}
