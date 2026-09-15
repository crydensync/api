package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/memory"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/usermeta"
)

// roleFunc lets a test answer RoleFor without a database, the same job
// operator.Store does in production.
type roleFunc func(ctx context.Context, userID string) (string, bool, error)

func (f roleFunc) RoleFor(ctx context.Context, userID string) (string, bool, error) {
	return f(ctx, userID)
}

// metadataFixture is an engine whose claims provider is the real one —
// usermeta.ClaimsProvider, the same call main.go makes — plus a router
// wired with the same user store the engine holds.
//
// That last part matters: Deps.Users is what the handlers use to answer
// "does this user exist", and a second store instance would 404 every
// user the engine had just created.
type metadataFixture struct {
	engine *cryden.Engine
	router http.Handler
	meta   *usermeta.MemoryStore

	// user and operator are two real accounts: the first is an ordinary
	// end user whose metadata is being mapped, the second holds the role
	// claim RequireAdmin wants.
	userID    string
	userToken string
	opID      string
	opToken   string
}

func newMetadataFixture(t *testing.T) metadataFixture {
	t.Helper()
	ctx := context.Background()

	users := memory.NewUserStore()
	meta := usermeta.NewMemoryStore()

	// The operator is identified by id, which is only known after signup
	// — so the closure reads it from here, exactly as operator.Store
	// would answer from its table.
	var operatorID string
	roles := roleFunc(func(_ context.Context, userID string) (string, bool, error) {
		if userID == operatorID {
			return "admin", true, nil
		}
		return "", false, nil
	})

	engine, err := cryden.New(cryden.Config{
		JWTSecret:         "test-secret",
		Users:             users,
		Sessions:          memory.NewSessionStore(),
		Audit:             memory.NewAuditStore(),
		Verifications:     memory.NewVerificationStore(),
		EmailSender:       stubMailSender{},
		MagicLinkSender:   stubMailSender{},
		APIKeys:           memory.NewAPIKeyStore(),
		APIKeyPrefix:      "ck",
		AccessTokenClaims: usermeta.ClaimsProvider(meta, roles),
	})
	if err != nil {
		t.Fatalf("building engine: %v", err)
	}

	operator, err := cryden.SignUp(ctx, engine, "operator@example.com", testPassword, "203.0.113.1")
	if err != nil {
		t.Fatalf("signup (operator): %v", err)
	}
	operatorID = operator.ID
	opTokens, err := cryden.Login(ctx, engine, "operator@example.com", testPassword, "203.0.113.1", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (operator): %v", err)
	}

	user, err := cryden.SignUp(ctx, engine, "user@example.com", testPassword, "203.0.113.2")
	if err != nil {
		t.Fatalf("signup (user): %v", err)
	}
	userTokens, err := cryden.Login(ctx, engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (user): %v", err)
	}

	return metadataFixture{
		engine:    engine,
		router:    NewRouter(Deps{Engine: engine, Config: config.Config{}, Users: users, Meta: meta}),
		meta:      meta,
		userID:    user.ID,
		userToken: userTokens.AccessToken,
		opID:      operator.ID,
		opToken:   opTokens.AccessToken,
	}
}

func (f metadataFixture) call(t *testing.T, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func metadataPath(userID, key string) string {
	base := "/v1/admin/users/" + userID + "/metadata"
	if key != "" {
		return base + "/" + key
	}
	return base
}

type metadataResponse struct {
	Data struct {
		UserID             string         `json:"user_id"`
		Metadata           map[string]any `json:"metadata"`
		ReservedClaimNames []string       `json:"reserved_claim_names"`
	} `json:"data"`
}

func decodeMetadata(t *testing.T, rec *httptest.ResponseRecorder) metadataResponse {
	t.Helper()
	var resp metadataResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// The claim the whole feature exists for. This asserts through a token
// the engine actually issued, not through the store: it is the only
// check that proves the wiring in main.go's Config.AccessTokenClaims is
// connected to the table the admin endpoints write.
func TestMetadataKeyReachesAFreshlyIssuedToken(t *testing.T) {
	f := newMetadataFixture(t)

	rec := f.call(t, http.MethodPut, metadataPath(f.userID, "plan"), `{"value":"pro"}`, f.opToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	// A NEW login: claims are attached when a token is issued, so a
	// token minted before the write would prove nothing.
	tokens, err := cryden.Login(context.Background(), f.engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	userID, claims, err := cryden.VerifyTokenWithClaims(f.engine, tokens.AccessToken)
	if err != nil {
		t.Fatalf("verifying token: %v", err)
	}
	if userID != f.userID {
		t.Fatalf("token subject = %q, want %q", userID, f.userID)
	}
	if claims["plan"] != "pro" {
		t.Errorf("claims = %v, want plan=pro", claims)
	}
	// An ordinary user, so no role — see usermeta.RoleClaim for why that
	// absence has to stay an absence.
	if _, hasRole := claims["role"]; hasRole {
		t.Errorf("claims = %v, want no role claim for an ordinary user", claims)
	}
}

// The escalation this feature would otherwise open. Every metadata key
// becomes a claim, and RequireAdmin reads "role" — so a key of "role"
// would mint an operator token for a user the operators table has never
// heard of, and revoking an operator would not take it away.
func TestMetadataCannotGrantOperatorStatus(t *testing.T) {
	f := newMetadataFixture(t)

	rec := f.call(t, http.MethodPut, metadataPath(f.userID, "role"), `{"value":"admin"}`, f.opToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT role status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "reserved_metadata_key") {
		t.Errorf("body = %s, want reserved_metadata_key", rec.Body.String())
	}

	// And the user still cannot reach an admin route.
	tokens, err := cryden.Login(context.Background(), f.engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	admin := f.call(t, http.MethodGet, metadataPath(f.userID, ""), "", tokens.AccessToken)
	if admin.Code != http.StatusForbidden {
		t.Errorf("admin route with the user's token: status = %d, want 403", admin.Code)
	}
}

// A registered JWT claim name is refused where an operator can still see
// why. Stored, it would not be ignored — cryden's checkExtraClaims
// rejects it while building the token, so every login for that user
// would fail with the cause sitting in a different table.
func TestMetadataRefusesRegisteredClaimNames(t *testing.T) {
	f := newMetadataFixture(t)

	for _, key := range []string{"sub", "iss", "aud", "exp", "nbf", "iat", "jti"} {
		rec := f.call(t, http.MethodPut, metadataPath(f.userID, key), `{"value":"x"}`, f.opToken)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %q status = %d, want 400", key, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), "reserved_metadata_key") {
			t.Errorf("PUT %q body = %s, want reserved_metadata_key", key, rec.Body.String())
		}
	}

	// The login still works, which is the point of refusing at write time.
	if _, err := cryden.Login(context.Background(), f.engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS); err != nil {
		t.Fatalf("login after refused writes: %v", err)
	}
}

// A key that is not a claim name is refused by the store, and the refusal
// reaches the client as a 400 with a code that says which rule it broke.
//
// Two of the keys below are percent-escaped because that is the only way a
// console can put them in a path at all: the router matches one segment and
// hands the handler the *decoded* value, so %2F arrives as "a/b" and is
// judged on its merits rather than being rejected by URL parsing.
func TestMetadataRejectsKeysThatAreNotClaimNames(t *testing.T) {
	f := newMetadataFixture(t)

	for _, tc := range []struct{ name, key string }{
		{"starts with a digit", "1st"},
		{"contains a slash", "a%2Fb"},
		{"too long", strings.Repeat("a", 65)},
		{"only whitespace", "%20"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.call(t, http.MethodPut, metadataPath(f.userID, tc.key), `{"value":"x"}`, f.opToken)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "invalid_metadata_key") {
				t.Errorf("body = %s, want invalid_metadata_key", rec.Body.String())
			}
		})
	}

	// None of them landed, so a refused key is refused rather than written
	// and reported.
	if keys := f.meta.Keys(f.userID); len(keys) != 0 {
		t.Errorf("keys after refused requests = %v, want none", keys)
	}
}

// "value": null is a value. A missing field is a client bug. Both are
// easy to conflate by decoding into an `any`, so the distinction is
// asserted rather than assumed.
func TestMetadataDistinguishesNullFromAbsent(t *testing.T) {
	f := newMetadataFixture(t)

	rec := f.call(t, http.MethodPut, metadataPath(f.userID, "note"), `{"value":null}`, f.opToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT null status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if _, present := decodeMetadata(t, rec).Data.Metadata["note"]; !present {
		t.Error("a stored null is missing from the response — null is a value, not an absence")
	}

	for _, body := range []string{`{}`, `{"value":`} {
		if rec := f.call(t, http.MethodPut, metadataPath(f.userID, "note"), body, f.opToken); rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s status = %d, want 400", body, rec.Code)
		}
	}
}

func TestMetadataRoundTripAndDelete(t *testing.T) {
	f := newMetadataFixture(t)

	if rec := f.call(t, http.MethodPut, metadataPath(f.userID, "tenant"), `{"value":"acme"}`, f.opToken); rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := f.call(t, http.MethodPut, metadataPath(f.userID, "seats"), `{"value":12}`, f.opToken); rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	rec := f.call(t, http.MethodGet, metadataPath(f.userID, ""), "", f.opToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decodeMetadata(t, rec)
	if got.Data.UserID != f.userID {
		t.Errorf("user_id = %q, want %q", got.Data.UserID, f.userID)
	}
	if got.Data.Metadata["tenant"] != "acme" {
		t.Errorf("tenant = %#v, want \"acme\"", got.Data.Metadata["tenant"])
	}
	// JSON numbers come back as float64 — the same thing the JSONB column
	// decodes to, so a console sees one shape in both stores.
	if got.Data.Metadata["seats"] != float64(12) {
		t.Errorf("seats = %#v, want float64(12)", got.Data.Metadata["seats"])
	}

	// The reserved list is what a console greys out, so it has to be
	// present and complete rather than a token gesture.
	if len(got.Data.ReservedClaimNames) != 8 {
		t.Errorf("reserved_claim_names = %v, want the seven registered names plus role", got.Data.ReservedClaimNames)
	}

	// Replace, not accumulate.
	if rec := f.call(t, http.MethodPut, metadataPath(f.userID, "tenant"), `{"value":"globex"}`, f.opToken); rec.Code != http.StatusOK {
		t.Fatalf("PUT (replace) status = %d, want 200", rec.Code)
	}
	if all := decodeMetadata(t, f.call(t, http.MethodGet, metadataPath(f.userID, ""), "", f.opToken)).Data.Metadata; all["tenant"] != "globex" {
		t.Errorf("tenant = %#v, want \"globex\"", all["tenant"])
	}

	// DELETE answers with the updated set, so a save is also the refresh.
	rec = f.call(t, http.MethodDelete, metadataPath(f.userID, "tenant"), "", f.opToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if _, present := decodeMetadata(t, rec).Data.Metadata["tenant"]; present {
		t.Error("the deleted key is still in the response")
	}

	// Deleting it twice reports that there was nothing to delete, rather
	// than showing a success that did not happen.
	again := f.call(t, http.MethodDelete, metadataPath(f.userID, "tenant"), "", f.opToken)
	if again.Code != http.StatusNotFound {
		t.Errorf("second DELETE status = %d, want 404", again.Code)
	}
	if !strings.Contains(again.Body.String(), "metadata_key_not_found") {
		t.Errorf("body = %s, want metadata_key_not_found", again.Body.String())
	}

	// The store agrees with the responses.
	if keys := f.meta.Keys(f.userID); len(keys) != 1 || keys[0] != "seats" {
		t.Errorf("stored keys = %v, want just \"seats\"", keys)
	}
}

// An unknown user, and an id that could never be a user, both answer 404.
// The second half is the one that matters: handed straight to Postgres, a
// malformed id is a driver error — "invalid input syntax for type uuid" —
// which mapError turns into a 500 an operator reads as a bug in the API.
func TestMetadataUnknownOrMalformedUserIs404(t *testing.T) {
	f := newMetadataFixture(t)

	for _, tc := range []struct{ name, userID string }{
		{"well-formed but unknown", "01a0a4ce-5453-78d3-9126-000000000000"},
		{"not a uuid at all", "not-a-uuid"},
		{"a uuid with a stray character", "01a0a4ce-5453-78d3-9126-52268da8da5z"},
		{"too short", "01a0a4ce-5453-78d3-9126-52268da8da5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, call := range []struct {
				method, body string
			}{
				{http.MethodGet, ""},
				{http.MethodPut, `{"value":1}`},
				{http.MethodDelete, ""},
			} {
				path := metadataPath(tc.userID, "plan")
				if call.method == http.MethodGet {
					path = metadataPath(tc.userID, "")
				}
				rec := f.call(t, call.method, path, call.body, f.opToken)
				if rec.Code != http.StatusNotFound {
					t.Errorf("%s status = %d, want 404 (body %s)", call.method, rec.Code, rec.Body.String())
				}
				if rec.Code == http.StatusInternalServerError {
					t.Errorf("%s reached the database with a malformed id", call.method)
				}
			}
		})
	}
}

// Every route here is admin-only, and the gate is the same one the rest of
// the admin surface uses.
func TestMetadataRoutesRequireAdmin(t *testing.T) {
	f := newMetadataFixture(t)

	paths := []struct{ method, path, body string }{
		{http.MethodGet, metadataPath(f.userID, ""), ""},
		{http.MethodPut, metadataPath(f.userID, "plan"), `{"value":"pro"}`},
		{http.MethodDelete, metadataPath(f.userID, "plan"), ""},
	}

	for _, tc := range paths {
		rec := f.call(t, tc.method, tc.path, tc.body, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no token: status = %d, want 401", tc.method, tc.path, rec.Code)
		}

		rec = f.call(t, tc.method, tc.path, tc.body, f.userToken)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with an ordinary user's token: status = %d, want 403 (body %s)",
				tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not_operator") {
			t.Errorf("%s %s body = %s, want not_operator", tc.method, tc.path, rec.Body.String())
		}
	}

	// And nothing was written by any of those attempts.
	if keys := f.meta.Keys(f.userID); len(keys) != 0 {
		t.Errorf("keys after refused requests = %v, want none", keys)
	}
}

// A router built without the metadata stores is a wiring fact, not a
// server fault — 404, the same shape as every other unconfigured feature.
func TestMetadataWithoutStoresIs404(t *testing.T) {
	f := newMetadataFixture(t)
	router := NewRouter(Deps{Engine: f.engine, Config: config.Config{}})

	req := httptest.NewRequest(http.MethodGet, metadataPath(f.userID, ""), nil)
	req.Header.Set("Authorization", "Bearer "+f.opToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_configured") {
		t.Errorf("body = %s, want not_configured", rec.Body.String())
	}
}

// Two accounts, one table: nothing an operator does to one user's
// metadata may be visible on another's.
func TestMetadataIsScopedPerUser(t *testing.T) {
	f := newMetadataFixture(t)

	if rec := f.call(t, http.MethodPut, metadataPath(f.userID, "plan"), `{"value":"pro"}`, f.opToken); rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	rec := f.call(t, http.MethodGet, metadataPath(f.opID, ""), "", f.opToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET (operator) status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := decodeMetadata(t, rec).Data.Metadata; len(got) != 0 {
		t.Errorf("the operator sees %v on their own record, want nothing", got)
	}
}
