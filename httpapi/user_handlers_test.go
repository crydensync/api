package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/usermeta"
)

// idAssigningAuditStore fills in the event id that cryden's Postgres store
// gets from gen_random_uuid() and its in-memory double does not set at all
// (see store/memory/audit_store.go's Record). Not a fix to cryden — a test
// double for a gap in cryden's own double, kept here rather than patched
// into the engine.
//
// It matters for these tests specifically: every endpoint on this surface
// keys on the audit event id, so a fixture that produced events with empty
// ids would be testing against rows no deployment can have.
type idAssigningAuditStore struct {
	store.AuditStore
	next int
}

func (s *idAssigningAuditStore) Record(ctx context.Context, event store.AuditEvent) error {
	s.next++
	// A real UUID shape, because the review store's foreign key is a uuid
	// column and looksLikeUUID guards the review path.
	event.ID = fmt.Sprintf("01a0a4ce-5453-78d3-9126-%012d", s.next)
	return s.AuditStore.Record(ctx, event)
}

// userFixture is an engine on in-memory stores, an admin token and an
// ordinary user's token, and the stores themselves so a test can seed
// events and lockouts.
type userFixture struct {
	engine   *cryden.Engine
	router   http.Handler
	users    *memory.UserStore
	sessions *memory.SessionStore
	audit    *idAssigningAuditStore

	// revocable is a SessionStore handle that can revoke, which the
	// engine's own interface also offers but which the fixture exposes so
	// a test can end a session without going through the engine.
	userID    string
	userToken string
	opID      string
	opToken   string
}

func newUserFixture(t *testing.T) userFixture {
	t.Helper()
	ctx := context.Background()

	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := &idAssigningAuditStore{AuditStore: memory.NewAuditStore()}

	var operatorID string
	roles := roleFunc(func(_ context.Context, userID string) (string, bool, error) {
		if userID == operatorID {
			return "admin", true, nil
		}
		return "", false, nil
	})

	engine, err := cryden.New(cryden.Config{
		JWTSecret:       "test-secret",
		Users:           users,
		Sessions:        sessions,
		Audit:           audit,
		Verifications:   memory.NewVerificationStore(),
		EmailSender:     stubMailSender{},
		MagicLinkSender: stubMailSender{},
		APIKeys:         memory.NewAPIKeyStore(),
		APIKeyPrefix:    "ck",
		// The real claims provider, not a stand-in: the role claim it
		// attaches is what RequireAdmin reads, so a fixture that faked it
		// would be testing a different gate than production has. The
		// metadata store behind it is empty — this surface does not read
		// metadata — and user_metadata's own tests cover the mapping.
		AccessTokenClaims: usermeta.ClaimsProvider(usermeta.NewMemoryStore(), roles),
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

	return userFixture{
		engine:    engine,
		router:    NewRouter(Deps{Engine: engine, Config: config.Config{}, Users: users, Sessions: sessions, Audit: audit, Meta: usermeta.NewMemoryStore()}),
		users:     users,
		sessions:  sessions,
		audit:     audit,
		userID:    user.ID,
		userToken: userTokens.AccessToken,
		opID:      operator.ID,
		opToken:   opTokens.AccessToken,
	}
}

func (f userFixture) call(t *testing.T, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

type userListResponse struct {
	Data struct {
		Users []struct {
			ID             string     `json:"id"`
			Email          string     `json:"email"`
			CreatedAt      time.Time  `json:"created_at"`
			FailedAttempts int        `json:"failed_attempts"`
			Locked         bool       `json:"locked"`
			LockedUntil    *time.Time `json:"locked_until"`
		} `json:"users"`
		Total  int    `json:"total"`
		Limit  int    `json:"limit"`
		Offset int    `json:"offset"`
		Match  string `json:"match"`
		Query  string `json:"query"`
	} `json:"data"`
}

type userDetailResponse struct {
	Data struct {
		User struct {
			ID             string     `json:"id"`
			Email          string     `json:"email"`
			FailedAttempts int        `json:"failed_attempts"`
			Locked         bool       `json:"locked"`
			LockedUntil    *time.Time `json:"locked_until"`
		} `json:"user"`
		ActiveSessions int `json:"active_sessions"`
		RecentActivity []struct {
			ID        string            `json:"id"`
			Type      string            `json:"type"`
			IP        string            `json:"ip"`
			Metadata  map[string]string `json:"metadata"`
			CreatedAt time.Time         `json:"created_at"`
		} `json:"recent_activity"`
	} `json:"data"`
}

func decodeUserList(t *testing.T, rec *httptest.ResponseRecorder) userListResponse {
	t.Helper()
	var resp userListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

func decodeUserDetail(t *testing.T, rec *httptest.ResponseRecorder) userDetailResponse {
	t.Helper()
	var resp userDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// Browsing returns every account newest-first with a total that matches,
// so a console can page and show "1-50 of N".
func TestUserListBrowsesNewestFirstWithATotal(t *testing.T) {
	f := newUserFixture(t)

	rec := f.call(t, http.MethodGet, "/v1/admin/users", f.opToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decodeUserList(t, rec)

	if got.Data.Match != "browse" {
		t.Errorf("match = %q, want browse", got.Data.Match)
	}
	if got.Data.Total != 2 {
		t.Errorf("total = %d, want 2", got.Data.Total)
	}
	if len(got.Data.Users) != 2 {
		t.Fatalf("users = %d, want 2", len(got.Data.Users))
	}
	// Newest first: the ordinary user signed up after the operator.
	if got.Data.Users[0].Email != "user@example.com" || got.Data.Users[1].Email != "operator@example.com" {
		t.Errorf("order = %q, %q, want newest (user) first", got.Data.Users[0].Email, got.Data.Users[1].Email)
	}
	if got.Data.Query != "" {
		t.Errorf("query = %q, want empty when browsing", got.Data.Query)
	}
}

func TestUserListPaginates(t *testing.T) {
	f := newUserFixture(t)

	got := decodeUserList(t, f.call(t, http.MethodGet, "/v1/admin/users?limit=1&offset=1", f.opToken))
	if len(got.Data.Users) != 1 {
		t.Fatalf("users = %d, want 1", len(got.Data.Users))
	}
	if got.Data.Users[0].Email != "operator@example.com" {
		t.Errorf("second page = %q, want the oldest account", got.Data.Users[0].Email)
	}
	// total is the table's count, not the page's — that is the whole point
	// of returning it.
	if got.Data.Total != 2 || got.Data.Limit != 1 || got.Data.Offset != 1 {
		t.Errorf("total/limit/offset = %d/%d/%d, want 2/1/1", got.Data.Total, got.Data.Limit, got.Data.Offset)
	}
}

// A search that found nothing succeeded. Answering 404 here would make a
// console render an error for the most ordinary outcome a search has.
func TestUserSearchForAnUnknownEmailIsAnEmptyPageNot404(t *testing.T) {
	f := newUserFixture(t)

	rec := f.call(t, http.MethodGet, "/v1/admin/users?q=nobody@example.com", f.opToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decodeUserList(t, rec)
	if got.Data.Total != 0 || len(got.Data.Users) != 0 {
		t.Errorf("total/users = %d/%d, want an empty result", got.Data.Total, len(got.Data.Users))
	}
	if got.Data.Match != "exact_email" {
		t.Errorf("match = %q, want exact_email", got.Data.Match)
	}
	if got.Data.Query != "nobody@example.com" {
		t.Errorf("query = %q, want the search echoed back", got.Data.Query)
	}
	// Present and empty rather than null, so a console ranges over it.
	if !strings.Contains(rec.Body.String(), `"users":[]`) {
		t.Errorf("body = %s, want users to render as [] rather than null", rec.Body.String())
	}
}

func TestUserSearchFindsAnExactEmail(t *testing.T) {
	f := newUserFixture(t)

	got := decodeUserList(t, f.call(t, http.MethodGet, "/v1/admin/users?q=user@example.com", f.opToken))
	if got.Data.Total != 1 || len(got.Data.Users) != 1 {
		t.Fatalf("total/users = %d/%d, want exactly one", got.Data.Total, len(got.Data.Users))
	}
	if got.Data.Users[0].ID != f.userID {
		t.Errorf("id = %q, want %q", got.Data.Users[0].ID, f.userID)
	}
}

// The surprising half of an exact match, asserted so it is a documented
// behaviour rather than a bug report: cryden stores an address exactly as
// it was typed and matches it with SQL's `=`, so a search is
// case-sensitive. This is why the response carries `match`.
func TestUserSearchIsCaseSensitive(t *testing.T) {
	f := newUserFixture(t)

	got := decodeUserList(t, f.call(t, http.MethodGet, "/v1/admin/users?q=User@Example.com", f.opToken))
	if got.Data.Total != 0 {
		t.Errorf("total = %d, want 0 — the lookup is exact and case-sensitive", got.Data.Total)
	}
	// The label is what stops an operator reading that as "no such account".
	if got.Data.Match != "exact_email" {
		t.Errorf("match = %q, want the exact match to be labelled", got.Data.Match)
	}
}

// `?q=` is a search nobody filled in, not a search for the empty string.
func TestUserSearchWithAnEmptyQueryBrowses(t *testing.T) {
	f := newUserFixture(t)

	got := decodeUserList(t, f.call(t, http.MethodGet, "/v1/admin/users?q=", f.opToken))
	if got.Data.Match != "browse" || got.Data.Total != 2 {
		t.Errorf("match/total = %q/%d, want browse/2", got.Data.Match, got.Data.Total)
	}
}

// A limit or offset the caller got wrong is reported rather than clamped
// silently — the same rule queryInt applies everywhere else.
func TestUserListRejectsOutOfRangePaging(t *testing.T) {
	f := newUserFixture(t)

	for _, path := range []string{
		"/v1/admin/users?limit=0",
		"/v1/admin/users?limit=5000",
		"/v1/admin/users?offset=-1",
		"/v1/admin/users?offset=999999",
		"/v1/admin/users?limit=abc",
	} {
		rec := f.call(t, http.MethodGet, path, f.opToken)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s status = %d, want 400 (body %s)", path, rec.Code, rec.Body.String())
		}
	}
}

func TestUserDetailReportsSessionsAndHistory(t *testing.T) {
	f := newUserFixture(t)
	ctx := context.Background()

	if err := f.audit.Record(ctx, store.AuditEvent{
		Type: store.EventLoginSuccess, UserID: f.userID, IP: "203.0.113.2",
	}); err != nil {
		t.Fatalf("recording event: %v", err)
	}
	if err := f.audit.Record(ctx, store.AuditEvent{
		Type:     store.EventAnomalyDetected,
		UserID:   f.userID,
		IP:       "198.51.100.7",
		Metadata: map[string]string{"signals": "new_device,new_ip"},
	}); err != nil {
		t.Fatalf("recording event: %v", err)
	}

	rec := f.call(t, http.MethodGet, "/v1/admin/users/"+f.userID, f.opToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decodeUserDetail(t, rec)

	if got.Data.User.ID != f.userID || got.Data.User.Email != "user@example.com" {
		t.Errorf("user = %+v, want the account that was asked for", got.Data.User)
	}
	// One live session from the login in the fixture; the operator's
	// session must not be counted here.
	if got.Data.ActiveSessions != 1 {
		t.Errorf("active_sessions = %d, want 1", got.Data.ActiveSessions)
	}
	// The fixture's own signup and login are audited too, so this is the
	// account's whole recorded history rather than just what the test
	// seeded — which is the point of the endpoint. Asserting the exact
	// length would bake in how many events the engine happens to write per
	// signup, so the assertions are about content and order instead.
	if len(got.Data.RecentActivity) < 2 {
		t.Fatalf("recent_activity = %d events, want at least the two seeded", len(got.Data.RecentActivity))
	}
	// Newest first, and metadata passes through in cryden's own
	// vocabulary rather than being renamed.
	newest := got.Data.RecentActivity[0]
	if newest.Type != string(store.EventAnomalyDetected) {
		t.Errorf("newest event = %q, want the anomaly that was recorded last", newest.Type)
	}
	if newest.Metadata["signals"] != "new_device,new_ip" {
		t.Errorf("metadata = %v, want the engine's own keys", newest.Metadata)
	}
	if newest.ID == "" {
		t.Error("event id is empty — every review endpoint keys on it")
	}

	var sawLogin bool
	for _, e := range got.Data.RecentActivity {
		if e.Type == string(store.EventLoginSuccess) {
			sawLogin = true
		}
	}
	if !sawLogin {
		t.Error("history has no login_success — the account's own events are missing from its history")
	}
}

// Revoked sessions are not live sessions. cryden's ListByUser filters on
// revoked_at IS NULL, and this asserts the fixture and the count agree.
func TestUserDetailCountsOnlyLiveSessions(t *testing.T) {
	f := newUserFixture(t)
	ctx := context.Background()

	sessions, err := f.sessions.ListByUser(ctx, f.userID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want the one the fixture logged in with", len(sessions))
	}
	if err := f.sessions.Revoke(ctx, sessions[0].ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got := decodeUserDetail(t, f.call(t, http.MethodGet, "/v1/admin/users/"+f.userID, f.opToken))
	if got.Data.ActiveSessions != 0 {
		t.Errorf("active_sessions = %d, want 0 after the session was revoked", got.Data.ActiveSessions)
	}
	// The session rows still exist — this is a count of live ones, not a
	// count of rows.
	all, err := f.sessions.ListByUser(ctx, f.userID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("ListByUser = %d, want the store to agree that nothing is live", len(all))
	}
}

// The subtle one. cryden clears a lockout by time passing rather than by
// clearing the column, so an expired locked_until is still non-nil. An
// operator shown "locked" for an account that is not would go looking for
// a problem that has already resolved itself.
func TestUserDetailReportsLockedFromTheDeadlineNotTheColumn(t *testing.T) {
	f := newUserFixture(t)
	ctx := context.Background()

	if err := f.users.LockAccount(ctx, f.userID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("LockAccount: %v", err)
	}
	got := decodeUserDetail(t, f.call(t, http.MethodGet, "/v1/admin/users/"+f.userID, f.opToken))
	if !got.Data.User.Locked {
		t.Error("locked = false, want true for a deadline in the future")
	}
	if got.Data.User.LockedUntil == nil {
		t.Error("locked_until = nil, want the stored deadline reported alongside")
	}

	// Now the same column holding a deadline that has passed.
	if err := f.users.LockAccount(ctx, f.userID, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("LockAccount: %v", err)
	}
	got = decodeUserDetail(t, f.call(t, http.MethodGet, "/v1/admin/users/"+f.userID, f.opToken))
	if got.Data.User.Locked {
		t.Error("locked = true for a deadline in the past — a lockout that expired is not a lockout")
	}
	if got.Data.User.LockedUntil == nil {
		t.Error("locked_until = nil, want the expired deadline still visible")
	}
}

// The reason the DTO exists at all. This asserts on the raw body rather
// than on a decoded struct, because a struct that happens not to have the
// field proves nothing about what was written.
func TestAdminUserResponsesNeverCarryAPasswordHash(t *testing.T) {
	f := newUserFixture(t)

	for _, path := range []string{
		"/v1/admin/users",
		"/v1/admin/users?q=user@example.com",
		"/v1/admin/users/" + f.userID,
	} {
		rec := f.call(t, http.MethodGet, path, f.opToken)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, rec.Code)
		}
		body := rec.Body.String()
		for _, leak := range []string{"password_hash", "PasswordHash", "$2a$", "$2b$", "argon2id$"} {
			if strings.Contains(body, leak) {
				t.Errorf("GET %s body contains %q — a hash must never reach a response: %s", path, leak, body)
			}
		}
	}

	// The fixture's users do have hashes, so the assertion above is not
	// passing because there was nothing to leak.
	stored, err := f.users.GetByID(context.Background(), f.userID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.PasswordHash == "" {
		t.Fatal("the stored user has no password hash — this test would pass vacuously")
	}
}

// An unknown user and an id that could never be a user both answer 404.
// The second half is the one that matters: handed to Postgres, a malformed
// id is a driver error that mapError turns into a 500.
func TestUserDetailUnknownOrMalformedIDIs404(t *testing.T) {
	f := newUserFixture(t)

	for _, tc := range []struct{ name, userID string }{
		{"well-formed but unknown", "01a0a4ce-5453-78d3-9126-000000000000"},
		{"not a uuid at all", "not-a-uuid"},
		{"a uuid with a stray character", "01a0a4ce-5453-78d3-9126-52268da8da5z"},
		{"empty-ish", "%20"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.call(t, http.MethodGet, "/v1/admin/users/"+tc.userID, f.opToken)
			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// The more specific metadata route must still win over the detail route,
// which now matches a bare /v1/admin/users/{userID} as well.
func TestUserDetailRouteDoesNotShadowTheMetadataRoutes(t *testing.T) {
	f := newUserFixture(t)

	rec := f.call(t, http.MethodGet, "/v1/admin/users/"+f.userID+"/metadata", f.opToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET metadata status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "reserved_claim_names") {
		t.Errorf("body = %s, want the metadata response — the detail route shadowed it", rec.Body.String())
	}
}

func TestUserRoutesRequireAdmin(t *testing.T) {
	f := newUserFixture(t)

	for _, path := range []string{"/v1/admin/users", "/v1/admin/users/" + f.userID} {
		rec := f.call(t, http.MethodGet, path, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with no token: status = %d, want 401", path, rec.Code)
		}

		rec = f.call(t, http.MethodGet, path, f.userToken)
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s with an ordinary user's token: status = %d, want 403 (body %s)",
				path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not_operator") {
			t.Errorf("GET %s body = %s, want not_operator", path, rec.Body.String())
		}
	}
}

// A router built without the stores is a wiring fact, not a server fault.
func TestUserEndpointsWithoutStoresAre404(t *testing.T) {
	f := newUserFixture(t)
	router := NewRouter(Deps{Engine: f.engine, Config: config.Config{}})

	for _, path := range []string{"/v1/admin/users", "/v1/admin/users/" + f.userID} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+f.opToken)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404 (body %s)", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not_configured") {
			t.Errorf("GET %s body = %s, want not_configured", path, rec.Body.String())
		}
	}
}
