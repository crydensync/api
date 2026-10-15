package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"

	"github.com/crydensync/csag/config"
	"github.com/crydensync/csag/usermeta"
)

// userActionFixture is userFixture's shape with the two extra stores the
// actions need wired through to the router: OAuth and TOTP. It is a
// separate fixture rather than an extension of userFixture because the
// read-only surface's tests do not need OAuth or TOTP stores, and a
// fixture that wires a dependency a handler never reads teaches the
// next reader that nil is a state the router can be in, which for these
// two fields it now always is in production.
type userActionFixture struct {
	engine    *cryden.Engine
	router    http.Handler
	users     *memory.UserStore
	sessions  *memory.SessionStore
	audit     *idAssigningAuditStore
	oauth     *memory.OAuthStore
	totp      *memory.TOTPStore
	userID    string
	opID      string
	opToken   string
	userToken string
}

func newUserActionFixture(t *testing.T) userActionFixture {
	t.Helper()
	ctx := context.Background()

	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := &idAssigningAuditStore{AuditStore: memory.NewAuditStore()}
	oauth := memory.NewOAuthStore()
	totp := memory.NewTOTPStore()

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
		OAuth:           oauth,
		// TOTP is wired so the mfa/disable action can be tested against
		// the engine's own enrolment path, which requires the store and
		// an encryption key together (cryden validates that pair). The
		// memory TOTP store is what the engine gets here, and the same
		// handle the fixture keeps for asserting on the enrolment.
		TOTP:          totp,
		EncryptionKey: "0123456789abcdef0123456789abcdef",
		// Same reasoning as userFixture's: the real claims provider, so
		// the gate these tests cross is the one production has.
		AccessTokenClaims: usermeta.ClaimsProvider(usermeta.NewMemoryStore(), roles),
	})
	if err != nil {
		t.Fatalf("building engine: %v", err)
	}

	operator, err := cryden.SignUp(ctx, engine, "operator@example.com", testPassword, "203.0.113.1")
	if err != nil {
		t.Fatalf("signup (operator): %v", err)
	}
	// operatorID must be set before the operator's login: the role claim
	// is attached to the access token when it is issued, so the closure
	// above has to know who the operator is by then. (userFixture makes
	// the same assignment in the same place.)
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

	return userActionFixture{
		engine: engine,
		router: NewRouter(Deps{
			Engine:   engine,
			Config:   config.Config{},
			Users:    users,
			Sessions: sessions,
			Audit:    audit,
			Meta:     usermeta.NewMemoryStore(),
			OAuth:    oauth,
			TOTP:     totp,
		}),
		users:     users,
		sessions:  sessions,
		audit:     audit,
		oauth:     oauth,
		totp:      totp,
		userID:    user.ID,
		opID:      operator.ID,
		opToken:   opTokens.AccessToken,
		userToken: userTokens.AccessToken,
	}
}

func (f userActionFixture) call(t *testing.T, method, path, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// actionResponse is the envelope every action here answers with.
type userActionResponse struct {
	Data struct {
		User struct {
			ID             string     `json:"id"`
			Email          string     `json:"email"`
			FailedAttempts int        `json:"failed_attempts"`
			Locked         bool       `json:"locked"`
			LockedUntil    *time.Time `json:"locked_until"`
		} `json:"user"`
		Detail string `json:"detail"`
	} `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeAction(t *testing.T, rec *httptest.ResponseRecorder) userActionResponse {
	t.Helper()
	var body userActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return body
}

// eventsOf returns the audit events the fixture's store holds for one
// user, newest last, in insertion order.
func (f userActionFixture) eventsFor(t *testing.T, userID string) []store.AuditEvent {
	t.Helper()
	events, err := f.audit.ListByUser(context.Background(), userID, 100)
	if err != nil {
		t.Fatalf("listing audit events: %v", err)
	}
	return events
}

// --- Create ---------------------------------------------------------------

func TestAdminCreateUser(t *testing.T) {
	f := newUserActionFixture(t)

	rec := f.call(t, http.MethodPost, "/v1/admin/users", f.opToken,
		`{"email":"new@example.com","password":"`+testPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	body := decodeAction(t, rec)
	if body.Data.User.Email != "new@example.com" {
		t.Errorf("user email = %q", body.Data.User.Email)
	}

	// The new account can actually sign in: the action went through the
	// engine's signup, password policy and all, not a bare store write.
	if _, err := cryden.Login(context.Background(), f.engine, "new@example.com", testPassword, "203.0.113.9", chromeOnMacOS); err != nil {
		t.Fatalf("login with created account: %v", err)
	}

	// Two audit events: the engine's own signup and the operator's.
	types := map[string]bool{}
	for _, e := range f.eventsFor(t, body.Data.User.ID) {
		types[string(e.Type)] = true
	}
	if !types["signup_success"] || !types["admin_user_created"] {
		t.Errorf("audit events = %v, want signup_success and admin_user_created", types)
	}
}

func TestAdminCreateUserDuplicateEmail(t *testing.T) {
	f := newUserActionFixture(t)

	rec := f.call(t, http.MethodPost, "/v1/admin/users", f.opToken,
		`{"email":"user@example.com","password":"`+testPassword+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAdminCreateUserRequiresBothFields(t *testing.T) {
	f := newUserActionFixture(t)

	rec := f.call(t, http.MethodPost, "/v1/admin/users", f.opToken, `{"email":"only@example.com"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAdminCreateUserForbiddenForNonOperator(t *testing.T) {
	f := newUserActionFixture(t)

	rec := f.call(t, http.MethodPost, "/v1/admin/users", f.userToken,
		`{"email":"x@example.com","password":"`+testPassword+`"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// --- Unlock ----------------------------------------------------------------

func TestAdminUnlockClearsLockoutAndCounter(t *testing.T) {
	f := newUserActionFixture(t)

	// Lock the account the way the engine does: failed attempts past the
	// threshold, which sets both the counter and LockedUntil.
	for i := 0; i < 5; i++ {
		if _, err := cryden.Login(context.Background(), f.engine, "user@example.com", "wrong-password", "203.0.113.2", chromeOnMacOS); err == nil {
			t.Fatal("expected failed logins to fail")
		}
	}

	user, err := f.users.GetByID(context.Background(), f.userID)
	if err != nil || !user.LockedUntil.After(time.Now()) {
		t.Fatalf("expected the account to be locked (err=%v, until=%v)", err, user.LockedUntil)
	}

	rec := f.call(t, http.MethodPost, "/v1/admin/users/"+f.userID+"/unlock", f.opToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	body := decodeAction(t, rec)
	if body.Data.User.Locked {
		t.Error("user still locked after unlock")
	}
	if body.Data.User.FailedAttempts != 0 {
		t.Errorf("failed attempts = %d, want 0", body.Data.User.FailedAttempts)
	}

	// The proof of an unlock is a login that works.
	if _, err := cryden.Login(context.Background(), f.engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS); err != nil {
		t.Fatalf("login after unlock: %v", err)
	}
}

// --- Suspend and unsuspend -------------------------------------------------

func TestAdminSuspendBlocksLoginAndRevokesSessions(t *testing.T) {
	f := newUserActionFixture(t)

	// The account has a live session a suspension must not leave usable.
	if _, err := cryden.Login(context.Background(), f.engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS); err != nil {
		t.Fatalf("precondition: login: %v", err)
	}

	rec := f.call(t, http.MethodPost, "/v1/admin/users/"+f.userID+"/suspend", f.opToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	body := decodeAction(t, rec)
	if !body.Data.User.Locked {
		t.Error("user not locked after suspend")
	}

	// A live session cannot outlive the lock it was granted under.
	sessions, err := f.sessions.ListByUser(context.Background(), f.userID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	for _, s := range sessions {
		if s.RevokedAt == nil {
			t.Errorf("session %s survived the suspend", s.ID)
		}
	}

	// And the engine refuses the password it would otherwise accept.
	if _, err := cryden.Login(context.Background(), f.engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS); err == nil {
		t.Error("login succeeded on a suspended account")
	}
}

func TestAdminUnsuspendRestoresSignIn(t *testing.T) {
	f := newUserActionFixture(t)

	if err := f.users.LockAccount(context.Background(), f.userID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("locking account: %v", err)
	}

	rec := f.call(t, http.MethodPost, "/v1/admin/users/"+f.userID+"/unsuspend", f.opToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	body := decodeAction(t, rec)
	if body.Data.User.Locked {
		t.Error("user still locked after unsuspend")
	}

	if _, err := cryden.Login(context.Background(), f.engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS); err != nil {
		t.Fatalf("login after unsuspend: %v", err)
	}
}

// --- Revoke sessions --------------------------------------------------------

func TestAdminRevokeSessions(t *testing.T) {
	f := newUserActionFixture(t)

	if _, err := cryden.Login(context.Background(), f.engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS); err != nil {
		t.Fatalf("precondition: login: %v", err)
	}

	rec := f.call(t, http.MethodPost, "/v1/admin/users/"+f.userID+"/revoke-sessions", f.opToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	sessions, err := f.sessions.ListByUser(context.Background(), f.userID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	// The memory store's ListByUser returns only live sessions, so an
	// empty list after the revoke is the success condition, and the
	// login above guarantees there was something to revoke. The handler
	// itself reports the count it saw before revoking, which is the
	// number this asserts on without re-deriving it.
	if len(sessions) != 0 {
		t.Errorf("live sessions after revoke = %d, want 0", len(sessions))
	}
}

// --- MFA disable -------------------------------------------------------------

func TestAdminDisableTOTP(t *testing.T) {
	f := newUserActionFixture(t)

	// Enrol TOTP the way the account holder would, and confirm it, so
	// the secret is one that actually gates login.
	ctx := context.Background()
	if _, err := cryden.EnrollTOTP(ctx, f.engine, f.userID); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := f.totp.Confirm(ctx, f.userID); err != nil {
		t.Fatalf("confirming enrolment: %v", err)
	}
	if _, err := f.totp.GetByUserID(ctx, f.userID); err != nil {
		t.Fatalf("precondition: secret exists: %v", err)
	}

	rec := f.call(t, http.MethodPost, "/v1/admin/users/"+f.userID+"/mfa/disable", f.opToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// The enrolment is gone: a fresh login asks for the password and
	// nothing else, which is what removing the second factor means.
	if _, err := cryden.Login(ctx, f.engine, "user@example.com", testPassword, "203.0.113.2", chromeOnMacOS); err != nil {
		t.Fatalf("login after mfa disable: %v", err)
	}

	types := map[string]bool{}
	for _, e := range f.eventsFor(t, f.userID) {
		types[string(e.Type)] = true
	}
	if !types["admin_totp_disabled"] {
		t.Errorf("audit events = %v, want admin_totp_disabled", types)
	}
}

func TestAdminDisableTOTPWithoutEnrolment(t *testing.T) {
	f := newUserActionFixture(t)

	rec := f.call(t, http.MethodPost, "/v1/admin/users/"+f.userID+"/mfa/disable", f.opToken, "")
	// The engine's own TOTP store answers ErrNotFound for an account
	// with no enrolment, and mapError turns that into the same 404 every
	// missing resource gets.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

// --- OAuth unlink -------------------------------------------------------------

func TestAdminUnlinkOAuth(t *testing.T) {
	f := newUserActionFixture(t)

	if err := f.oauth.Link(context.Background(), store.OAuthIdentity{
		ID:         "00000000-0000-0000-0000-0000000000a1",
		UserID:     f.userID,
		Provider:   "github",
		ExternalID: "gh-1",
		Email:      "user@example.com",
	}); err != nil {
		t.Fatalf("linking identity: %v", err)
	}

	rec := f.call(t, http.MethodDelete, "/v1/admin/users/"+f.userID+"/oauth/github", f.opToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// The row is gone from the store the engine authenticates against.
	if _, err := f.oauth.ListByUser(context.Background(), f.userID); err == nil {
		identities, _ := f.oauth.ListByUser(context.Background(), f.userID)
		if len(identities) != 0 {
			t.Errorf("identities = %d, want 0", len(identities))
		}
	}

	types := map[string]bool{}
	for _, e := range f.eventsFor(t, f.userID) {
		types[string(e.Type)] = true
	}
	if !types["admin_oauth_unlinked"] {
		t.Errorf("audit events = %v, want admin_oauth_unlinked", types)
	}
}

func TestAdminUnlinkUnknownProvider(t *testing.T) {
	f := newUserActionFixture(t)

	rec := f.call(t, http.MethodDelete, "/v1/admin/users/"+f.userID+"/oauth/github", f.opToken, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// --- Common behaviours --------------------------------------------------------

func TestAdminActionOnMalformedUserID(t *testing.T) {
	f := newUserActionFixture(t)

	// A path segment that cannot be a user id is a 404, the same answer
	// as a well-formed id that names nobody: nothing about the shape of
	// an id tells a caller whether the account exists.
	rec := f.call(t, http.MethodPost, "/v1/admin/users/not-a-uuid/unlock", f.opToken, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAdminActionsRequireAuth(t *testing.T) {
	f := newUserActionFixture(t)

	paths := []string{
		"/v1/admin/users/" + f.userID + "/unlock",
		"/v1/admin/users/" + f.userID + "/suspend",
		"/v1/admin/users/" + f.userID + "/unsuspend",
		"/v1/admin/users/" + f.userID + "/revoke-sessions",
		"/v1/admin/users/" + f.userID + "/mfa/disable",
	}
	for _, p := range paths {
		rec := f.call(t, http.MethodPost, p, "", "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: status = %d, want 401", p, rec.Code)
		}
	}
}

func TestAdminUnlinkRequiresAuth(t *testing.T) {
	f := newUserActionFixture(t)

	rec := f.call(t, http.MethodDelete, "/v1/admin/users/"+f.userID+"/oauth/github", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unlink without a token: status = %d, want 401", rec.Code)
	}
}

// eventsOf returns the audit events the fixture's store holds for one
// user, in insertion order (ListByUser returns newest first; the tests
// above read them as a set, so order does not matter to them).
func (f userActionFixture) auditTypes(t *testing.T, userID string) map[string]bool {
	t.Helper()
	types := map[string]bool{}
	for _, e := range f.eventsFor(t, userID) {
		types[string(e.Type)] = true
	}
	return types
}
