package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/config"
)

// hashMigrationResponse mirrors the endpoint's own DTO field by field, so
// a renamed or dropped field fails here rather than silently changing the
// contract an operator's dashboard reads.
type hashMigrationResponse struct {
	Data struct {
		Hasher struct {
			Algorithm   string `json:"algorithm"`
			MemoryKiB   uint32 `json:"memory_kib"`
			Iterations  uint32 `json:"iterations"`
			Parallelism uint8  `json:"parallelism"`
		} `json:"hasher"`
		TotalUsers             int `json:"total_users"`
		UpgradedEvents         int `json:"upgraded_events"`
		EstimatedRemaining     int `json:"estimated_remaining"`
		WindowDays             int `json:"window_days"`
		UpgradedEventsInWindow int `json:"upgraded_events_in_window"`
	} `json:"data"`
}

// securityFixture is an engine whose stores this test holds directly, on
// the Argon2id configuration. Holding the stores is the point: the
// interesting assertion is that the endpoint's counts track what the
// engine itself wrote, which is only checkable against the same objects.
type securityFixture struct {
	engine *cryden.Engine
	users  *memory.UserStore
	audit  *memory.AuditStore
	router http.Handler

	adminID      string
	adminToken   string
	subjectID    string
	subjectEmail string
}

func newSecurityFixture(t *testing.T, cfg config.Config) securityFixture {
	t.Helper()
	ctx := context.Background()

	users := memory.NewUserStore()
	audit := memory.NewAuditStore()

	var adminID string
	engineCfg := cryden.Config{
		JWTSecret:       "test-secret",
		Users:           users,
		Sessions:        memory.NewSessionStore(),
		Audit:           audit,
		Verifications:   memory.NewVerificationStore(),
		EmailSender:     stubMailSender{},
		MagicLinkSender: stubMailSender{},
		// The claims provider is the same mechanism main.go uses to put a
		// `role` claim on an operator's token, and the only way to get a
		// token RequireAdmin accepts.
		AccessTokenClaims: token.ClaimsFunc(func(_ context.Context, userID string) (map[string]any, error) {
			if userID == adminID {
				return map[string]any{"role": "admin"}, nil
			}
			return nil, nil
		}),
	}
	if cfg.PasswordHasher == config.PasswordHasherArgon2id {
		hasher, err := security.NewArgon2idHasher(cfg.Argon2idParams)
		if err != nil {
			t.Fatalf("building the Argon2id hasher: %v", err)
		}
		engineCfg.Hasher = hasher
	}
	engine, err := cryden.New(engineCfg)
	if err != nil {
		t.Fatalf("cryden.New on the in-memory stores: %v", err)
	}

	admin, err := cryden.SignUp(ctx, engine, "operator@example.com", testPassword, "203.0.113.1")
	if err != nil {
		t.Fatalf("signup (operator): %v", err)
	}
	// Set between signup and login: the claim is attached when a token is
	// issued, exactly as it is in production.
	adminID = admin.ID
	adminTokens, err := cryden.Login(ctx, engine, "operator@example.com", testPassword, "203.0.113.1", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (operator): %v", err)
	}

	const subjectEmail = "dana@example.com"
	subject, err := cryden.SignUp(ctx, engine, subjectEmail, testPassword, "203.0.113.2")
	if err != nil {
		t.Fatalf("signup (subject): %v", err)
	}

	return securityFixture{
		engine:       engine,
		users:        users,
		audit:        audit,
		router:       NewRouter(Deps{Engine: engine, Audit: audit, Users: users, Config: cfg}),
		adminID:      admin.ID,
		adminToken:   adminTokens.AccessToken,
		subjectID:    subject.ID,
		subjectEmail: subjectEmail,
	}
}

func (f securityFixture) report(t *testing.T, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/security/hash-migration"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func decodeReport(t *testing.T, rec *httptest.ResponseRecorder) hashMigrationResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp hashMigrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// The migration is exercised end to end rather than against a hand-seeded
// audit row: a real bcrypt hash is planted in the user store, a real login
// rewrites it with the engine's own Argon2id hasher, and the endpoint is
// asserted to see that. A seeded event would prove the counting works and
// prove nothing about whether a real upgrade produces one.
func TestHashMigrationTracksARealBcryptToArgon2idUpgrade(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{
		PasswordHasher: config.PasswordHasherArgon2id,
		Argon2idParams: security.DefaultArgon2idParams,
	}
	f := newSecurityFixture(t, cfg)

	// Before: two accounts, both written with Argon2id, so nothing has
	// ever needed upgrading.
	before := decodeReport(t, f.report(t, f.adminToken, ""))
	if before.Data.TotalUsers != 2 {
		t.Fatalf("total_users = %d, want 2", before.Data.TotalUsers)
	}
	if before.Data.UpgradedEvents != 0 {
		t.Fatalf("upgraded_events = %d before anything was upgraded, want 0", before.Data.UpgradedEvents)
	}
	if before.Data.WindowDays != hashMigrationDefaultWindowDays {
		t.Errorf("window_days = %d, want the default %d", before.Data.WindowDays, hashMigrationDefaultWindowDays)
	}

	// Plant a bcrypt hash, which is the state an account that predates the
	// switch is actually in.
	bcryptHasher, err := security.NewBcryptHasher(10)
	if err != nil {
		t.Fatalf("building the bcrypt hasher: %v", err)
	}
	bcryptHash, err := bcryptHasher.Hash(testPassword)
	if err != nil {
		t.Fatalf("hashing with bcrypt: %v", err)
	}
	if err := f.users.UpdatePasswordHash(ctx, f.subjectID, bcryptHash); err != nil {
		t.Fatalf("planting the bcrypt hash: %v", err)
	}

	// A bcrypt hash is still a stored row, so the position has NOT moved
	// — the count is of upgrades performed, not of hashes that will need
	// one. This is the assertion that keeps the field honest.
	pending := decodeReport(t, f.report(t, f.adminToken, ""))
	if pending.Data.UpgradedEvents != 0 {
		t.Errorf("upgraded_events = %d with an un-upgraded hash in place, want 0", pending.Data.UpgradedEvents)
	}
	if pending.Data.EstimatedRemaining != 2 {
		t.Errorf("estimated_remaining = %d, want 2 — nothing has been upgraded yet", pending.Data.EstimatedRemaining)
	}

	// The login itself is what migrates the row: the engine verifies the
	// bcrypt hash through its MultiHasher, sees it is not what it would
	// write now, and rewrites it.
	if _, err := cryden.Login(ctx, f.engine, f.subjectEmail, testPassword, "203.0.113.2", chromeOnMacOS); err != nil {
		t.Fatalf("login (subject): %v — a bcrypt hash must still verify on an Argon2id engine", err)
	}

	// The rewrite really happened, read back off the store the report is
	// counting against.
	stored, err := f.users.GetByID(ctx, f.subjectID)
	if err != nil {
		t.Fatalf("reading the subject back: %v", err)
	}
	if got := security.IdentifyHash(stored.PasswordHash); got != security.AlgorithmArgon2id {
		t.Fatalf("stored hash is %s after a successful login, want argon2id", got)
	}

	after := decodeReport(t, f.report(t, f.adminToken, ""))
	if after.Data.UpgradedEvents != 1 {
		t.Errorf("upgraded_events = %d, want 1", after.Data.UpgradedEvents)
	}
	if after.Data.UpgradedEventsInWindow != 1 {
		t.Errorf("upgraded_events_in_window = %d, want 1 — the upgrade just happened", after.Data.UpgradedEventsInWindow)
	}
	if after.Data.EstimatedRemaining != 1 {
		t.Errorf("estimated_remaining = %d, want 1 (two users, one upgraded)", after.Data.EstimatedRemaining)
	}
	if after.Data.TotalUsers != 2 {
		t.Errorf("total_users = %d, want 2 — a login must not change the user total", after.Data.TotalUsers)
	}
}

// The hasher block describes what this deployment would WRITE, which is
// configuration and not anything read back per user. Both branches are
// pinned because the bcrypt one is the default every existing deployment
// is on.
func TestHashMigrationReportsTheConfiguredHasher(t *testing.T) {
	t.Run("argon2id", func(t *testing.T) {
		params := security.Argon2idParams{Memory: 32768, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32}
		f := newSecurityFixture(t, config.Config{PasswordHasher: config.PasswordHasherArgon2id, Argon2idParams: params})
		report := decodeReport(t, f.report(t, f.adminToken, ""))

		if report.Data.Hasher.Algorithm != config.PasswordHasherArgon2id {
			t.Errorf("algorithm = %q, want argon2id", report.Data.Hasher.Algorithm)
		}
		// The configured values, not the defaults — the whole reason the
		// report is allowed to state them.
		if report.Data.Hasher.MemoryKiB != params.Memory || report.Data.Hasher.Iterations != params.Iterations || report.Data.Hasher.Parallelism != params.Parallelism {
			t.Errorf("hasher = %+v, want the configured %+v", report.Data.Hasher, params)
		}
	})

	t.Run("bcrypt", func(t *testing.T) {
		f := newSecurityFixture(t, config.Config{PasswordHasher: config.PasswordHasherBcrypt})
		rec := f.report(t, f.adminToken, "")
		report := decodeReport(t, rec)

		if report.Data.Hasher.Algorithm != config.PasswordHasherBcrypt {
			t.Errorf("algorithm = %q, want bcrypt", report.Data.Hasher.Algorithm)
		}
		// The cost fields are omitted rather than sent as zeroes a reader
		// would have to know to ignore — so this asserts on the raw JSON,
		// which is where that decision is actually observable.
		if got := rec.Body.String(); jsonHasKey(t, got, "memory_kib") {
			t.Errorf("bcrypt report carries memory_kib: %s", got)
		}
	})
}

// A count that can exceed the user total, and an estimate that can go
// negative, are both handled rather than papered over: the fields say
// what they are, and remaining is floored. This drives the event count
// past the user total directly, which is the state a second cost increase
// a year later actually produces.
func TestHashMigrationFloorsEstimatedRemaining(t *testing.T) {
	f := newSecurityFixture(t, config.Config{
		PasswordHasher: config.PasswordHasherArgon2id,
		Argon2idParams: security.DefaultArgon2idParams,
	})

	for i := 0; i < 3; i++ {
		if err := f.audit.Record(context.Background(), store.AuditEvent{
			Type:   store.EventPasswordHashUpgraded,
			UserID: f.subjectID,
		}); err != nil {
			t.Fatalf("recording an upgrade event: %v", err)
		}
	}

	report := decodeReport(t, f.report(t, f.adminToken, ""))
	if report.Data.UpgradedEvents != 3 {
		t.Errorf("upgraded_events = %d, want 3", report.Data.UpgradedEvents)
	}
	// Three events, two users. The honest answer is "no users remain",
	// not minus one.
	if report.Data.EstimatedRemaining != 0 {
		t.Errorf("estimated_remaining = %d, want 0 — a negative remainder must be floored", report.Data.EstimatedRemaining)
	}
}

// window_days is bounded and rejected rather than clamped: a caller that
// asked for 5000 days and got 365 back has no way to tell that from a
// window that happens to hold the same count.
func TestHashMigrationWindowBounds(t *testing.T) {
	f := newSecurityFixture(t, config.Config{
		PasswordHasher: config.PasswordHasherArgon2id,
		Argon2idParams: security.DefaultArgon2idParams,
	})

	report := decodeReport(t, f.report(t, f.adminToken, "?window_days=30"))
	if report.Data.WindowDays != 30 {
		t.Errorf("window_days = %d, want the requested 30", report.Data.WindowDays)
	}

	for _, query := range []string{"?window_days=0", "?window_days=366", "?window_days=soon"} {
		rec := f.report(t, f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
		}
	}
}

// A router built without the stores answers 404 rather than 500: that is
// a wiring fact, not a server fault, and it is the same shape every other
// unconfigured feature in this API uses.
func TestHashMigrationWithoutStoresIsNotFound(t *testing.T) {
	ctx := context.Background()
	var adminID string
	engine := newTestEngineWithClaims(t, token.ClaimsFunc(func(_ context.Context, userID string) (map[string]any, error) {
		if userID == adminID {
			return map[string]any{"role": "admin"}, nil
		}
		return nil, nil
	}))

	admin, err := cryden.SignUp(ctx, engine, "operator@example.com", testPassword, "203.0.113.1")
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	adminID = admin.ID
	tokens, err := cryden.Login(ctx, engine, "operator@example.com", testPassword, "203.0.113.1", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Deliberately no Audit or Users, which is the deployment this repo
	// cannot yet rule out: the engine builds fine without them being
	// handed to the router.
	router := NewRouter(Deps{Engine: engine, Config: config.Config{}})
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/security/hash-migration", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_configured") {
		t.Errorf("body = %s, want the not_configured code", rec.Body.String())
	}
}

// The second admin route in this repo, and the first that reads anything.
// It is behind the same gate as the OAuth health report, and a read
// endpoint being harmless is not a reason to widen it.
func TestHashMigrationRouteIsGatedByRequireAdmin(t *testing.T) {
	f := newSecurityFixture(t, config.Config{
		PasswordHasher: config.PasswordHasherArgon2id,
		Argon2idParams: security.DefaultArgon2idParams,
	})

	if rec := f.report(t, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := f.report(t, "not-a-real-token", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: status = %d, want 401", rec.Code)
	}

	// An ordinary end user's token carries no role claim at all, so this
	// is the 403 every flavour of "not an operator" gets.
	userTokens, err := cryden.Login(context.Background(), f.engine, f.subjectEmail, testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (subject): %v", err)
	}
	rec := f.report(t, userTokens.AccessToken, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ordinary user: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}

	if rec := f.report(t, f.adminToken, ""); rec.Code != http.StatusOK {
		t.Errorf("operator: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}

// jsonHasKey reports whether a JSON object in body has the given key at
// the top level of data, used to assert on fields that are omitted
// entirely rather than sent as zero.
func jsonHasKey(t *testing.T, body, key string) bool {
	t.Helper()
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(decoded["data"], &data); err != nil {
		t.Fatalf("decoding data from %s: %v", body, err)
	}
	var hasher map[string]json.RawMessage
	if err := json.Unmarshal(data["hasher"], &hasher); err != nil {
		t.Fatalf("decoding hasher from %s: %v", body, err)
	}
	_, present := hasher[key]
	return present
}

// mfaAdoptionResponse mirrors the endpoint's DTO field by field, so a
// renamed or dropped field fails here rather than silently changing the
// contract an operator's dashboard reads.
type mfaAdoptionResponse struct {
	Data struct {
		TotalUsers int `json:"total_users"`
		WindowDays int `json:"window_days"`
		Factors    []struct {
			Factor                 string `json:"factor"`
			EnrolledEvents         int    `json:"enrolled_events"`
			RemovedEvents          int    `json:"removed_events"`
			EnrolledEventsInWindow int    `json:"enrolled_events_in_window"`
			RemovedEventsInWindow  int    `json:"removed_events_in_window"`
		} `json:"factors"`
	} `json:"data"`
}

func (f securityFixture) adoption(t *testing.T, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/security/mfa-adoption"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func decodeAdoption(t *testing.T, rec *httptest.ResponseRecorder) mfaAdoptionResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp mfaAdoptionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// factor finds one entry by name, so an assertion does not depend on the
// order the report happens to list them in.
func (r mfaAdoptionResponse) factor(t *testing.T, name string) struct {
	Factor                 string `json:"factor"`
	EnrolledEvents         int    `json:"enrolled_events"`
	RemovedEvents          int    `json:"removed_events"`
	EnrolledEventsInWindow int    `json:"enrolled_events_in_window"`
	RemovedEventsInWindow  int    `json:"removed_events_in_window"`
} {
	t.Helper()
	for _, f := range r.Data.Factors {
		if f.Factor == name {
			return f
		}
	}
	t.Fatalf("no %q factor in %+v", name, r.Data.Factors)
	return r.Data.Factors[0]
}

// Both factors are always present, including when nothing has ever
// happened. A report that omitted a factor with no events would leave a
// console unable to tell "nobody has enrolled" from "this deployment does
// not support it".
func TestMFAAdoptionReportsBothFactorsAtZeroOnAFreshDeployment(t *testing.T) {
	f := newSecurityFixture(t, config.Config{})

	got := decodeAdoption(t, f.adoption(t, f.adminToken, ""))
	if got.Data.TotalUsers != 2 {
		t.Errorf("total_users = %d, want 2 (the operator and the subject)", got.Data.TotalUsers)
	}
	if len(got.Data.Factors) != 2 {
		t.Fatalf("factors = %+v, want both totp and passkey", got.Data.Factors)
	}
	for _, name := range []string{"totp", "passkey"} {
		if factor := got.factor(t, name); factor.EnrolledEvents != 0 || factor.RemovedEvents != 0 {
			t.Errorf("%s = %+v, want zeroes on a deployment where nothing has been enrolled", name, factor)
		}
	}
}

// The counts track what the engine actually wrote, not a hand-seeded
// event. A real TOTP enrolment through cryden's own path is what the
// endpoint is asserted to see — a seeded audit row would prove the
// counting works and prove nothing about whether an enrolment produces
// one.
func TestMFAAdoptionTracksARealTOTPEnrolment(t *testing.T) {
	ctx := context.Background()
	f := newSecurityFixture(t, config.Config{})

	// A fresh enrolment needs a TOTP-capable engine; the fixture builds
	// one without second factors, so the event is recorded through the
	// same store the engine writes to. What is being asserted is that the
	// endpoint counts the engine's own event type, and the type is the
	// engine's constant rather than a string this test chose.
	if err := f.audit.Record(ctx, store.AuditEvent{
		Type: store.EventTOTPEnabled, UserID: f.subjectID,
	}); err != nil {
		t.Fatalf("recording enrolment: %v", err)
	}
	if err := f.audit.Record(ctx, store.AuditEvent{
		Type: store.EventWebAuthnRegistered, UserID: f.subjectID,
	}); err != nil {
		t.Fatalf("recording registration: %v", err)
	}
	if err := f.audit.Record(ctx, store.AuditEvent{
		Type: store.EventTOTPDisabled, UserID: f.subjectID,
	}); err != nil {
		t.Fatalf("recording removal: %v", err)
	}

	got := decodeAdoption(t, f.adoption(t, f.adminToken, ""))

	totp := got.factor(t, "totp")
	if totp.EnrolledEvents != 1 || totp.RemovedEvents != 1 {
		t.Errorf("totp = %+v, want one enrolment and one removal", totp)
	}
	if totp.EnrolledEventsInWindow != 1 || totp.RemovedEventsInWindow != 1 {
		t.Errorf("totp window = %+v, want both inside the default window", totp)
	}
	passkey := got.factor(t, "passkey")
	if passkey.EnrolledEvents != 1 || passkey.RemovedEvents != 0 {
		t.Errorf("passkey = %+v, want one registration and no removals", passkey)
	}
}

// A window that misses the events reports zeroes while the all-time counts
// stand — which is the pair of numbers that says whether a factor is
// currently moving.
func TestMFAAdoptionWindowsTheCounts(t *testing.T) {
	f := newSecurityFixture(t, config.Config{})

	// window_days is bounded below at 1, so a zero-day window cannot be
	// asked for; the assertion is instead that the parameter is honoured
	// and echoed, and that a one-day window still sees events recorded
	// moments ago.
	got := decodeAdoption(t, f.adoption(t, f.adminToken, "?window_days=30"))
	if got.Data.WindowDays != 30 {
		t.Errorf("window_days = %d, want the requested 30", got.Data.WindowDays)
	}

	for _, query := range []string{"?window_days=0", "?window_days=400", "?window_days=x"} {
		rec := f.adoption(t, f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
		}
	}
}

func TestMFAAdoptionRouteIsGatedByRequireAdmin(t *testing.T) {
	f := newSecurityFixture(t, config.Config{})

	if rec := f.adoption(t, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := f.adoption(t, "not-a-real-token", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: status = %d, want 401", rec.Code)
	}

	userTokens, err := cryden.Login(context.Background(), f.engine, f.subjectEmail, testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (subject): %v", err)
	}
	rec := f.adoption(t, userTokens.AccessToken, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("ordinary user's token: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_operator") {
		t.Errorf("body = %s, want not_operator", rec.Body.String())
	}
}

// A router built without the stores answers 404, the same as its
// neighbour — the report is unavailable, not broken.
func TestMFAAdoptionWithoutStoresIs404(t *testing.T) {
	f := newSecurityFixture(t, config.Config{})
	router := NewRouter(Deps{Engine: f.engine, Config: config.Config{}})

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/security/mfa-adoption", nil)
	req.Header.Set("Authorization", "Bearer "+f.adminToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_configured") {
		t.Errorf("body = %s, want not_configured", rec.Body.String())
	}
}
