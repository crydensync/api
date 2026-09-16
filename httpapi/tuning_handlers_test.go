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
	"github.com/crydensync/cryden/v2/admin"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/config"
)

// tuningResponse mirrors the endpoint's DTO field by field, so a renamed
// or dropped field fails here rather than silently changing the contract a
// console reads — and this one is rendered as a card per suggestion, so a
// renamed field is a broken screen rather than a cosmetic difference.
type tuningResponse struct {
	Data struct {
		Since       time.Time      `json:"since"`
		Until       time.Time      `json:"until"`
		WindowDays  int            `json:"window_days"`
		Counts      map[string]int `json:"counts"`
		Suggestions []struct {
			Area       string `json:"area"`
			Finding    string `json:"finding"`
			Suggestion string `json:"suggestion"`
		} `json:"suggestions"`
	} `json:"data"`
}

// findByArea returns the suggestion for one knob, and whether there was
// one. Area is the field a console groups on, so finding by it is finding
// the thing the endpoint promises.
func (r tuningResponse) findByArea(area string) (string, bool) {
	for _, s := range r.Data.Suggestions {
		if s.Area == area {
			return s.Finding + " " + s.Suggestion, true
		}
	}
	return "", false
}

type tuningFixture struct {
	audit  *memory.AuditStore
	router http.Handler

	adminToken string
	userToken  string
}

// newTuningFixture builds an engine on in-memory stores with the audit
// store held directly, because the report is computed from exactly that
// store and the test is the only thing that can seed it. cfg is the
// deployment under test — the report describes the settings in force, so
// the settings are the input.
func newTuningFixture(t *testing.T, cfg config.Config) tuningFixture {
	t.Helper()
	ctx := context.Background()

	audit := memory.NewAuditStore()
	var adminID string
	engine, err := cryden.New(cryden.Config{
		JWTSecret:       "test-secret",
		Users:           memory.NewUserStore(),
		Sessions:        memory.NewSessionStore(),
		Audit:           audit,
		Verifications:   memory.NewVerificationStore(),
		EmailSender:     stubMailSender{},
		MagicLinkSender: stubMailSender{},
		AccessTokenClaims: token.ClaimsFunc(func(_ context.Context, userID string) (map[string]any, error) {
			if userID == adminID {
				return map[string]any{"role": "admin"}, nil
			}
			return nil, nil
		}),
	})
	if err != nil {
		t.Fatalf("cryden.New on the in-memory stores: %v", err)
	}

	admin, err := cryden.SignUp(ctx, engine, "operator@example.com", testPassword, "203.0.113.1")
	if err != nil {
		t.Fatalf("signup (operator): %v", err)
	}
	adminID = admin.ID
	adminTokens, err := cryden.Login(ctx, engine, "operator@example.com", testPassword, "203.0.113.1", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (operator): %v", err)
	}

	const userEmail = "dana@example.com"
	if _, err := cryden.SignUp(ctx, engine, userEmail, testPassword, "203.0.113.2"); err != nil {
		t.Fatalf("signup (user): %v", err)
	}
	userTokens, err := cryden.Login(ctx, engine, userEmail, testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (user): %v", err)
	}

	return tuningFixture{
		audit:      audit,
		router:     NewRouter(Deps{Engine: engine, Audit: audit, Config: cfg}),
		adminToken: adminTokens.AccessToken,
		userToken:  userTokens.AccessToken,
	}
}

func (f tuningFixture) record(t *testing.T, eventType store.AuditEventType, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := f.audit.Record(context.Background(), store.AuditEvent{Type: eventType}); err != nil {
			t.Fatalf("recording a %s event: %v", eventType, err)
		}
	}
}

func (f tuningFixture) report(t *testing.T, method, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/v1/admin/config-tuning"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f tuningFixture) tuning(t *testing.T, token, query string) tuningResponse {
	t.Helper()
	rec := f.report(t, http.MethodGet, token, query)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp tuningResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// The lockout suggestion quotes the threshold and duration in force, and
// this drives the whole path to check it quotes the CONFIGURED ones rather
// than cryden's documented defaults. That distinction is the reason this
// repo passes the lockout knobs to the engine at all: a report describing
// settings the engine is not running would be worse than no report.
func TestConfigTuningJudgesHistoryAgainstTheSettingsInForce(t *testing.T) {
	cfg := config.Config{
		LockoutThreshold:  7,
		LockoutDuration:   30 * time.Minute,
		RateLimitAttempts: 42,
		RateLimitWindow:   90 * time.Second,
	}
	f := newTuningFixture(t, cfg)

	// Five lockouts against five failures: every failed attempt ended in a
	// lockout, which is the shape cryden flags as "probably catching real
	// users".
	f.record(t, store.EventAccountLocked, 5)
	f.record(t, store.EventLoginFailed, 5)
	f.record(t, "host_specific_thing", 3)

	resp := f.tuning(t, f.adminToken, "")

	lockout, ok := resp.findByArea("Lockout")
	if !ok {
		t.Fatalf("no Lockout suggestion in %+v, want one for five lockouts", resp.Data.Suggestions)
	}
	if !strings.Contains(lockout, "LockoutThreshold is currently 7") {
		t.Errorf("lockout finding = %q, want the configured threshold", lockout)
	}
	if !strings.Contains(lockout, "30m0s") {
		t.Errorf("lockout finding = %q, want the configured duration", lockout)
	}
	// And it suggests rather than acts: nothing in the text claims a
	// change was made, and no field carries one.
	if !strings.Contains(lockout, "consider") {
		t.Errorf("lockout text = %q, want a suggestion, not an instruction", lockout)
	}

	// The counts are the evidence behind the suggestions, reported raw so a
	// console can show them rather than asking an operator to trust a
	// sentence. A type cryden does not define is included, which is what
	// makes this the engine's own count rather than a list this repo keeps.
	if got := resp.Data.Counts[string(store.EventAccountLocked)]; got != 5 {
		t.Errorf("counts[account_locked] = %d, want 5", got)
	}
	if got := resp.Data.Counts["host_specific_thing"]; got != 3 {
		t.Errorf("counts[host_specific_thing] = %d, want 3", got)
	}

	// The rate limiter suggestion quotes the configured bounds for the same
	// reason.
	limiter, ok := resp.findByArea("Rate limiting")
	if !ok {
		t.Fatalf("no Rate limiting suggestion in %+v, want one for the in-process limiter", resp.Data.Suggestions)
	}
	if !strings.Contains(limiter, "42 attempts per 1m30s") {
		t.Errorf("rate limiter finding = %q, want the configured bounds", limiter)
	}
}

// A Redis-backed limiter is the one suggestion that needs no audit data at
// all — it is a fact about the deployment — so it has to disappear when
// the deployment has actually fixed it. Derived from RedisURL, which is
// the same condition main.go uses to build the Redis limiter.
func TestConfigTuningOnlyFlagsTheInProcessRateLimiter(t *testing.T) {
	t.Run("in-process", func(t *testing.T) {
		f := newTuningFixture(t, config.Config{RateLimitAttempts: 10, RateLimitWindow: time.Minute})
		if _, ok := f.tuning(t, f.adminToken, "").findByArea("Rate limiting"); !ok {
			t.Error("no Rate limiting suggestion with the default in-process limiter")
		}
	})

	t.Run("shared", func(t *testing.T) {
		f := newTuningFixture(t, config.Config{
			RedisURL:          "redis://cache.internal:6379",
			RateLimitAttempts: 10,
			RateLimitWindow:   time.Minute,
		})
		if _, ok := f.tuning(t, f.adminToken, "").findByArea("Rate limiting"); ok {
			t.Error("the in-process limiter was flagged on a deployment running the Redis one")
		}
	})
}

// Anomaly detection off and on are different reports, and the off case is
// the one every deployment starts in. Both are asserted because the
// suggestion is the only place a console learns detection is not running.
func TestConfigTuningReportsWhetherAnomalyDetectionIsOn(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		f := newTuningFixture(t, config.Config{})
		finding, ok := f.tuning(t, f.adminToken, "").findByArea("Anomaly detection")
		if !ok {
			t.Fatal("no Anomaly detection suggestion with detection off")
		}
		if !strings.Contains(finding, "is not set") {
			t.Errorf("finding = %q, want it to say detection is not configured", finding)
		}
	})

	t.Run("on and quiet", func(t *testing.T) {
		cfg := config.Config{AnomalyDetection: true}
		cfg.AnomalyThresholds.UserFailureVelocity = 5
		cfg.AnomalyThresholds.IPFailureVelocity = 20
		cfg.AnomalyThresholds.HistorySize = 100
		f := newTuningFixture(t, cfg)
		// Enough successful sign-ins that silence is worth remarking on
		// rather than being a quiet window.
		f.record(t, store.EventLoginSuccess, 60)

		finding, ok := f.tuning(t, f.adminToken, "").findByArea("Anomaly detection")
		if !ok {
			t.Fatal("no Anomaly detection suggestion with detection on and 60 sign-ins, none flagged")
		}
		// The thresholds come from this repo's config, so the report quotes
		// the numbers the engine is screening against.
		for _, want := range []string{"UserFailureVelocity=5", "IPFailureVelocity=20", "HistorySize=100"} {
			if !strings.Contains(finding, want) {
				t.Errorf("finding = %q, want it to contain %q", finding, want)
			}
		}
	})
}

// The password-strength finding is the one that is always present here,
// and it is accurate rather than a stub: this repo has never set a
// breached-password checker, because cryden ships no implementation and
// every real one calls somebody else's corpus.
func TestConfigTuningReportsTheAbsentBreachChecker(t *testing.T) {
	f := newTuningFixture(t, config.Config{})

	finding, ok := f.tuning(t, f.adminToken, "").findByArea("Password strength")
	if !ok {
		t.Fatal("no Password strength suggestion, want the always-present one")
	}
	if !strings.Contains(finding, "BreachedPasswordChecker is not set") {
		t.Errorf("finding = %q, want it to say the checker is not configured", finding)
	}
}

// window_days defaults to cryden's own 30-day tuning window — deliberately
// wider than the digest's week, because a config knob should be judged
// against a month of traffic — and is bounded rather than clamped.
func TestConfigTuningWindowBounds(t *testing.T) {
	f := newTuningFixture(t, config.Config{})

	if got := f.tuning(t, f.adminToken, "").Data.WindowDays; got != int(admin.DefaultTuningWindow.Hours()/24) {
		t.Errorf("window_days = %d, want cryden's default %v", got, admin.DefaultTuningWindow)
	}
	if got := f.tuning(t, f.adminToken, "?window_days=90").Data.WindowDays; got != 90 {
		t.Errorf("window_days = %d with window_days=90, want 90", got)
	}
	for _, query := range []string{"?window_days=0", "?window_days=366", "?window_days=month"} {
		rec := f.report(t, http.MethodGet, f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
		}
	}
}

// The route answers GET and nothing else. This is the HTTP-level half of
// "suggests, never applies": there is no POST that takes a suggestion, and
// a suggestion cannot be turned into a config change by a request to this
// path in any method. The recorded decision is that applying one means
// pre-filling a settings field and a human saving it through the ordinary
// settings path — see CLAUDE.md's hard rule.
func TestConfigTuningAcceptsNoWriteMethod(t *testing.T) {
	f := newTuningFixture(t, config.Config{})

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := f.report(t, method, f.adminToken, "")
		if rec.Code == http.StatusOK {
			t.Errorf("%s: status = %d, want this route to refuse anything but GET (body %s)", method, rec.Code, rec.Body.String())
		}
	}
}

// A handler built without the audit store answers 404 rather than 500 — a
// wiring fact, not a server fault, and the same shape every unconfigured
// feature in this API uses. Called directly, because a router built with a
// nil engine cannot serve an authenticated request at all and this is the
// only way to reach the branch.
func TestConfigTuningWithoutAnAuditStoreIsNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/config-tuning", nil)
	rec := httptest.NewRecorder()

	h := &TuningHandlers{}
	h.ConfigTuning(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_configured") {
		t.Errorf("body = %s, want the not_configured code", rec.Body.String())
	}
}

// The reports name failed logins and lockouts by account, so this sits
// behind the same gate as every other admin report.
func TestConfigTuningRouteIsGatedByRequireAdmin(t *testing.T) {
	f := newTuningFixture(t, config.Config{})

	if rec := f.report(t, http.MethodGet, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := f.report(t, http.MethodGet, "not-a-real-token", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: status = %d, want 401", rec.Code)
	}
	if rec := f.report(t, http.MethodGet, f.userToken, ""); rec.Code != http.StatusForbidden {
		t.Errorf("ordinary user: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := f.report(t, http.MethodGet, f.adminToken, ""); rec.Code != http.StatusOK {
		t.Errorf("operator: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}
