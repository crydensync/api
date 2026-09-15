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
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/shiplog"
)

// logEventsResponse mirrors the endpoint's DTO field by field, so a renamed
// or dropped field fails here rather than silently changing the contract an
// operator's console reads.
type logEventsResponse struct {
	Data struct {
		Events []struct {
			ID        int64             `json:"id"`
			Level     string            `json:"level"`
			Message   string            `json:"message"`
			Fields    map[string]string `json:"fields"`
			Sink      string            `json:"sink"`
			ShippedAt time.Time         `json:"shipped_at"`
		} `json:"events"`
		Count  int      `json:"count"`
		Level  string   `json:"level"`
		Levels []string `json:"levels"`
	} `json:"data"`
}

type loggingFixture struct {
	store  *shiplog.MemoryStore
	router http.Handler

	adminToken string
	userToken  string
}

// newLoggingFixture builds an engine whose operator carries the admin claim
// and a router holding the shipped-events log. Records are written through
// the real sink — shiplog.Logger, composed the way main.go composes it —
// rather than inserted by hand, so what these tests list is what the
// cloud-logging sink actually produced.
func newLoggingFixture(t *testing.T) loggingFixture {
	t.Helper()
	ctx := context.Background()

	store := shiplog.NewMemoryStore()
	var adminID string
	engine, err := cryden.New(cryden.Config{
		JWTSecret:       "test-secret",
		Users:           memory.NewUserStore(),
		Sessions:        memory.NewSessionStore(),
		Audit:           memory.NewAuditStore(),
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

	return loggingFixture{
		store:      store,
		router:     NewRouter(Deps{Engine: engine, Config: config.Config{}, Shipped: store}),
		adminToken: adminTokens.AccessToken,
		userToken:  userTokens.AccessToken,
	}
}

// record writes one entry through the sink the engine would hold, and fails
// the test if it did not land. The sink has no error return — logger.Logger
// has no room for one — so the check is what stops a wiring mistake from
// looking like an endpoint that merely returns nothing.
func (f loggingFixture) record(t *testing.T, level logger.Level, message string, fields map[string]string) {
	t.Helper()
	before := f.store.Count()
	shiplog.NewLogger(f.store).Log(context.Background(), level, message, fields)
	if got := f.store.Count(); got != before+1 {
		t.Fatalf("recording %q did not reach the store: %d rows, want %d", message, got, before+1)
	}
}

func (f loggingFixture) recent(t *testing.T, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/logging/recent"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func decodeLogEvents(t *testing.T, rec *httptest.ResponseRecorder) logEventsResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp logEventsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

func TestLoggingRecentListsNewestFirst(t *testing.T) {
	f := newLoggingFixture(t)

	f.record(t, logger.LevelInfo, "login: completed", map[string]string{"user_id": "u1"})
	f.record(t, logger.LevelWarn, "login: rate limited", map[string]string{"ip": "203.0.113.9"})

	resp := decodeLogEvents(t, f.recent(t, f.adminToken, ""))
	if resp.Data.Count != 2 {
		t.Fatalf("count = %d, want 2", resp.Data.Count)
	}
	if resp.Data.Events[0].Message != "login: rate limited" {
		t.Errorf("first row = %q, want the newest", resp.Data.Events[0].Message)
	}

	// The vocabulary is reported rather than hardcoded, so a console can
	// offer the filter without a second copy of it.
	if strings.Join(resp.Data.Levels, ",") != "debug,info,warn,error" {
		t.Errorf("levels = %v, want the four names least severe first", resp.Data.Levels)
	}
	// No filter in force, so nothing is echoed back — "debug" here would
	// suggest a filter an operator had not asked for.
	if resp.Data.Level != "" {
		t.Errorf("level = %q on an unfiltered listing, want empty", resp.Data.Level)
	}

	// The record's own fields come back, which is what makes the listing a
	// log rather than a list of bare messages.
	if resp.Data.Events[0].Fields["ip"] != "203.0.113.9" {
		t.Errorf("fields = %v, want the record's own", resp.Data.Events[0].Fields)
	}
	if resp.Data.Events[0].Sink != shiplog.SinkName {
		t.Errorf("sink = %q, want %q", resp.Data.Events[0].Sink, shiplog.SinkName)
	}
	if resp.Data.Events[0].ShippedAt.IsZero() {
		t.Error("shipped_at is zero, want when the sink wrote the record")
	}
}

// level=warn means warn AND WORSE — the same direction the LevelFilter
// above the sink reads the word. A filter that meant "exactly warn" here
// while the shipping filter meant "warn and above" would be one word with
// two meanings in one feature.
func TestLoggingRecentFiltersAtOrAboveTheLevel(t *testing.T) {
	f := newLoggingFixture(t)
	f.record(t, logger.LevelDebug, "cache miss", nil)
	f.record(t, logger.LevelInfo, "login: completed", nil)
	f.record(t, logger.LevelWarn, "login: rate limited", nil)
	f.record(t, logger.LevelError, "token reuse detected", nil)

	for query, want := range map[string]int{
		"":               4,
		"?level=debug":   4,
		"?level=info":    3,
		"?level=warn":    2,
		"?level=error":   1,
		"?level=WARNING": 2, // logger.ParseLevel's own leniency, not a second vocabulary
	} {
		resp := decodeLogEvents(t, f.recent(t, f.adminToken, query))
		if resp.Data.Count != want {
			t.Errorf("%s: count = %d, want %d", query, resp.Data.Count, want)
		}
	}

	// The filter in force is echoed back, in the caller's own word — an
	// operator looking at a short list needs to know whether it is short
	// because of the filter or because the engine has been quiet.
	filtered := decodeLogEvents(t, f.recent(t, f.adminToken, "?level=warn"))
	if filtered.Data.Level != "warn" {
		t.Errorf("level = %q, want the requested filter echoed back", filtered.Data.Level)
	}
}

// An unrecognized level is a 400 naming the four real values. It must not
// be an empty list, which is indistinguishable from "the engine has been
// quiet" — the one thing a filter must never be able to look like.
func TestLoggingRecentRejectsAnUnknownLevel(t *testing.T) {
	f := newLoggingFixture(t)
	f.record(t, logger.LevelError, "token reuse detected", nil)

	for _, query := range []string{"?level=fatal", "?level=verbose", "?level=1"} {
		rec := f.recent(t, f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
			continue
		}
		for _, want := range []string{"debug", "info", "warn", "error"} {
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("%s: body = %s, want the valid values including %q", query, rec.Body.String(), want)
			}
		}
	}
}

func TestLoggingRecentBoundsTheLimit(t *testing.T) {
	f := newLoggingFixture(t)
	for _, message := range []string{"one", "two", "three"} {
		f.record(t, logger.LevelInfo, message, nil)
	}

	limited := decodeLogEvents(t, f.recent(t, f.adminToken, "?limit=2"))
	if limited.Data.Count != 2 {
		t.Errorf("count = %d with limit=2, want 2", limited.Data.Count)
	}
	if limited.Data.Events[0].Message != "three" {
		t.Errorf("first row = %q, want the newest of the bounded set", limited.Data.Events[0].Message)
	}

	// Bounded, not clamped: a caller that asked for 100000 and got 500 back
	// has no way to tell that from a log holding 500 records.
	for _, query := range []string{"?limit=0", "?limit=501", "?limit=lots"} {
		rec := f.recent(t, f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
		}
	}
}

// A router built without the sink answers 404 rather than 500 — a wiring
// fact, not a server fault, and the same shape every unconfigured feature
// in this API uses. Called directly because this repo has no engine without
// its stores either, and this is the only way to reach the branch.
func TestLoggingRecentWithoutAStoreIsNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/logging/recent", nil)
	rec := httptest.NewRecorder()

	h := &LoggingHandlers{}
	h.Recent(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_configured") {
		t.Errorf("body = %s, want the not_configured code", rec.Body.String())
	}
}

// The shipped copy is the redacted one, and this is the endpoint that shows
// it — so it sits behind the same gate as every other admin report. A
// record can name a user even after redaction, and the keyed digest mode
// exists precisely because the correlation is worth keeping.
func TestLoggingRecentRouteIsGatedByRequireAdmin(t *testing.T) {
	f := newLoggingFixture(t)
	f.record(t, logger.LevelWarn, "login: rate limited", map[string]string{"ip": "[redacted]"})

	if rec := f.recent(t, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := f.recent(t, "not-a-real-token", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: status = %d, want 401", rec.Code)
	}
	if rec := f.recent(t, f.userToken, ""); rec.Code != http.StatusForbidden {
		t.Errorf("ordinary user: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := f.recent(t, f.adminToken, ""); rec.Code != http.StatusOK {
		t.Errorf("operator: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}
