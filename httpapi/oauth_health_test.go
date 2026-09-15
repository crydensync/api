package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/config"
)

// TestOAuthHealthReportsEveryProviderCase covers all four verdicts in one
// response, which is the property an operator actually depends on: one
// provider being unreachable must not stop the others being reported.
func TestOAuthHealthReportsEveryProviderCase(t *testing.T) {
	var mu sync.Mutex
	var probeQuery, probeAgent string

	// Answers the way a real authorize endpoint answers a request with no
	// client_id: 400. That is proof of life, not a failure, and this test
	// is where that reading is pinned.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		probeQuery, probeAgent = r.URL.RawQuery, r.Header.Get("User-Agent")
		mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ok.Close()

	degraded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer degraded.Close()

	// A server that has been closed stands in for DNS/TLS/connect
	// failures without the test needing a network.
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()

	urls := map[string]string{
		"google":    ok.URL,
		"github":    degraded.URL,
		"microsoft": closedURL,
		"discord":   "http://[::1", // unparseable: fails before a dial
		// apple is absent on purpose — that is the not-configured case.
	}
	h := &OAuthHealthHandlers{
		lookup: func(name string) (oauthProvider, bool) {
			authURL, configured := urls[name]
			if !configured {
				return oauthProvider{}, false
			}
			return oauthProvider{name: name, authURL: authURL}, true
		},
		client: &http.Client{Timeout: oauthHealthTimeout},
		names:  []string{"google", "github", "microsoft", "discord", "apple"},
	}

	rec := httptest.NewRecorder()
	h.Health(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/oauth/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var body struct {
		Data struct {
			Providers []oauthProviderHealth `json:"providers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}

	want := []struct {
		provider   string
		configured bool
		status     oauthHealthStatus
		httpStatus int
	}{
		{"google", true, oauthHealthOK, http.StatusBadRequest},
		{"github", true, oauthHealthDegraded, http.StatusServiceUnavailable},
		{"microsoft", true, oauthHealthUnreachable, 0},
		{"discord", true, oauthHealthUnreachable, 0},
		{"apple", false, oauthHealthNotConfigured, 0},
	}
	if len(body.Data.Providers) != len(want) {
		t.Fatalf("got %d rows, want %d", len(body.Data.Providers), len(want))
	}
	for i, w := range want {
		got := body.Data.Providers[i]
		if got.Provider != w.provider {
			t.Errorf("row %d is %q, want %q (order is the report's own)", i, got.Provider, w.provider)
		}
		if got.Configured != w.configured {
			t.Errorf("%s: configured = %v, want %v", w.provider, got.Configured, w.configured)
		}
		if got.Status != w.status {
			t.Errorf("%s: status = %q, want %q", w.provider, got.Status, w.status)
		}
		if got.HTTPStatus != w.httpStatus {
			t.Errorf("%s: http_status = %d, want %d", w.provider, got.HTTPStatus, w.httpStatus)
		}
		switch w.status {
		case oauthHealthOK, oauthHealthDegraded:
			if got.Error != "" {
				t.Errorf("%s: error = %q, want empty when a response arrived", w.provider, got.Error)
			}
			if got.LatencyMS < 0 {
				t.Errorf("%s: latency_ms = %d, want >= 0", w.provider, got.LatencyMS)
			}
		case oauthHealthUnreachable:
			if got.Error == "" {
				t.Errorf("%s: no error text explaining the verdict", w.provider)
			}
		case oauthHealthNotConfigured:
			// Nothing was probed, so nothing may be reported about a
			// request: the verdict is a configuration fact.
			if got.LatencyMS != 0 {
				t.Errorf("%s: latency_ms = %d, want 0 — an unconfigured provider must not be probed", w.provider, got.LatencyMS)
			}
		}
	}

	mu.Lock()
	defer mu.Unlock()
	// A health probe must not look like an authorization request.
	if probeQuery != "" {
		t.Errorf("probe sent query string %q; it must carry no OAuth parameters", probeQuery)
	}
	if probeAgent == "" {
		t.Error("probe sent no User-Agent, so a provider sees an anonymous request")
	}
}

// TestTruncate covers the only helper this endpoint added: error text
// goes into a JSON field, so it has to be bounded and stay valid UTF-8.
func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate left a short string alone incorrectly: %q", got)
	}
	if got := truncate("0123456789abc", 10); got != "0123456789…" {
		t.Errorf("truncate = %q, want the first 10 runes plus an ellipsis", got)
	}
	// Cut a multi-byte string at a rune boundary, not a byte one.
	got := truncate(strings.Repeat("é", 5), 3)
	if got != "ééé…" {
		t.Errorf("truncate = %q, want three whole runes plus an ellipsis", got)
	}
}

// The health check's own logic is covered above against real HTTP servers.
// What this covers is the part those cannot: that the route exists inside
// the real router and really is behind RequireAdmin, and that an operator
// token is the only thing that gets through it. It runs on the in-memory
// engine, so no database is involved anywhere — the router is built with a
// nil *sql.DB on purpose, which is safe because neither the gate nor this
// endpoint ever touches the database.
func TestAdminOAuthHealthRouteIsGatedByRequireAdmin(t *testing.T) {
	var operatorID string
	engine := newTestEngineWithClaims(t, token.ClaimsFunc(func(_ context.Context, userID string) (map[string]any, error) {
		if userID == operatorID {
			return map[string]any{"role": "admin"}, nil
		}
		return nil, nil
	}))
	ctx := context.Background()

	operator, err := cryden.SignUp(ctx, engine, "operator@example.com", testPassword, "203.0.113.1")
	if err != nil {
		t.Fatalf("signup (operator): %v", err)
	}
	// Set between signup and login: the claim is attached when a token is
	// issued, exactly as it is in production.
	operatorID = operator.ID
	operatorTokens, err := cryden.Login(ctx, engine, "operator@example.com", testPassword, "203.0.113.1", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (operator): %v", err)
	}

	if _, err := cryden.SignUp(ctx, engine, "regular@example.com", testPassword, "203.0.113.2"); err != nil {
		t.Fatalf("signup (regular user): %v", err)
	}
	userTokens, err := cryden.Login(ctx, engine, "regular@example.com", testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (regular user): %v", err)
	}

	router := NewRouter(Deps{Engine: engine, Config: config.Config{}})
	const path = "/v1/admin/oauth/health"

	call := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		router.ServeHTTP(rec, req)
		return rec
	}

	t.Run("no token", func(t *testing.T) {
		if rec := call(""); rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("ordinary user is refused", func(t *testing.T) {
		rec := call(userTokens.AccessToken)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
		}
		// One code for every flavour of "not an operator" — never
		// distinguishing a revoked operator from someone who never was one.
		if !strings.Contains(rec.Body.String(), "not_operator") {
			t.Errorf("body = %s, want the not_operator code", rec.Body.String())
		}
	})

	t.Run("operator gets the report", func(t *testing.T) {
		rec := call(operatorTokens.AccessToken)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		var body struct {
			Data struct {
				Providers []oauthProviderHealth `json:"providers"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding %s: %v", rec.Body.String(), err)
		}
		if len(body.Data.Providers) != len(oauthProviderNames) {
			t.Fatalf("got %d rows, want one per known provider (%d)", len(body.Data.Providers), len(oauthProviderNames))
		}
		// This router was built with an empty config, so nothing is
		// configured and nothing may have been probed.
		for _, row := range body.Data.Providers {
			if row.Status != oauthHealthNotConfigured {
				t.Errorf("%s: status = %q, want not_configured on a config with no providers", row.Provider, row.Status)
			}
		}
	})
}
