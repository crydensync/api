package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crydensync/api/config"
)

// adminPaths is one route from each block under /v1/admin, not all 25 —
// the point of AdminOnly is that a route added later inherits the answer,
// so what needs pinning is that the gate is applied per block rather than
// that any particular list of paths is complete. Add a route to a new
// block and it belongs here; add one to an existing block and it does not.
var adminPaths = []string{
	"/v1/admin/oauth/health",
	"/v1/admin/security/hash-migration",
	"/v1/admin/security/mfa-adoption",
	"/v1/admin/users",
	"/v1/admin/users/some-user-id",
	"/v1/admin/users/some-user-id/metadata",
	"/v1/admin/webhooks/deliveries",
	"/v1/admin/logging/recent",
	"/v1/admin/digest",
	"/v1/admin/digest/history",
	"/v1/admin/support/diagnose",
	"/v1/admin/config-tuning",
	"/v1/admin/anomalies",
	"/v1/admin/settings/llm-provider",
	"/v1/admin/settings/database-provider",
	"/v1/admin/settings/ask-ai-widget",
}

// TestTier6AdminSurfaceIs501OnSQLite is the decision NEXT.md Tier 6 asked
// to be made explicitly rather than left to whatever happens to occur: a
// SQLite deployment answers 501 not_implemented_on_sqlite for the whole
// admin console, before the token is looked at, rather than failing as a
// confusing 500 from a missing operators table.
//
// No Authorization header is sent, and that is the assertion: on a
// Postgres deployment the same requests are 401 missing_auth_header,
// because RequireAdmin reaches the header check first. Getting 501 without
// one proves the gate never looked at the caller — which is the whole
// design, since a SQLite deployment has no operators and so could not have
// authenticated anyone anyway.
func TestTier6AdminSurfaceIs501OnSQLite(t *testing.T) {
	router := NewRouter(Deps{Config: config.Config{SQLitePath: "/var/lib/cryden/api.db"}})

	for _, path := range adminPaths {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("GET %s = %d, want 501 — body: %s", path, rec.Code, rec.Body.String())
			}
			body := decodeError(t, rec)
			if body.Code != "not_implemented_on_sqlite" {
				t.Errorf("code = %q, want not_implemented_on_sqlite", body.Code)
			}
			// The message has to name the backend, because the caller may
			// well be a legitimate operator and 501 alone does not tell
			// them what to do about it.
			if body.Message == "" {
				t.Error("message is empty; an operator is owed the reason")
			}
		})
	}
}

// TestTier6AdminSurfaceIsNotAnswering501OnPostgres is the other half, and
// without it the test above would pass on a router that answered 501 to
// everything on both backends. Same paths, same absent token, different
// backend: now the answer comes from RequireAdmin, which is the gate this
// one replaces.
//
// 401 rather than 403 because no token was sent at all — 403 not_operator
// is what a valid non-operator token gets, and that needs a real engine to
// verify one, which this test deliberately does not build (a nil engine is
// never reached, since the missing header short-circuits first).
func TestTier6AdminSurfaceIsNotAnswering501OnPostgres(t *testing.T) {
	router := NewRouter(Deps{Config: config.Config{DatabaseURL: "postgres://user:pw@localhost/db"}})

	for _, path := range adminPaths {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("GET %s = %d, want 401 from RequireAdmin — body: %s", path, rec.Code, rec.Body.String())
			}
			if body := decodeError(t, rec); body.Code != "missing_auth_header" {
				t.Errorf("code = %q, want missing_auth_header", body.Code)
			}
		})
	}
}

// The 501 is a statement about /v1/admin, not about the deployment. Core
// auth is what a SQLite deployment is FOR, so the routes around the admin
// block must still be routed normally — a 401 from RequireAuth is the
// proof that they are: the request reached its own middleware and was
// refused there, rather than being caught by the console's gate.
func TestTier6NonAdminRoutesAreUnaffectedOnSQLite(t *testing.T) {
	router := NewRouter(Deps{Config: config.Config{SQLitePath: "/var/lib/cryden/api.db"}})

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/sessions"},
		{http.MethodGet, "/v1/verify"},
		{http.MethodGet, "/v1/passkeys"},
		{http.MethodGet, "/v1/api-keys"},
		{http.MethodPost, "/v1/ask-ai"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))

			if rec.Code == http.StatusNotImplemented {
				t.Fatalf("%s %s answered 501 — the admin gate is leaking into the core surface", tc.method, tc.path)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s = %d, want 401 — body: %s", tc.method, tc.path, rec.Code, rec.Body.String())
			}
			if body := decodeError(t, rec); body.Code != "missing_auth_header" {
				t.Errorf("code = %q, want missing_auth_header", body.Code)
			}
		})
	}
}

// errBody is the {"error": {"code", "message"}} envelope every refusal on
// this API uses — declared locally because the other tests in this package
// each decode a success shape they own, and nothing yet needed the error
// one generically.
type errBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) errBody {
	t.Helper()
	var envelope struct {
		Error errBody `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decoding %q: %v", rec.Body.String(), err)
	}
	return envelope.Error
}
