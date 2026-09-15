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
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/config"
)

// supportResponse mirrors the endpoint's DTO field by field, so a renamed
// or dropped field fails here rather than silently changing the contract a
// support console reads.
type supportResponse struct {
	Data struct {
		Email string `json:"email"`
		Text  string `json:"text"`
	} `json:"data"`
}

type supportFixture struct {
	engine *cryden.Engine
	router http.Handler

	adminToken string
	userToken  string
	userEmail  string
}

// newSupportFixture builds an engine on the in-memory stores, on the
// lockout settings a real deployment runs — five failures then fifteen
// minutes, which is what config.Config defaults to. The threshold is set
// rather than left zero, because cryden's engine takes these straight from
// its config with no defaulting of its own: a zero threshold locks the
// account on the very first failure, which is not the deployment these
// tests are about.
func newSupportFixture(t *testing.T) supportFixture {
	t.Helper()
	ctx := context.Background()

	var adminID string
	engine, err := cryden.New(cryden.Config{
		JWTSecret:        "test-secret",
		Users:            memory.NewUserStore(),
		Sessions:         memory.NewSessionStore(),
		Audit:            memory.NewAuditStore(),
		Verifications:    memory.NewVerificationStore(),
		EmailSender:      stubMailSender{},
		MagicLinkSender:  stubMailSender{},
		LockoutThreshold: 5,
		LockoutDuration:  15 * time.Minute,
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

	return supportFixture{
		engine:     engine,
		router:     NewRouter(Deps{Engine: engine, Config: config.Config{}}),
		adminToken: adminTokens.AccessToken,
		userToken:  userTokens.AccessToken,
		userEmail:  userEmail,
	}
}

// failLogin makes one wrong-password attempt and insists it really failed.
// An assertion that a diagnosis shows failed attempts is worth nothing if
// the attempts before it quietly succeeded.
func (f supportFixture) failLogin(t *testing.T) {
	t.Helper()
	if _, err := cryden.Login(context.Background(), f.engine, f.userEmail, "not-the-password", "203.0.113.2", chromeOnMacOS); err == nil {
		t.Fatal("a login with the wrong password succeeded")
	}
}

func (f supportFixture) diagnose(t *testing.T, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/support/diagnose"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f supportFixture) diagnosis(t *testing.T, token, query string) supportResponse {
	t.Helper()
	rec := f.diagnose(t, token, query)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp supportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// The healthy case, which is what makes the failure cases mean anything:
// an account nobody has troubled reads as not locked, holding the one
// session its login created. The session count is the assertion that this
// report is reading live state rather than describing a template.
func TestDiagnoseReportsAHealthyAccount(t *testing.T) {
	f := newSupportFixture(t)

	resp := f.diagnosis(t, f.adminToken, "?email="+f.userEmail)
	if resp.Data.Email != f.userEmail {
		t.Errorf("email = %q, want the address asked about echoed back", resp.Data.Email)
	}
	if !strings.Contains(resp.Data.Text, "Login diagnosis for "+f.userEmail) {
		t.Errorf("text = %q, want the engine's report for this address", resp.Data.Text)
	}
	if !strings.Contains(resp.Data.Text, "Account is not locked.") {
		t.Errorf("text = %q, want the account reported as unlocked", resp.Data.Text)
	}
	if !strings.Contains(resp.Data.Text, "0 consecutive failed attempts") {
		t.Errorf("text = %q, want no failed attempts on an account that has none", resp.Data.Text)
	}
	if !strings.Contains(resp.Data.Text, "1 session is currently active") {
		t.Errorf("text = %q, want the session the login created", resp.Data.Text)
	}
}

// The ticket this endpoint exists for: an account that cannot get in.
// Five wrong passwords trip the configured lockout, and both halves of
// that — the lock and the failures behind it — have to show up, because
// "locked until 14:32" and "five bad passwords in a row" lead a support
// agent to different answers.
func TestDiagnoseReportsALockedAccountAndWhy(t *testing.T) {
	f := newSupportFixture(t)
	for i := 0; i < 5; i++ {
		f.failLogin(t)
	}

	resp := f.diagnosis(t, f.adminToken, "?email="+f.userEmail)
	if !strings.Contains(resp.Data.Text, "Account is LOCKED until") {
		t.Errorf("text = %q, want the lockout reported", resp.Data.Text)
	}
	if !strings.Contains(resp.Data.Text, "5 consecutive failed attempts") {
		t.Errorf("text = %q, want the five failures counted", resp.Data.Text)
	}
	// The history that explains it, not just the state. Both types are the
	// engine's own records — nothing here is inferred by this endpoint.
	for _, want := range []string{"Recent failure-type events", "login_failed", "account_locked"} {
		if !strings.Contains(resp.Data.Text, want) {
			t.Errorf("text = %q, want it to contain %q", resp.Data.Text, want)
		}
	}
}

// An address nobody has is the answer, not a 404 and not an error. The
// distinction is cryden's own (admin.DiagnoseLogin returns Found=false
// rather than an error) and this handler passes it through instead of
// inventing a status the engine did not mean — a support agent asking
// about a typo'd address needs told there is no account, which a 404
// would look identical to a broken endpoint.
func TestDiagnoseReportsAnUnknownAccountAsAnAnswer(t *testing.T) {
	f := newSupportFixture(t)

	resp := f.diagnosis(t, f.adminToken, "?email=nobody@example.com")
	if resp.Data.Email != "nobody@example.com" {
		t.Errorf("email = %q, want the address asked about", resp.Data.Email)
	}
	if !strings.Contains(resp.Data.Text, "No account exists for this email address.") {
		t.Errorf("text = %q, want the engine's own no-such-account answer", resp.Data.Text)
	}
}

// The address is the whole request, so a missing one is a 400 rather than
// a diagnosis of the empty string — which would come back as "no account
// exists", an answer to a question nobody asked.
func TestDiagnoseRequiresAnEmail(t *testing.T) {
	f := newSupportFixture(t)

	for _, query := range []string{"", "?email=", "?email=%20", "?email=%20%20"} {
		rec := f.diagnose(t, f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q: status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), "email") {
			t.Errorf("%q: body = %s, want the missing parameter named", query, rec.Body.String())
		}
	}
}

// Every diagnosis names an account and its failure history, so this sits
// behind the same gate as the rest of the admin surface. Read-only is not
// a reason to widen who can read it.
func TestDiagnoseRouteIsGatedByRequireAdmin(t *testing.T) {
	f := newSupportFixture(t)
	query := "?email=" + f.userEmail

	if rec := f.diagnose(t, "", query); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := f.diagnose(t, "not-a-real-token", query); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: status = %d, want 401", rec.Code)
	}
	if rec := f.diagnose(t, f.userToken, query); rec.Code != http.StatusForbidden {
		t.Errorf("ordinary user: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := f.diagnose(t, f.adminToken, query); rec.Code != http.StatusOK {
		t.Errorf("operator: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}
