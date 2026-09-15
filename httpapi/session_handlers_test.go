package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/memory"
)

// stubMailSender stands in for a real console/SES/SMTP implementation.
// Nothing in these tests reads what it is handed — a signup just needs
// the engine to have somewhere to hand a verification token.
type stubMailSender struct{}

func (stubMailSender) SendVerification(context.Context, string, string) error { return nil }
func (stubMailSender) SendMagicLink(context.Context, string, string) error    { return nil }

// chromeOnMacOS is a real UA string; cryden's own tests pin what it
// parses to ("Chrome" on "macOS", desktop form), so this is a
// known-good input rather than one this repo also has to own.
const chromeOnMacOS = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// newTestEngine builds a real cryden engine on the engine's own in-memory
// stores: no Postgres, no network, but every line below the HTTP layer is
// the production one. Tier 1's tests could only reach error mapping
// because there was no store to build on; this is what makes an endpoint's
// actual response shape testable here.
func newTestEngine(t *testing.T) *cryden.Engine {
	t.Helper()
	engine, err := cryden.New(cryden.Config{
		JWTSecret:       "test-secret",
		Users:           memory.NewUserStore(),
		Sessions:        memory.NewSessionStore(),
		Audit:           memory.NewAuditStore(),
		Verifications:   memory.NewVerificationStore(),
		EmailSender:     stubMailSender{},
		MagicLinkSender: stubMailSender{},
	})
	if err != nil {
		t.Fatalf("cryden.New on the in-memory stores: %v", err)
	}
	return engine
}

const testPassword = "Sup3r-Secret-Passphrase-42!"

// ListSessions now answers with named sessions, which is a deliberate
// change to an endpoint's response shape rather than a quietly added
// field — so the shape itself is what this test pins, field by field.
func TestListSessionsReturnsNamedSessions(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()

	if _, err := cryden.SignUp(ctx, engine, "dana@example.com", testPassword, "203.0.113.7"); err != nil {
		t.Fatalf("signup: %v", err)
	}
	tokens, err := cryden.Login(ctx, engine, "dana@example.com", testPassword, "203.0.113.7", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	handler := RequireAuth(engine, (&SessionHandlers{Engine: engine}).List)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Data []struct {
			ID        string `json:"id"`
			IP        string `json:"ip"`
			UserAgent string `json:"user_agent"`
			CreatedAt string `json:"created_at"`
			Label     string `json:"label"`
			Device    struct {
				Browser string `json:"browser"`
				OS      string `json:"os"`
				Form    string `json:"form"`
			} `json:"device"`
			Location struct {
				City    string `json:"city"`
				Region  string `json:"region"`
				Country string `json:"country"`
			} `json:"location"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("got %d sessions, want 1", len(resp.Data))
	}

	got := resp.Data[0]
	if got.ID == "" {
		t.Error("id is empty")
	}
	if got.IP != "203.0.113.7" {
		t.Errorf("ip = %q, want the login's caller IP", got.IP)
	}
	if got.UserAgent != chromeOnMacOS {
		t.Errorf("user_agent = %q, want the login's User-Agent", got.UserAgent)
	}
	if _, err := time.Parse(time.RFC3339, got.CreatedAt); err != nil {
		t.Errorf("created_at = %q, not RFC3339: %v", got.CreatedAt, err)
	}

	// The label is the whole point of the change, and with no geolocator
	// wired it is the device half alone — never empty, never "— unknown".
	if got.Label != "Chrome on macOS" {
		t.Errorf("label = %q, want %q", got.Label, "Chrome on macOS")
	}
	if got.Device.Browser != "Chrome" || got.Device.OS != "macOS" || got.Device.Form != "desktop" {
		t.Errorf("device = %+v, want Chrome on macOS, desktop", got.Device)
	}
	// No geolocator implementation is wired in this repo (Config.Geolocator
	// is a deployment's own choice — every implementation of it calls
	// somebody else's internet service), so the structured location is
	// present but empty. Pinned so that stays a deliberate state rather
	// than drifting into "some deployments get null".
	if got.Location.City != "" || got.Location.Region != "" || got.Location.Country != "" {
		t.Errorf("location = %+v, want empty without a geolocator", got.Location)
	}
}

// The session redaction this handler was built around is easy to lose by
// switching to a richer engine type: this asserts on the raw JSON that
// nothing token-shaped travels with the new fields.
func TestListSessionsStillRedactsTokenMaterial(t *testing.T) {
	engine := newTestEngine(t)
	ctx := context.Background()

	if _, err := cryden.SignUp(ctx, engine, "erin@example.com", testPassword, "203.0.113.9"); err != nil {
		t.Fatalf("signup: %v", err)
	}
	tokens, err := cryden.Login(ctx, engine, "erin@example.com", testPassword, "203.0.113.9", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	handler := RequireAuth(engine, (&SessionHandlers{Engine: engine}).List)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	handler(rec, req)

	var raw struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if len(raw.Data) != 1 {
		t.Fatalf("got %d sessions, want 1", len(raw.Data))
	}
	for _, forbidden := range []string{"token_hash", "family_id", "refresh_token"} {
		if _, present := raw.Data[0][forbidden]; present {
			t.Errorf("%s is present in the session response", forbidden)
		}
	}
}

func TestListSessionsRequiresAuth(t *testing.T) {
	engine := newTestEngine(t)
	handler := RequireAuth(engine, (&SessionHandlers{Engine: engine}).List)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/v1/sessions", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a token", rec.Code)
	}
}
