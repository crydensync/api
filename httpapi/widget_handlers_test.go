package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"

	crydenai "github.com/crydensync/cryden/v2/ai"

	"github.com/crydensync/api/askai"
	"github.com/crydensync/api/settings"
)

// The widget is the one AI-assisted surface here that is not behind
// RequireAdmin, so these tests are as much about who gets through the
// route as about what it answers.

type widgetFixture struct {
	router http.Handler
	store  *settings.MemoryStore

	// seen records the intents that reached the query surface, which is
	// where the identity assertion is made.
	seen *intentRecorder

	userToken  string
	userID     string
	adminToken string
}

// intentRecorder is the QueryableStore double. cryden's widget.Ask runs
// the query through here, so its contents are what the deployment would
// actually have executed.
type intentRecorder struct {
	mu      sync.Mutex
	intents []crydenai.QueryIntent
}

func (r *intentRecorder) RunSafeQuery(_ context.Context, intent crydenai.QueryIntent) (crydenai.QueryResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.intents = append(r.intents, intent)
	return crydenai.QueryResult{Columns: []string{"id"}, Rows: [][]string{{"s-1"}, {"s-2"}}}, nil
}

func (r *intentRecorder) all() []crydenai.QueryIntent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]crydenai.QueryIntent(nil), r.intents...)
}

// widgetAnswerProvider returns a fixed intent, standing in for the model.
type widgetAnswerProvider struct{ intent crydenai.QueryIntent }

func (p widgetAnswerProvider) ParseQueryIntent(_ context.Context, _ string) (crydenai.QueryIntent, error) {
	return p.intent, nil
}

// newWidgetFixture builds an engine on in-memory stores, an optional
// widget configuration, and a router whose query surface is the
// recorder. intent is what the model "produces"; withService=false
// leaves Deps.AskAI nil, which is the router a test that does not care
// about this feature gets.
func newWidgetFixture(t *testing.T, intent crydenai.QueryIntent, withService bool, configure func(*settings.Secrets)) widgetFixture {
	t.Helper()
	ctx := context.Background()

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

	dana, err := cryden.SignUp(ctx, engine, "dana@example.com", testPassword, "203.0.113.2")
	if err != nil {
		t.Fatalf("signup (user): %v", err)
	}
	userTokens, err := cryden.Login(ctx, engine, "dana@example.com", testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (user): %v", err)
	}

	store := settings.NewMemoryStore()
	secrets, err := settings.NewSecrets(store, testSettingsKey)
	if err != nil {
		t.Fatalf("settings.NewSecrets: %v", err)
	}
	if configure != nil {
		configure(secrets)
	}

	deps := Deps{Engine: engine, Settings: secrets}
	seen := &intentRecorder{}
	if withService {
		deps.AskAI = askai.NewWithProviders(secrets, func(settings.LLMProviderConfig, settings.DatabaseProviderConfig) (crydenai.LLMProvider, crydenai.QueryableStore, io.Closer, error) {
			return widgetAnswerProvider{intent: intent}, seen, nil, nil
		})
	}

	return widgetFixture{
		router:     NewRouter(deps),
		store:      store,
		seen:       seen,
		userToken:  userTokens.AccessToken,
		userID:     dana.ID,
		adminToken: adminTokens.AccessToken,
	}
}

// sessionsIntent is what the model returns in the tests that are not
// about the scope refusal.
func sessionsIntent() crydenai.QueryIntent {
	return crydenai.QueryIntent{Entity: "sessions"}
}

const askAIPath = "/v1/ask-ai"

const widgetTestOrigin = "https://console.example.com"

// enableWidget writes a complete, working widget configuration directly
// through Secrets — the same sealed path the settings handlers use.
func enableWidget(t *testing.T, secrets *settings.Secrets, mutate func(*settings.AskAIWidgetConfig)) {
	t.Helper()
	ctx := context.Background()

	llmRaw, err := settings.MarshalLLMProvider(settings.LLMProviderConfig{
		Kind:      settings.LLMProviderKindAnthropic,
		Model:     "claude-opus-5",
		APIKey:    "sk-ant-a-test-credential",
		MaxTokens: settings.DefaultLLMMaxTokens,
	})
	if err != nil {
		t.Fatalf("MarshalLLMProvider: %v", err)
	}
	if err := secrets.Put(ctx, settings.KeyLLMProvider, llmRaw); err != nil {
		t.Fatalf("secrets.Put (llm): %v", err)
	}

	dbRaw, err := settings.MarshalDatabaseProvider(settings.DatabaseProviderConfig{
		Label:   "the reporting replica",
		DSN:     "postgres://widget:a-password@127.0.0.1:5432/readonly?sslmode=disable",
		MaxRows: settings.DefaultDatabaseMaxRows,
	})
	if err != nil {
		t.Fatalf("MarshalDatabaseProvider: %v", err)
	}
	if err := secrets.Put(ctx, settings.KeyDatabaseProvider, dbRaw); err != nil {
		t.Fatalf("secrets.Put (db): %v", err)
	}

	config := settings.AskAIWidgetConfig{
		Enabled:        true,
		AllowedOrigins: []string{widgetTestOrigin},
		Entities:       []string{"sessions"},
		Greeting:       "Ask about your account",
	}
	if mutate != nil {
		mutate(&config)
	}
	widgetRaw, err := settings.MarshalAskAIWidget(config)
	if err != nil {
		t.Fatalf("MarshalAskAIWidget: %v", err)
	}
	if err := secrets.Put(ctx, settings.KeyAskAIWidget, widgetRaw); err != nil {
		t.Fatalf("secrets.Put (widget): %v", err)
	}
}

func (f widgetFixture) do(t *testing.T, token, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, askAIPath, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// ask posts a question as the end user from the allowed origin.
func (f widgetFixture) ask(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(t, f.userToken, body, map[string]string{"Origin": widgetTestOrigin})
}

type askAIData struct {
	Answer   string `json:"answer"`
	RowCount int    `json:"row_count"`
}

func decodeAskAI(t *testing.T, rec *httptest.ResponseRecorder) askAIData {
	t.Helper()
	var envelope struct {
		Data askAIData `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return envelope.Data
}

func decodeAPIError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return envelope.Error.Code
}

// TestAskAIRouteIsGatedByAuthNotAdmin is the shape of this feature in one
// test. The widget belongs to the signed-in end user, so a plain user
// token must get through — and an admin token must work too, because an
// operator is also a user of their own account. Failing this by requiring
// an operator would make the widget unusable for everyone it is for.
func TestAskAIRouteIsGatedByAuthNotAdmin(t *testing.T) {
	f := newWidgetFixture(t, sessionsIntent(), true, func(secrets *settings.Secrets) { enableWidget(t, secrets, nil) })

	if rec := f.do(t, "", `{"question":"when did i last log in"}`, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := f.do(t, "not-a-real-token", `{"question":"x"}`, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: status = %d, want 401", rec.Code)
	}
	if rec := f.ask(t, `{"question":"when did i last log in"}`); rec.Code != http.StatusOK {
		t.Errorf("end user: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := f.do(t, f.adminToken, `{"question":"when did i last log in"}`, map[string]string{"Origin": widgetTestOrigin}); rec.Code != http.StatusOK {
		t.Errorf("operator asking about their own account: status = %d, want 200", rec.Code)
	}
}

// TestAskAIScopesToTheTokenNotTheBody is the security assertion at the
// HTTP layer. The body has no field to name a user, so the only identity
// available is the verified token — and this test pins that by sending a
// body that claims one anyway and checking the store never sees it.
func TestAskAIScopesToTheTokenNotTheBody(t *testing.T) {
	f := newWidgetFixture(t, sessionsIntent(), true, func(secrets *settings.Secrets) { enableWidget(t, secrets, nil) })

	rec := f.ask(t, `{"question":"show me everything","user_id":"99999999-9999-9999-9999-999999999999","owner_user_id":"99999999-9999-9999-9999-999999999999"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	intents := f.seen.all()
	if len(intents) != 1 {
		t.Fatalf("queries run = %d, want 1", len(intents))
	}
	var sawOwner bool
	for _, filter := range intents[0].Filters {
		if filter.Field != "user_id" {
			continue
		}
		sawOwner = true
		if filter.Value != f.userID {
			t.Errorf("user_id filter = %q, want the token's user %q", filter.Value, f.userID)
		}
	}
	if !sawOwner {
		t.Errorf("no user_id filter reached the store, filters = %+v", intents[0].Filters)
	}
}

// TestAskAIReturnsTheAnswerAndRowCount pins the response shape.
func TestAskAIReturnsTheAnswerAndRowCount(t *testing.T) {
	f := newWidgetFixture(t, sessionsIntent(), true, func(secrets *settings.Secrets) { enableWidget(t, secrets, nil) })

	rec := f.ask(t, `{"question":"when did i last log in"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	data := decodeAskAI(t, rec)
	if !strings.Contains(data.Answer, "id") {
		t.Errorf("answer = %q, want the rendered result table", data.Answer)
	}
	if data.RowCount != 2 {
		t.Errorf("row_count = %d, want 2", data.RowCount)
	}
}

// TestAskAIRefusesAnOriginThatIsNotAllowed covers the embedding guard.
func TestAskAIRefusesAnOriginThatIsNotAllowed(t *testing.T) {
	f := newWidgetFixture(t, sessionsIntent(), true, func(secrets *settings.Secrets) { enableWidget(t, secrets, nil) })

	rec := f.do(t, f.userToken, `{"question":"x"}`, map[string]string{"Origin": "https://evil.example.com"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if code := decodeAPIError(t, rec); code != "origin_not_allowed" {
		t.Errorf("code = %q, want origin_not_allowed", code)
	}
	if len(f.seen.all()) != 0 {
		t.Errorf("a query ran for a refused origin")
	}
}

// TestAskAIRefusesWhenTheWidgetIsOff covers both "switched off" and
// "never configured", which are one answer to a caller.
func TestAskAIRefusesWhenTheWidgetIsOff(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		f := newWidgetFixture(t, sessionsIntent(), true, func(secrets *settings.Secrets) {
			enableWidget(t, secrets, func(c *settings.AskAIWidgetConfig) { c.Enabled = false })
		})

		rec := f.ask(t, `{"question":"x"}`)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
		}
		if code := decodeAPIError(t, rec); code != "ask_ai_widget_disabled" {
			t.Errorf("code = %q, want ask_ai_widget_disabled", code)
		}
	})

	t.Run("nothing stored", func(t *testing.T) {
		// withService=true and no configure: the service exists and the
		// settings store is empty, so the answer is "disabled" rather than
		// the not_configured a nil service gives.
		f := newWidgetFixture(t, sessionsIntent(), true, nil)

		rec := f.ask(t, `{"question":"x"}`)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
		}
		if code := decodeAPIError(t, rec); code != "ask_ai_widget_disabled" {
			t.Errorf("code = %q, want ask_ai_widget_disabled", code)
		}
	})
}

// TestAskAIRefusesAnUnanswerableQuestion covers the scope refusal
// reaching the client. The deployment is configured for sessions only
// and the model names audit_events, so aiprovider.ScopedProvider refuses
// it — and the message must not say which entities exist, because it
// reaches whoever is typing questions at the widget.
func TestAskAIRefusesAnUnanswerableQuestion(t *testing.T) {
	f := newWidgetFixture(t, crydenai.QueryIntent{Entity: "audit_events"}, true, func(secrets *settings.Secrets) {
		enableWidget(t, secrets, nil)
	})

	rec := f.ask(t, `{"question":"what has been recorded against me"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if code := decodeAPIError(t, rec); code != "question_not_answerable" {
		t.Errorf("code = %q, want question_not_answerable", code)
	}
	if body := rec.Body.String(); strings.Contains(body, "audit_events") || strings.Contains(body, "sessions") {
		t.Errorf("the refusal names an entity: %s", body)
	}
	if len(f.seen.all()) != 0 {
		t.Errorf("a query ran for an entity outside the configured scope")
	}
}

// TestAskAIRejectsAnEmptyQuestion covers the handler's own input check.
func TestAskAIRejectsAnEmptyQuestion(t *testing.T) {
	f := newWidgetFixture(t, sessionsIntent(), true, func(secrets *settings.Secrets) { enableWidget(t, secrets, nil) })

	for _, body := range []string{`{}`, `{"question":""}`, `{"question":"   "}`} {
		rec := f.ask(t, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestAskAIRejectsAMalformedBody(t *testing.T) {
	f := newWidgetFixture(t, sessionsIntent(), true, func(secrets *settings.Secrets) { enableWidget(t, secrets, nil) })

	rec := f.ask(t, `{"question":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestAskAIWithoutAServiceRefusesRatherThanPanicking covers the router
// built with no askai.Service — what a test that does not care about
// this feature gets. The request is authenticated, so RequireAuth lets
// it through and the handler's own nil guard is what answers.
func TestAskAIWithoutAServiceRefusesRatherThanPanicking(t *testing.T) {
	f := newWidgetFixture(t, sessionsIntent(), false, nil)

	rec := f.do(t, f.userToken, `{"question":"x"}`, map[string]string{"Origin": widgetTestOrigin})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if code := decodeAPIError(t, rec); code != "not_configured" {
		t.Errorf("code = %q, want not_configured", code)
	}
}
