package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/settings"
)

// testSettingsKey is the deployment key these tests seal with. Not a
// secret and not meant to look like one — the point of the encryption
// tests below is that a value written through the handler does not appear
// in the store as the bytes that went in, which any non-empty key shows.
const testSettingsKey = "test-settings-encryption-key"

type settingsFixture struct {
	store  *settings.MemoryStore
	router http.Handler

	adminToken string
	userToken  string
}

// newSettingsFixture builds an engine on in-memory stores plus a settings
// store held directly, because the point of several of these tests is
// what did or did not reach the table — which only the store itself can
// answer. key is the deployment's SETTINGS_ENCRYPTION_KEY; "" is the
// unconfigured deployment, which is a case worth testing on its own.
func newSettingsFixture(t *testing.T, key string) settingsFixture {
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

	if _, err := cryden.SignUp(ctx, engine, "dana@example.com", testPassword, "203.0.113.2"); err != nil {
		t.Fatalf("signup (user): %v", err)
	}
	userTokens, err := cryden.Login(ctx, engine, "dana@example.com", testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (user): %v", err)
	}

	store := settings.NewMemoryStore()
	secrets, err := settings.NewSecrets(store, key)
	if err != nil {
		t.Fatalf("settings.NewSecrets: %v", err)
	}

	return settingsFixture{
		store:      store,
		router:     NewRouter(Deps{Engine: engine, Settings: secrets}),
		adminToken: adminTokens.AccessToken,
		userToken:  userTokens.AccessToken,
	}
}

func (f settingsFixture) do(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// raw returns what is actually in the store under key, which is the only
// way to assert that a credential was sealed rather than trusted to a
// handler's good intentions.
func (f settingsFixture) raw(t *testing.T, key string) ([]byte, bool) {
	t.Helper()
	return f.store.Raw(key)
}

const llmProviderPath = "/v1/admin/settings/llm-provider"
const databaseProviderPath = "/v1/admin/settings/database-provider"
const widgetPath = "/v1/admin/settings/ask-ai-widget"

// Every route on this surface writes or reads a credential or a scope, so
// all nine are behind the same gate as the rest of /v1/admin.
func TestSettingsRoutesAreGatedByRequireAdmin(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, llmProviderPath},
		{http.MethodPut, llmProviderPath},
		{http.MethodDelete, llmProviderPath},
		{http.MethodGet, databaseProviderPath},
		{http.MethodPut, databaseProviderPath},
		{http.MethodDelete, databaseProviderPath},
		{http.MethodGet, widgetPath},
		{http.MethodPut, widgetPath},
		{http.MethodDelete, widgetPath},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			if rec := f.do(t, route.method, route.path, "", `{}`); rec.Code != http.StatusUnauthorized {
				t.Errorf("no token: status = %d, want 401", rec.Code)
			}
			if rec := f.do(t, route.method, route.path, "not-a-real-token", `{}`); rec.Code != http.StatusUnauthorized {
				t.Errorf("garbage token: status = %d, want 401", rec.Code)
			}
			if rec := f.do(t, route.method, route.path, f.userToken, `{}`); rec.Code != http.StatusForbidden {
				t.Errorf("ordinary user: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// A deployment with no SETTINGS_ENCRYPTION_KEY must refuse everything
// rather than store a credential it cannot seal. This is the case the
// whole Secrets type exists for, so it is asserted against every route
// and against the store, not just against the status code.
func TestSettingsRoutesRefuseWhenNoEncryptionKeyIsConfigured(t *testing.T) {
	f := newSettingsFixture(t, "")

	routes := []struct{ method, path, body string }{
		{http.MethodGet, llmProviderPath, ""},
		{http.MethodPut, llmProviderPath, `{"kind":"anthropic","model":"claude-opus-5","api_key":"sk-ant-x"}`},
		{http.MethodDelete, llmProviderPath, ""},
		{http.MethodGet, databaseProviderPath, ""},
		{http.MethodPut, databaseProviderPath, `{"label":"replica","dsn":"postgres://ro@127.0.0.1:5432/db"}`},
		{http.MethodDelete, databaseProviderPath, ""},
		{http.MethodGet, widgetPath, ""},
		{http.MethodPut, widgetPath, `{"enabled":true}`},
		{http.MethodDelete, widgetPath, ""},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			rec := f.do(t, route.method, route.path, f.adminToken, route.body)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "not_configured") {
				t.Errorf("body = %s, want the not_configured code", rec.Body.String())
			}
		})
	}

	keys, err := f.store.Keys(context.Background())
	if err != nil {
		t.Fatalf("listing the store: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("store holds %v, want nothing — an unconfigured deployment must not write a credential", keys)
	}
}

// The credential must not survive as the bytes that were submitted. This
// is the CLAUDE.md rule about treating this key like JWT_SECRET, asserted
// where it can actually be observed: in the table.
func TestLLMProviderKeyIsSealedBeforeItReachesTheStore(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	const apiKey = "sk-ant-super-secret-value"
	body := `{"kind":"anthropic","model":"claude-opus-5","api_key":"` + apiKey + `"}`

	if rec := f.do(t, http.MethodPut, llmProviderPath, f.adminToken, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	stored, ok := f.raw(t, settings.KeyLLMProvider)
	if !ok {
		t.Fatal("nothing was stored under the llm provider key")
	}
	if strings.Contains(string(stored), apiKey) {
		t.Errorf("the stored value contains the api key in the clear: %s", stored)
	}
	if strings.Contains(string(stored), "claude-opus-5") {
		t.Errorf("the stored value contains the plaintext config: %s", stored)
	}
}

// The credential never comes back out, in any form. Not masked, not
// truncated — the response type has no field for it at all, and this
// asserts the wire shape rather than the type, because the type is only a
// promise until something serialises it.
func TestLLMProviderGetNeverReturnsTheCredential(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	const apiKey = "sk-ant-super-secret-value"
	body := `{"kind":"anthropic","model":"claude-opus-5","api_key":"` + apiKey + `","max_tokens":4096}`
	if rec := f.do(t, http.MethodPut, llmProviderPath, f.adminToken, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d (body %s)", rec.Code, rec.Body.String())
	}

	rec := f.do(t, http.MethodGet, llmProviderPath, f.adminToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), apiKey) {
		t.Errorf("GET returned the api key: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sk-ant") {
		t.Errorf("GET returned part of the api key: %s", rec.Body.String())
	}

	var got struct {
		Data struct {
			Kind       string `json:"kind"`
			Model      string `json:"model"`
			MaxTokens  int    `json:"max_tokens"`
			APIKeySet  bool   `json:"api_key_set"`
			Configured bool   `json:"configured"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if !got.Data.Configured || !got.Data.APIKeySet {
		t.Errorf("api_key_set = %v, configured = %v, want both true", got.Data.APIKeySet, got.Data.Configured)
	}
	if got.Data.Model != "claude-opus-5" || got.Data.MaxTokens != 4096 {
		t.Errorf("model = %q, max_tokens = %d, want the stored values back", got.Data.Model, got.Data.MaxTokens)
	}
}

// "Nothing configured yet" is an answer, not a 404. A console renders an
// empty form from it; a 404 would make it render a broken panel.
func TestLLMProviderGetBeforeAnySaveIsAnEmptyAnswer(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	rec := f.do(t, http.MethodGet, llmProviderPath, f.adminToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var got struct {
		Data struct {
			Configured bool `json:"configured"`
			APIKeySet  bool `json:"api_key_set"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if got.Data.Configured || got.Data.APIKeySet {
		t.Errorf("configured = %v, api_key_set = %v, want both false", got.Data.Configured, got.Data.APIKeySet)
	}
}

// The credential is required on every write rather than "blank keeps the
// existing one" — see PutLLMProvider's comment for why the usual
// convention is the wrong one here.
func TestPutLLMProviderRequiresTheCredentialEveryTime(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	first := `{"kind":"anthropic","model":"claude-opus-5","api_key":"sk-ant-first"}`
	if rec := f.do(t, http.MethodPut, llmProviderPath, f.adminToken, first); rec.Code != http.StatusOK {
		t.Fatalf("first PUT: status = %d (body %s)", rec.Code, rec.Body.String())
	}

	second := `{"kind":"anthropic","model":"claude-opus-5","api_key":""}`
	rec := f.do(t, http.MethodPut, llmProviderPath, f.adminToken, second)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("second PUT: status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_llm_provider") {
		t.Errorf("body = %s, want invalid_llm_provider", rec.Body.String())
	}

	// And the refusal changed nothing: the first credential is still what
	// is stored, so a console that retried with an empty field has not
	// silently cleared a working key.
	if _, ok := f.raw(t, settings.KeyLLMProvider); !ok {
		t.Error("the refused write cleared the stored provider")
	}
}

func TestDeleteLLMProviderClearsWithoutNeedingTheCredential(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	body := `{"kind":"anthropic","model":"claude-opus-5","api_key":"sk-ant-x"}`
	if rec := f.do(t, http.MethodPut, llmProviderPath, f.adminToken, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d (body %s)", rec.Code, rec.Body.String())
	}

	if rec := f.do(t, http.MethodDelete, llmProviderPath, f.adminToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("DELETE: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if _, ok := f.raw(t, settings.KeyLLMProvider); ok {
		t.Error("DELETE left the row in place")
	}
}

// A DSN that cannot be connected to must be refused AND not stored. This
// is the ordering that matters: the read-only check runs before the write,
// so a failure in it leaves the deployment exactly as it was rather than
// half-configured with a connection nothing has verified.
//
// The target is a closed port on the loopback interface, which refuses
// immediately and needs no server — the point is the failure path, and
// CheckReadOnly reports it as unverifiable rather than as a pass or a
// refusal. That distinction is what this asserts.
func TestPutDatabaseProviderRefusesAnUnverifiableConnection(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	body := `{"label":"reporting replica","dsn":"postgres://reader:pw@127.0.0.1:1/cryden?sslmode=disable&connect_timeout=2"}`
	rec := f.do(t, http.MethodPut, databaseProviderPath, f.adminToken, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "database_role_unverified") {
		t.Errorf("body = %s, want database_role_unverified — a connection that could not be made is not a pass", rec.Body.String())
	}

	if _, ok := f.raw(t, settings.KeyDatabaseProvider); ok {
		t.Error("a connection the check could not verify was stored anyway")
	}
}

// A DSN that is not a Postgres connection string is caught before any
// connection is attempted, so a malformed form is a fast failure rather
// than a ten-second timeout.
func TestPutDatabaseProviderRejectsAMalformedDSNWithoutConnecting(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	cases := []struct{ name, body string }{
		{"no dsn", `{"label":"replica"}`},
		{"wrong scheme", `{"label":"replica","dsn":"mysql://reader@db.example.com/cryden"}`},
		{"no host", `{"label":"replica","dsn":"postgres://"}`},
		{"not a url or keyword string", `{"label":"replica","dsn":"just some words"}`},
		{"no label", `{"label":"  ","dsn":"postgres://reader@db.example.com/cryden"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.do(t, http.MethodPut, databaseProviderPath, f.adminToken, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "invalid_database_provider") {
				t.Errorf("body = %s, want invalid_database_provider", rec.Body.String())
			}
		})
	}

	if _, ok := f.raw(t, settings.KeyDatabaseProvider); ok {
		t.Error("a malformed configuration reached the store")
	}
}

// The stored DSN is a credential like the API key and is sealed the same
// way, and GET describes it without returning it.
func TestDatabaseProviderDSNIsSealedAndNeverReturned(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	// Sealed directly rather than through the handler, because the handler
	// refuses to store anything it could not connect to and there is no
	// Postgres in this test. What is under test here is the storage and
	// the response shape, both of which sit behind that check.
	const dsn = "postgres://reader:hunter2@db.internal:5432/cryden_ro?sslmode=require"
	config := settings.DatabaseProviderConfig{Label: "reporting replica", DSN: dsn, MaxRows: 50}
	if err := config.Validate(); err != nil {
		t.Fatalf("the fixture config does not validate: %v", err)
	}
	plaintext, err := settings.MarshalDatabaseProvider(config)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	secrets, err := settings.NewSecrets(f.store, testSettingsKey)
	if err != nil {
		t.Fatalf("settings.NewSecrets: %v", err)
	}
	if err := secrets.Put(context.Background(), settings.KeyDatabaseProvider, plaintext); err != nil {
		t.Fatalf("storing: %v", err)
	}

	stored, ok := f.raw(t, settings.KeyDatabaseProvider)
	if !ok {
		t.Fatal("nothing was stored")
	}
	if strings.Contains(string(stored), "hunter2") {
		t.Errorf("the stored value contains the password in the clear: %s", stored)
	}

	rec := f.do(t, http.MethodGet, databaseProviderPath, f.adminToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	for _, secret := range []string{"hunter2", "reader:", dsn} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("GET returned %q: %s", secret, rec.Body.String())
		}
	}

	var got struct {
		Data struct {
			Label      string `json:"label"`
			Host       string `json:"host"`
			Database   string `json:"database"`
			DSNSet     bool   `json:"dsn_set"`
			Configured bool   `json:"configured"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	// The host and database come back so an operator can tell which
	// connection is stored without being shown the credential.
	if got.Data.Host != "db.internal:5432" || got.Data.Database != "cryden_ro" {
		t.Errorf("host = %q, database = %q, want the two harmless halves back", got.Data.Host, got.Data.Database)
	}
	if !got.Data.DSNSet || !got.Data.Configured || got.Data.Label != "reporting replica" {
		t.Errorf("dsn_set = %v, configured = %v, label = %q", got.Data.DSNSet, got.Data.Configured, got.Data.Label)
	}
}

func TestAskAIWidgetRoundTrips(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	body := `{
		"enabled": true,
		"allowed_origins": ["https://console.example.com"],
		"entities": ["sessions", "audit_events"],
		"greeting": "Ask about your account",
		"placeholder": "When did I last log in?"
	}`
	if rec := f.do(t, http.MethodPut, widgetPath, f.adminToken, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d (body %s)", rec.Code, rec.Body.String())
	}

	rec := f.do(t, http.MethodGet, widgetPath, f.adminToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: status = %d (body %s)", rec.Code, rec.Body.String())
	}

	var got struct {
		Data settings.AskAIWidgetConfig `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if !got.Data.Enabled {
		t.Error("enabled came back false")
	}
	if len(got.Data.Entities) != 2 || got.Data.Entities[0] != "sessions" {
		t.Errorf("entities = %v, want the two that were saved, in order", got.Data.Entities)
	}
	if got.Data.Greeting != "Ask about your account" {
		t.Errorf("greeting = %q", got.Data.Greeting)
	}
}

// Before anything is saved the widget reads as off, which is what the
// zero value means — a console shows the feature as disabled rather than
// showing a form that looks as though someone filled it in.
func TestAskAIWidgetBeforeAnySaveIsDisabled(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	rec := f.do(t, http.MethodGet, widgetPath, f.adminToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("body = %s, want enabled:false", rec.Body.String())
	}
}

// The scope list is the one part of this setting with teeth, so what it
// refuses matters as much as what it accepts.
func TestPutAskAIWidgetRefusesAnOutOfScopeConfiguration(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	cases := []struct{ name, body string }{
		{
			"entity outside cryden's allowlist",
			`{"enabled":true,"allowed_origins":["https://c.example.com"],"entities":["password_hashes"],"greeting":"hi"}`,
		},
		{
			"wildcard origin",
			`{"enabled":true,"allowed_origins":["*"],"entities":["sessions"],"greeting":"hi"}`,
		},
		{
			"origin with a path",
			`{"enabled":true,"allowed_origins":["https://c.example.com/widget"],"entities":["sessions"],"greeting":"hi"}`,
		},
		{
			"enabled with no entities",
			`{"enabled":true,"allowed_origins":["https://c.example.com"],"greeting":"hi"}`,
		},
		{
			"enabled with no origins",
			`{"enabled":true,"entities":["sessions"],"greeting":"hi"}`,
		},
		{
			"enabled with no greeting",
			`{"enabled":true,"allowed_origins":["https://c.example.com"],"entities":["sessions"]}`,
		},
		{
			"duplicate entity",
			`{"enabled":true,"allowed_origins":["https://c.example.com"],"entities":["sessions","sessions"],"greeting":"hi"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.do(t, http.MethodPut, widgetPath, f.adminToken, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "invalid_ask_ai_widget") {
				t.Errorf("body = %s, want invalid_ask_ai_widget", rec.Body.String())
			}
		})
	}

	if _, ok := f.raw(t, settings.KeyAskAIWidget); ok {
		t.Error("a rejected configuration reached the store")
	}
}

// Switching the widget off must be savable without filling in the fields
// that are about to stop mattering.
func TestPutAskAIWidgetAcceptsADisabledEmptyConfiguration(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	rec := f.do(t, http.MethodPut, widgetPath, f.adminToken, `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestDeleteAskAIWidgetLeavesItDisabled(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	body := `{"enabled":true,"allowed_origins":["https://c.example.com"],"entities":["sessions"],"greeting":"hi"}`
	if rec := f.do(t, http.MethodPut, widgetPath, f.adminToken, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if rec := f.do(t, http.MethodDelete, widgetPath, f.adminToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("DELETE: status = %d (body %s)", rec.Code, rec.Body.String())
	}

	rec := f.do(t, http.MethodGet, widgetPath, f.adminToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("body = %s, want the widget back to disabled", rec.Body.String())
	}
}

// A malformed body is a 400 with a message about the body, not an invalid
// *configuration* — the two are different mistakes and an operator fixing
// one should not be told about the other.
func TestSettingsEndpointsRejectAMalformedBody(t *testing.T) {
	f := newSettingsFixture(t, testSettingsKey)

	for _, path := range []string{llmProviderPath, databaseProviderPath, widgetPath} {
		t.Run(path, func(t *testing.T) {
			rec := f.do(t, http.MethodPut, path, f.adminToken, `{"enabled":`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "malformed request body") {
				t.Errorf("body = %s, want the malformed-body message", rec.Body.String())
			}
		})
	}
}
