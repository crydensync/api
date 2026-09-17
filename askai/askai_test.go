package askai

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	crydenai "github.com/crydensync/cryden/v2/ai"
	"github.com/crydensync/cryden/v2/widget"

	"github.com/crydensync/api/aiprovider"
	"github.com/crydensync/api/settings"
)

// owner is the identity this repo's authentication would have supplied.
// Every scoping assertion below is about this value reaching the store
// and no other.
const owner = "11111111-1111-1111-1111-111111111111"

// otherUser is what the model claims. Nothing may ever run against it.
const otherUser = "99999999-9999-9999-9999-999999999999"

const allowedOrigin = "https://console.example.com"

// fakeProvider stands in for the LLM. It returns whatever intent the
// test says the model produced — including one that names somebody else,
// which is the case that matters.
type fakeProvider struct {
	intent crydenai.QueryIntent
	err    error
}

func (p *fakeProvider) ParseQueryIntent(_ context.Context, _ string) (crydenai.QueryIntent, error) {
	if p.err != nil {
		return crydenai.QueryIntent{}, p.err
	}
	return p.intent, nil
}

// fakeStore records what actually reached the query surface. In
// production this is a Postgres snapshot on a role verified to refuse
// writes; here it is the observation point for the scope assertions.
type fakeStore struct {
	mu     sync.Mutex
	ran    []crydenai.QueryIntent
	result crydenai.QueryResult
	err    error
}

func (s *fakeStore) RunSafeQuery(_ context.Context, intent crydenai.QueryIntent) (crydenai.QueryResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ran = append(s.ran, intent)
	if s.err != nil {
		return crydenai.QueryResult{}, s.err
	}
	return s.result, nil
}

func (s *fakeStore) last(t *testing.T) crydenai.QueryIntent {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ran) == 0 {
		t.Fatal("no query reached the store")
	}
	return s.ran[len(s.ran)-1]
}

func (s *fakeStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ran)
}

// fakeCloser stands in for the snapshot's connection pool, so a test can
// see a rebuild releasing the pair it replaced.
type fakeCloser struct {
	mu     sync.Mutex
	closed int
}

func (c *fakeCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	return nil
}

type fixture struct {
	t        *testing.T
	service  *Service
	secrets  *settings.Secrets
	provider *fakeProvider
	store    *fakeStore

	// builds counts factory calls, which is how the caching tests see a
	// rebuild. closers is parallel to it.
	builds  int
	closers []*fakeCloser
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	secrets, err := settings.NewSecrets(settings.NewMemoryStore(), "askai-test-encryption-key")
	if err != nil {
		t.Fatalf("NewSecrets: %v", err)
	}

	f := &fixture{t: t, secrets: secrets, provider: &fakeProvider{}, store: &fakeStore{}}
	f.service = New(secrets)
	f.service.providers = func(settings.LLMProviderConfig, settings.DatabaseProviderConfig) (crydenai.LLMProvider, crydenai.QueryableStore, io.Closer, error) {
		closer := &fakeCloser{}
		f.builds++
		f.closers = append(f.closers, closer)
		return f.provider, f.store, closer, nil
	}
	return f
}

// putLLMConfig and friends write through Secrets, so the tests exercise
// the same seal-and-open path production reads.
func (f *fixture) putLLMConfig(cfg settings.LLMProviderConfig) {
	f.t.Helper()
	raw, err := settings.MarshalLLMProvider(cfg)
	if err != nil {
		f.t.Fatalf("MarshalLLMProvider: %v", err)
	}
	if err := f.secrets.Put(context.Background(), settings.KeyLLMProvider, raw); err != nil {
		f.t.Fatalf("secrets.Put: %v", err)
	}
}

func (f *fixture) putDBConfig(cfg settings.DatabaseProviderConfig) {
	f.t.Helper()
	raw, err := settings.MarshalDatabaseProvider(cfg)
	if err != nil {
		f.t.Fatalf("MarshalDatabaseProvider: %v", err)
	}
	if err := f.secrets.Put(context.Background(), settings.KeyDatabaseProvider, raw); err != nil {
		f.t.Fatalf("secrets.Put: %v", err)
	}
}

func (f *fixture) putWidgetConfig(cfg settings.AskAIWidgetConfig) {
	f.t.Helper()
	raw, err := settings.MarshalAskAIWidget(cfg)
	if err != nil {
		f.t.Fatalf("MarshalAskAIWidget: %v", err)
	}
	if err := f.secrets.Put(context.Background(), settings.KeyAskAIWidget, raw); err != nil {
		f.t.Fatalf("secrets.Put: %v", err)
	}
}

func testLLMConfig() settings.LLMProviderConfig {
	return settings.LLMProviderConfig{
		Kind:      settings.LLMProviderKindAnthropic,
		Model:     "claude-opus-5",
		APIKey:    "sk-ant-a-test-credential",
		MaxTokens: settings.DefaultLLMMaxTokens,
	}
}

func testDBConfig() settings.DatabaseProviderConfig {
	return settings.DatabaseProviderConfig{
		Label:   "the reporting replica",
		DSN:     "postgres://widget:a-password@127.0.0.1:5432/readonly?sslmode=disable",
		MaxRows: settings.DefaultDatabaseMaxRows,
	}
}

func testWidgetConfig() settings.AskAIWidgetConfig {
	return settings.AskAIWidgetConfig{
		Enabled:        true,
		AllowedOrigins: []string{allowedOrigin},
		Entities:       []string{"sessions"},
		Greeting:       "Ask about your account",
	}
}

// configure writes a complete, working deployment: both credentials and
// an enabled widget scoped to sessions.
func (f *fixture) configure() {
	f.t.Helper()
	f.putLLMConfig(testLLMConfig())
	f.putDBConfig(testDBConfig())
	f.putWidgetConfig(testWidgetConfig())
}

func (f *fixture) ask(question string) (widget.Answer, error) {
	f.t.Helper()
	return f.service.Ask(context.Background(), Request{
		OwnerUserID: owner,
		Question:    question,
		Origin:      allowedOrigin,
	})
}

// ---------- the identity boundary ----------

// TestAskScopesTheQueryToTheAuthenticatedOwner is the test this package
// exists for. The model names somebody else; the store must never see
// it. cryden's widget.Ask overwrites the identity filter rather than
// validating it, so what arrives at the store is the owner and nothing
// the model said about identity survives.
func TestAskScopesTheQueryToTheAuthenticatedOwner(t *testing.T) {
	f := newFixture(t)
	f.configure()
	f.provider.intent = crydenai.QueryIntent{
		Entity:  "sessions",
		Filters: []crydenai.QueryFilter{{Field: "user_id", Operator: "=", Value: otherUser}},
	}

	if _, err := f.ask("show me the other person's sessions"); err != nil {
		t.Fatalf("Ask: %v", err)
	}

	got := f.store.last(t)
	if got.Entity != "sessions" {
		t.Errorf("entity = %q, want sessions", got.Entity)
	}
	for _, filter := range got.Filters {
		if filter.Field != "user_id" {
			continue
		}
		if filter.Value != owner {
			t.Errorf("user_id filter = %q, want the authenticated owner %q", filter.Value, owner)
		}
		if filter.Value == otherUser {
			t.Errorf("the model's identity filter reached the store unchanged")
		}
	}
}

// TestAskKeepsNonIdentityFilters pins the other half of the same
// behaviour: scoping replaces the identity filter and leaves everything
// else the model produced alone, because no other field can cross the
// identity boundary once user_id is forced.
func TestAskKeepsNonIdentityFilters(t *testing.T) {
	f := newFixture(t)
	f.configure()
	f.provider.intent = crydenai.QueryIntent{
		Entity: "sessions",
		Filters: []crydenai.QueryFilter{
			{Field: "user_id", Operator: "=", Value: otherUser},
			{Field: "ip", Operator: "=", Value: "203.0.113.7"},
		},
	}

	if _, err := f.ask("sessions from 203.0.113.7"); err != nil {
		t.Fatalf("Ask: %v", err)
	}

	got := f.store.last(t)
	var sawIP, sawOwner bool
	for _, filter := range got.Filters {
		switch filter.Field {
		case "ip":
			sawIP = filter.Value == "203.0.113.7"
		case "user_id":
			sawOwner = filter.Value == owner
		}
	}
	if !sawIP {
		t.Errorf("the ip filter was dropped, filters = %+v", got.Filters)
	}
	if !sawOwner {
		t.Errorf("the owner filter is missing, filters = %+v", got.Filters)
	}
}

// TestAskScopesAUsersQueryToTheCallersOwnRow covers the entity where the
// row IS the user, so every filter the model produced is discarded
// rather than merged.
func TestAskScopesAUsersQueryToTheCallersOwnRow(t *testing.T) {
	f := newFixture(t)
	config := testWidgetConfig()
	config.Entities = []string{"users"}
	f.putLLMConfig(testLLMConfig())
	f.putDBConfig(testDBConfig())
	f.putWidgetConfig(config)

	f.provider.intent = crydenai.QueryIntent{
		Entity: "users",
		Filters: []crydenai.QueryFilter{
			{Field: "email", Operator: "=", Value: "someone.else@example.com"},
		},
	}

	if _, err := f.ask("what is my email"); err != nil {
		t.Fatalf("Ask: %v", err)
	}

	got := f.store.last(t)
	if len(got.Filters) != 1 {
		t.Fatalf("filters = %+v, want exactly the owner filter", got.Filters)
	}
	if got.Filters[0].Field != "id" || got.Filters[0].Value != owner {
		t.Errorf("filters = %+v, want id = %q", got.Filters, owner)
	}
}

// TestAskRequiresAnOwner checks the guard rather than the happy path. An
// empty owner is the one input that would make widget.Ask scope a query
// to nobody, and it is refused before any provider is built.
func TestAskRequiresAnOwner(t *testing.T) {
	f := newFixture(t)
	f.configure()

	_, err := f.service.Ask(context.Background(), Request{
		Question: "who am i",
		Origin:   allowedOrigin,
	})
	if !errors.Is(err, widget.ErrMissingOwner) {
		t.Fatalf("Ask with no owner = %v, want widget.ErrMissingOwner", err)
	}
	if f.builds != 0 {
		t.Errorf("providers built %d times for a request that had no owner", f.builds)
	}
}

// ---------- the deployment's own scope ----------

// TestAskRefusesAnEntityOutsideTheConfiguredScope is ScopedProvider
// reaching through the service: cryden allowlists audit_events, but this
// deployment configured sessions only, so the question is refused before
// it runs.
func TestAskRefusesAnEntityOutsideTheConfiguredScope(t *testing.T) {
	f := newFixture(t)
	f.configure() // entities: sessions
	f.provider.intent = crydenai.QueryIntent{Entity: "audit_events"}

	_, err := f.ask("what has been recorded against me")
	if !errors.Is(err, aiprovider.ErrEntityOutOfScope) {
		t.Fatalf("Ask = %v, want aiprovider.ErrEntityOutOfScope", err)
	}
	if f.store.count() != 0 {
		t.Errorf("a query ran for an entity outside the configured scope")
	}
}

// TestAskAllowsAnEntityInsideTheConfiguredScope is the control for the
// test above: the same entity runs once the operator has allowed it.
func TestAskAllowsAnEntityInsideTheConfiguredScope(t *testing.T) {
	f := newFixture(t)
	config := testWidgetConfig()
	config.Entities = []string{"audit_events"}
	f.putLLMConfig(testLLMConfig())
	f.putDBConfig(testDBConfig())
	f.putWidgetConfig(config)

	f.provider.intent = crydenai.QueryIntent{Entity: "audit_events"}

	if _, err := f.ask("what has been recorded against me"); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if got := f.store.last(t); got.Entity != "audit_events" {
		t.Errorf("entity = %q, want audit_events", got.Entity)
	}
}

// ---------- switched off, and not configured ----------

func TestAskRefusesADisabledWidget(t *testing.T) {
	f := newFixture(t)
	f.putLLMConfig(testLLMConfig())
	f.putDBConfig(testDBConfig())
	config := testWidgetConfig()
	config.Enabled = false
	f.putWidgetConfig(config)

	if _, err := f.ask("anything"); !errors.Is(err, ErrWidgetDisabled) {
		t.Fatalf("Ask = %v, want ErrWidgetDisabled", err)
	}
}

// TestAskTreatsAnUnstoredWidgetConfigAsDisabled covers the deployment
// that has never opened the settings screen. Nothing stored reads as the
// zero value, which is disabled — the same answer the admin GET gives.
func TestAskTreatsAnUnstoredWidgetConfigAsDisabled(t *testing.T) {
	f := newFixture(t)
	f.putLLMConfig(testLLMConfig())
	f.putDBConfig(testDBConfig())

	if _, err := f.ask("anything"); !errors.Is(err, ErrWidgetDisabled) {
		t.Fatalf("Ask = %v, want ErrWidgetDisabled", err)
	}
}

// TestAskRefusesWhenAProviderIsNotConfigured covers both halves: an
// enabled widget with no LLM provider, and one with no database. Either
// missing means there is nothing to answer with.
func TestAskRefusesWhenAProviderIsNotConfigured(t *testing.T) {
	tests := []struct {
		name  string
		store bool // whether the LLM provider is stored
		db    bool // whether the database is stored
	}{
		{name: "no LLM provider", db: true},
		{name: "no database", store: true},
		{name: "neither"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.putWidgetConfig(testWidgetConfig())
			if tt.store {
				f.putLLMConfig(testLLMConfig())
			}
			if tt.db {
				f.putDBConfig(testDBConfig())
			}

			if _, err := f.ask("anything"); !errors.Is(err, ErrNotConfigured) {
				t.Fatalf("Ask = %v, want ErrNotConfigured", err)
			}
			if f.builds != 0 {
				t.Errorf("providers built %d times for an unconfigured widget", f.builds)
			}
		})
	}
}

// ---------- origins ----------

func TestCheckOrigin(t *testing.T) {
	allowed := []string{allowedOrigin, "http://localhost:3000"}

	tests := []struct {
		name   string
		origin string
		want   error
	}{
		{name: "an allowed origin", origin: allowedOrigin},
		{name: "an allowed origin with a default port spelled out", origin: "https://console.example.com:443"},
		{name: "an allowed origin in different case", origin: "HTTPS://Console.Example.COM"},
		{name: "a second allowed origin", origin: "http://localhost:3000"},
		{
			name:   "no origin at all",
			origin: "",
			// A non-browser caller sends no Origin and is not made to
			// pretend otherwise; see checkOrigin on why refusing this
			// would be theatre.
			want: nil,
		},
		{name: "a different host", origin: "https://evil.example.com", want: ErrOriginNotAllowed},
		{name: "a subdomain of an allowed origin", origin: "https://console.example.com.evil.test", want: ErrOriginNotAllowed},
		{name: "a different scheme", origin: "http://console.example.com", want: ErrOriginNotAllowed},
		{name: "a different port", origin: "https://console.example.com:8443", want: ErrOriginNotAllowed},
		{name: "a path", origin: "https://console.example.com/widget", want: ErrOriginNotAllowed},
		{name: "the literal null origin", origin: "null", want: ErrOriginNotAllowed},
		{name: "a bare host with no scheme", origin: "console.example.com", want: ErrOriginNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkOrigin(allowed, tt.origin)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("checkOrigin(%q) = %v, want nil", tt.origin, err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("checkOrigin(%q) = %v, want %v", tt.origin, err, tt.want)
			}
		})
	}
}

// TestAskRefusesAnOriginThatIsNotAllowed checks the check is wired into
// the request path and happens before anything is built or spent.
func TestAskRefusesAnOriginThatIsNotAllowed(t *testing.T) {
	f := newFixture(t)
	f.configure()

	_, err := f.service.Ask(context.Background(), Request{
		OwnerUserID: owner,
		Question:    "who am i",
		Origin:      "https://evil.example.com",
	})
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("Ask = %v, want ErrOriginNotAllowed", err)
	}
	if f.builds != 0 {
		t.Errorf("providers built %d times for a refused origin", f.builds)
	}
}

// TestAskRefusesADisabledWidgetBeforeAnOrigin keeps the two refusals in
// the right order: a deployment that has switched the widget off should
// not answer "that origin is not allowed", which would be true and would
// describe a feature that is not running.
func TestAskRefusesADisabledWidgetBeforeAnOrigin(t *testing.T) {
	f := newFixture(t)
	f.putLLMConfig(testLLMConfig())
	f.putDBConfig(testDBConfig())
	config := testWidgetConfig()
	config.Enabled = false
	f.putWidgetConfig(config)

	_, err := f.service.Ask(context.Background(), Request{
		OwnerUserID: owner,
		Question:    "anything",
		Origin:      "https://evil.example.com",
	})
	if !errors.Is(err, ErrWidgetDisabled) {
		t.Fatalf("Ask = %v, want ErrWidgetDisabled rather than an origin refusal", err)
	}
}

// ---------- questions ----------

func TestAskRejectsAnEmptyOrOversizedQuestion(t *testing.T) {
	tests := []struct {
		name     string
		question string
	}{
		{name: "empty", question: ""},
		{name: "whitespace only", question: "   \t "},
		{name: "over the limit", question: strings.Repeat("a", maxQuestionLength+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.configure()

			if _, err := f.ask(tt.question); !errors.Is(err, ErrInvalidQuestion) {
				t.Fatalf("Ask = %v, want ErrInvalidQuestion", err)
			}
			// Refused before the model is called: an empty question that
			// reached the provider would be a model call that buys
			// nothing.
			if f.builds != 0 {
				t.Errorf("providers built %d times for a refused question", f.builds)
			}
		})
	}
}

func TestAskAcceptsAQuestionAtTheLimit(t *testing.T) {
	f := newFixture(t)
	f.configure()
	f.provider.intent = crydenai.QueryIntent{Entity: "sessions"}

	if _, err := f.ask(strings.Repeat("a", maxQuestionLength)); err != nil {
		t.Fatalf("Ask at the limit: %v", err)
	}
}

// ---------- the cache ----------

// TestAskRebuildsOnlyWhenTheStoredSettingsChange is the whole caching
// rule. Reading the settings on every question is what makes a saved
// change take effect without a restart; comparing them is what stops
// that from being a rebuild per question.
func TestAskRebuildsOnlyWhenTheStoredSettingsChange(t *testing.T) {
	f := newFixture(t)
	f.configure()
	f.provider.intent = crydenai.QueryIntent{Entity: "sessions"}

	if _, err := f.ask("one"); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if _, err := f.ask("two"); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if f.builds != 1 {
		t.Fatalf("built %d times for two questions with unchanged settings, want 1", f.builds)
	}

	// A changed credential has to rebuild: it is the provider.
	llm := testLLMConfig()
	llm.APIKey = "sk-ant-a-rotated-credential"
	f.putLLMConfig(llm)

	if _, err := f.ask("three"); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if f.builds != 2 {
		t.Fatalf("built %d times after a credential change, want 2", f.builds)
	}

	// So does a changed scope, which is the ScopedProvider's input even
	// though neither credential moved.
	config := testWidgetConfig()
	config.Entities = []string{"sessions", "audit_events"}
	f.putWidgetConfig(config)

	if _, err := f.ask("four"); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if f.builds != 3 {
		t.Fatalf("built %d times after a scope change, want 3", f.builds)
	}

	// And a change that does not reach the built pair does not rebuild:
	// the greeting is copy, not configuration the providers hold.
	config.Greeting = "Ask me anything"
	f.putWidgetConfig(config)

	if _, err := f.ask("five"); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if f.builds != 3 {
		t.Fatalf("built %d times after a copy-only change, want 3", f.builds)
	}
}

// TestAskClosesTheProvidersItReplaces checks a rebuild releases the pool
// it is replacing, which is the leak this cache could otherwise have.
func TestAskClosesTheProvidersItReplaces(t *testing.T) {
	f := newFixture(t)
	f.configure()
	f.provider.intent = crydenai.QueryIntent{Entity: "sessions"}

	if _, err := f.ask("one"); err != nil {
		t.Fatalf("Ask: %v", err)
	}

	llm := testLLMConfig()
	llm.APIKey = "sk-ant-a-rotated-credential"
	f.putLLMConfig(llm)

	if _, err := f.ask("two"); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if len(f.closers) != 2 {
		t.Fatalf("closers = %d, want 2", len(f.closers))
	}
	if got := f.closers[0].closed; got != 1 {
		t.Errorf("the replaced pair was closed %d times, want 1", got)
	}
	if got := f.closers[1].closed; got != 0 {
		t.Errorf("the current pair was closed %d times, want 0", got)
	}
}

// TestCloseReleasesTheCurrentPair covers the shutdown path. Nothing in
// this repo calls it yet — there is no graceful shutdown to hang it off
// — so it is tested here rather than left to be discovered broken.
func TestCloseReleasesTheCurrentPair(t *testing.T) {
	f := newFixture(t)
	f.configure()
	f.provider.intent = crydenai.QueryIntent{Entity: "sessions"}

	if _, err := f.ask("one"); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if err := f.service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := f.closers[0].closed; got != 1 {
		t.Errorf("the current pair was closed %d times, want 1", got)
	}
	// Idempotent: a shutdown path that runs twice must not panic.
	if err := f.service.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestFingerprintDoesNotCarryTheCredential is a small property with a
// large blast radius: the fingerprint is held for the life of the
// process, and two of its three inputs are secrets.
func TestFingerprintDoesNotCarryTheCredential(t *testing.T) {
	llm := testLLMConfig()
	db := testDBConfig()

	llmRaw, err := settings.MarshalLLMProvider(llm)
	if err != nil {
		t.Fatalf("MarshalLLMProvider: %v", err)
	}
	dbRaw, err := settings.MarshalDatabaseProvider(db)
	if err != nil {
		t.Fatalf("MarshalDatabaseProvider: %v", err)
	}

	got := fingerprint(llmRaw, dbRaw, []string{"sessions"})
	for _, secret := range []string{llm.APIKey, db.DSN, "a-password"} {
		if strings.Contains(got, secret) {
			t.Errorf("the fingerprint contains %q", secret)
		}
	}

	// And it still tells two different settings apart.
	if again := fingerprint(llmRaw, dbRaw, []string{"sessions"}); again != got {
		t.Errorf("the same settings produced two fingerprints")
	}
	if other := fingerprint(llmRaw, dbRaw, []string{"audit_events"}); other == got {
		t.Errorf("a scope change produced the same fingerprint")
	}
}
