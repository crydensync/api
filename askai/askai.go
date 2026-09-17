// Package askai is the serving side of the ask-ai widget: cryden's
// owner-scoped query surface, handed to the signed-in end user it
// belongs to.
//
// The security boundary is not in this package. cryden's widget.Ask
// force-scopes every parsed intent to the one identity the caller
// supplies — it discards whatever identity filter the model produced
// and substitutes the real one — and aiprovider.ScopedProvider narrows
// which entities a deployment is willing to answer over at all. What
// this package adds is the last two things neither of those can do: the
// owner id must come from this repo's own authentication of the
// request, and the two providers cryden's widget.Config needs must be
// built from what an operator stored in the settings table.
//
// See docs/design of cryden's widget package for why ownerUserID is
// never read from the question or from anything derived from it.
package askai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	crydenai "github.com/crydensync/cryden/v2/ai"
	"github.com/crydensync/cryden/v2/widget"

	"github.com/crydensync/api/aiprovider"
	"github.com/crydensync/api/settings"
)

// maxQuestionLength bounds one question. This is chat copy typed into a
// widget, not a document: the bound is on what the deployment will pay
// to have parsed, since every question is at least one model call.
const maxQuestionLength = 500

var (
	// ErrNotConfigured means the widget is switched on but the
	// deployment has no LLM provider or no read-only database stored,
	// so there is nothing to answer with. A wiring fact, not a fault —
	// mapped to 404 like every other unconfigured feature in this api.
	ErrNotConfigured = errors.New("askai: the widget has no LLM provider or database configured")

	// ErrWidgetDisabled means an operator has switched the widget off.
	// This is the answer whether the setting was stored with
	// enabled=false or never stored at all: an unconfigured widget and
	// a deliberately disabled one are the same thing to a caller, and
	// the zero value of the stored config is disabled.
	ErrWidgetDisabled = errors.New("askai: the widget is switched off on this deployment")

	// ErrOriginNotAllowed means the request carried an Origin header
	// that is not in the configured allowlist. See checkOrigin for what
	// this does and does not protect against.
	ErrOriginNotAllowed = errors.New("askai: that origin is not allowed to embed the widget")

	// ErrInvalidQuestion means the question was empty or longer than
	// maxQuestionLength. Both are the caller's input rather than a
	// deployment fault, so both are one 400 with the reason in the
	// message rather than two codes nothing would branch on.
	ErrInvalidQuestion = errors.New("askai: invalid question")
)

// Service answers widget questions. It holds no state of its own beyond
// a cache of the providers built from the current settings.
type Service struct {
	secrets *settings.Secrets

	// providers builds the engine-facing pair from a stored
	// configuration. Nil means the real ones — see defaultProviders.
	//
	// It exists so that this package's own behaviour is testable without a
	// database: everything below the seam is cryden's widget.Ask and a
	// SELECT, and everything above it is this repo's. Leaving it nil in
	// production is the point — the concrete constructors are what ship —
	// and a test in this package replaces it with doubles so it can see
	// the intent that actually reached the store, which is the only way to
	// check that a question about somebody else cannot be asked.
	providers Providers

	// mu guards current. Held across a rebuild, which is cheap by
	// design — see build.
	mu      sync.Mutex
	current *built
}

// Providers builds the pair cryden's widget.Config needs from a stored
// configuration.
//
// It returns the raw provider and store; wrapping the provider in the
// scope check is build's job, not the factory's, so replacing this still
// exercises the real scope enforcement.
//
// The default is the Anthropic provider over the stored credential and
// the Postgres snapshot over the stored read-only connection. A host
// that wants a different LLM backend supplies its own, and so does a
// test that needs to see what reached the query surface.
type Providers func(
	llm settings.LLMProviderConfig,
	db settings.DatabaseProviderConfig,
) (crydenai.LLMProvider, crydenai.QueryableStore, io.Closer, error)

// defaultProviders builds what production runs: the Anthropic provider
// over the stored credential, and the snapshot over the stored read-only
// connection.
func defaultProviders(llm settings.LLMProviderConfig, db settings.DatabaseProviderConfig) (crydenai.LLMProvider, crydenai.QueryableStore, io.Closer, error) {
	provider, err := aiprovider.NewAnthropic(aiprovider.AnthropicConfig{
		APIKey:    llm.APIKey,
		Model:     llm.Model,
		MaxTokens: llm.MaxTokens,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	snapshot, err := aiprovider.NewPostgresSnapshot(db.DSN, db.MaxRows)
	if err != nil {
		return nil, nil, nil, err
	}
	return provider, snapshot, snapshot, nil
}

// built is the pair cryden's widget.Config needs, plus what it takes to
// tell whether it is still the pair the stored settings describe.
type built struct {
	// fingerprint is a digest of the settings this was built from, not
	// the settings themselves. Held as a digest because two of the three
	// inputs are credentials and a cache key is no place for one.
	fingerprint string

	provider crydenai.LLMProvider
	store    crydenai.QueryableStore

	// closer releases whatever the factory opened — the snapshot's pool,
	// in production. An interface rather than the concrete type because
	// the QueryableStore contract has no Close on it, and because a test's
	// double needs somewhere to hang its own cleanup.
	closer io.Closer
}

// New returns a Service over the settings store. A Service built over a
// Secrets with no encryption key is valid and answers ErrNotConfigured:
// the settings endpoints themselves are 404 in that deployment, so there
// is nothing that could have been configured.
func New(secrets *settings.Secrets) *Service {
	return &Service{secrets: secrets, providers: defaultProviders}
}

// NewWithProviders returns a Service that builds its providers with
// build rather than the default. See Providers — this is the hook for a
// host running a different LLM backend, and for a test that needs to
// observe what reaches the query surface.
func NewWithProviders(secrets *settings.Secrets, build Providers) *Service {
	return &Service{secrets: secrets, providers: build}
}

// Request is one widget question.
type Request struct {
	// OwnerUserID is the authenticated caller, from this repo's own
	// verification of their token. Never from the body and never from
	// anything the model produced — see the package doc.
	OwnerUserID string

	Question string

	// Origin is the request's Origin header, empty when it carried
	// none. Only ever consulted against the configured allowlist.
	Origin string
}

// Ask answers req.Question on behalf of req.OwnerUserID.
func (s *Service) Ask(ctx context.Context, req Request) (widget.Answer, error) {
	// Checked here as well as in the handler. The handler refuses an
	// empty question with a message written for a person; this is the
	// guard that holds for any other caller, because an empty question
	// reaching the model is a model call that buys nothing.
	if req.OwnerUserID == "" {
		return widget.Answer{}, widget.ErrMissingOwner
	}
	if strings.TrimSpace(req.Question) == "" {
		return widget.Answer{}, fmt.Errorf("%w: a question is required", ErrInvalidQuestion)
	}
	if len(req.Question) > maxQuestionLength {
		return widget.Answer{}, fmt.Errorf("%w: a question is limited to %d characters, got %d",
			ErrInvalidQuestion, maxQuestionLength, len(req.Question))
	}

	config, err := s.widgetConfig(ctx)
	if err != nil {
		return widget.Answer{}, err
	}
	// Enabled is checked before the origin, so a deployment that has
	// switched the widget off answers "off" rather than "that origin is
	// not allowed" — the second would be true and misleading, naming a
	// configuration detail of a feature that is not running.
	if !config.Enabled {
		return widget.Answer{}, ErrWidgetDisabled
	}
	if err := checkOrigin(config.AllowedOrigins, req.Origin); err != nil {
		return widget.Answer{}, err
	}

	// Read on every question rather than cached behind an invalidation
	// the settings handlers would have to remember to fire. Three short
	// reads and two AES-GCM opens, against one model call that takes
	// hundreds of milliseconds at best: the wrong side of this trade is
	// the one where a saved settings change does not take effect until a
	// restart, or takes effect only if every future writer remembers to
	// poke a hook.
	llmRaw, err := s.secrets.Get(ctx, settings.KeyLLMProvider)
	if errors.Is(err, settings.ErrNotFound) {
		return widget.Answer{}, ErrNotConfigured
	}
	if err != nil {
		return widget.Answer{}, err
	}
	dbRaw, err := s.secrets.Get(ctx, settings.KeyDatabaseProvider)
	if errors.Is(err, settings.ErrNotFound) {
		return widget.Answer{}, ErrNotConfigured
	}
	if err != nil {
		return widget.Answer{}, err
	}

	ready, err := s.build(llmRaw, dbRaw, config.Entities)
	if err != nil {
		return widget.Answer{}, err
	}

	// No Composer. cryden's widget package documents a nil Composer as
	// a valid, strictly safer default, and falls back to RenderResult —
	// a deterministic plain-text table built from rows that have already
	// been scoped to this one user. Supplying one would mean a second
	// model call per question, whose output nothing validates, for
	// prose. That is a decision worth making deliberately if it is ever
	// wanted; it is not one to make by default.
	return widget.Ask(ctx, widget.Config{
		Provider: ready.provider,
		Store:    ready.store,
	}, req.OwnerUserID, req.Question)
}

// Close releases the connection pool behind the cached providers. The
// cached pair is replaced and closed on every rebuild, so this is only
// about the last one — and nothing calls it yet, because this repo still
// has no graceful shutdown for it to hang off. It exists so that adding
// one does not have to start by widening this type's API.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return nil
	}
	var err error
	if s.current.closer != nil {
		err = s.current.closer.Close()
	}
	s.current = nil
	return err
}

// widgetConfig reads the stored widget configuration. Nothing stored
// reads as the zero value, which is disabled — the same answer an
// operator gets from GET /v1/admin/settings/ask-ai-widget, and the
// reason this returns no error for that case.
func (s *Service) widgetConfig(ctx context.Context) (settings.AskAIWidgetConfig, error) {
	raw, err := s.secrets.Get(ctx, settings.KeyAskAIWidget)
	if errors.Is(err, settings.ErrNotFound) {
		return settings.AskAIWidgetConfig{}, nil
	}
	if err != nil {
		return settings.AskAIWidgetConfig{}, err
	}
	return settings.UnmarshalAskAIWidget(raw)
}

// build returns the providers for these settings, reusing the cached
// pair when they are the settings it was built from.
//
// The check is on content rather than on a version or a timestamp: the
// settings are read fresh on every question, so comparing what was read
// against what is cached is the whole mechanism, and there is no window
// in which a change has been saved but not noticed.
//
// Building is deliberately cheap — aiprovider.NewPostgresSnapshot uses
// sql.Open, which does not connect — so a rebuild is a struct allocation
// and not a round trip. A stored connection that has since gone bad is
// therefore reported by the query that uses it rather than by this
// function, which is what keeps a broken setting from being a startup
// failure.
func (s *Service) build(llmRaw, dbRaw []byte, entities []string) (*built, error) {
	fingerprint := fingerprint(llmRaw, dbRaw, entities)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.current != nil && s.current.fingerprint == fingerprint {
		return s.current, nil
	}

	llmConfig, err := settings.UnmarshalLLMProvider(llmRaw)
	if err != nil {
		return nil, err
	}
	dbConfig, err := settings.UnmarshalDatabaseProvider(dbRaw)
	if err != nil {
		return nil, err
	}

	build := s.providers
	if build == nil {
		// The zero value builds what production builds, so a Service
		// assembled as a struct literal — which a test may well do —
		// behaves like one from New rather than panicking.
		build = defaultProviders
	}

	provider, store, closer, err := build(llmConfig, dbConfig)
	if err != nil {
		return nil, err
	}

	next := &built{
		fingerprint: fingerprint,
		// The scoped provider is what gives the widget's `entities`
		// setting teeth — see aiprovider.ScopedProvider. It wraps the
		// LLM provider and not the store, because the entity is the
		// model's output and refusing it is only possible at parse time.
		provider: aiprovider.NewScopedProvider(provider, entities),
		store:    store,
		closer:   closer,
	}

	if s.current != nil {
		// Closed while holding the lock, so a concurrent question cannot
		// be mid-query on a pool this is tearing down. The old pair is
		// only ever replaced here.
		if s.current.closer != nil {
			_ = s.current.closer.Close()
		}
	}
	s.current = next
	return next, nil
}

// fingerprint digests the settings a pair of providers was built from.
//
// Hashed rather than kept as a string because the LLM provider's
// plaintext is an API key and the database's is a connection string with
// a password in it, and a cache key lives as long as the process does.
func fingerprint(llmRaw, dbRaw []byte, entities []string) string {
	digest := sha256.New()
	digest.Write(llmRaw)
	digest.Write([]byte{0})
	digest.Write(dbRaw)
	digest.Write([]byte{0})
	// Entities are part of the key because they are part of the built
	// value: ScopedProvider holds them, so a scope change with no
	// credential change still has to rebuild.
	digest.Write([]byte(strings.Join(entities, ",")))
	return hex.EncodeToString(digest.Sum(nil))
}

// checkOrigin refuses a request whose Origin header names an origin the
// operator has not allowed.
//
// What this is: a guard against an embed on a site nobody meant to
// authorise. It is worth having — the widget answers questions about the
// signed-in user's own sessions and audit events, and a stray embed
// elsewhere on the internet would put those answers in front of whoever
// is browsing that page.
//
// What this is not: the security boundary. The boundary is the Bearer
// token, which is verified before this runs and which no origin can
// forge. Origin is a header the browser sets and anything that is not a
// browser sets freely, so a caller who wanted past this would simply not
// send one — which is exactly why an absent Origin is allowed rather
// than refused. Refusing it would break every non-browser client (the
// console itself, a mobile app, a test) while stopping nobody: the
// attacker who can forge an allowlisted origin can also omit it. Reading
// this check as authentication is the mistake worth avoiding here.
func checkOrigin(allowed []string, origin string) error {
	if strings.TrimSpace(origin) == "" {
		return nil
	}
	for _, candidate := range allowed {
		if sameOrigin(candidate, origin) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrOriginNotAllowed, origin)
}

// sameOrigin compares two origins by scheme and host, with the default
// port for the scheme treated as absent on both sides.
//
// That normalisation is not pedantry: browsers omit :443 from an https
// origin, so an operator who typed "https://console.example.com:443"
// into the allowlist would otherwise have configured an entry that could
// never match a real request — a setting that looks right, validates
// right, and silently refuses every embed.
func sameOrigin(a, b string) bool {
	canonicalA, ok := canonicalOrigin(a)
	if !ok {
		return false
	}
	canonicalB, ok := canonicalOrigin(b)
	if !ok {
		return false
	}
	return canonicalA == canonicalB
}

// canonicalOrigin reduces an origin to scheme://host[:port], and refuses
// anything that is not an origin at all.
//
// The refusals mirror settings.validateWidgetOrigin, which is the rule
// the allowlist was stored under. They have to agree: a comparison that
// silently ignored a path would accept a value the operator could never
// have stored, and the two sides of one rule disagreeing is how a check
// stops meaning what its comment says. A browser never puts a path in an
// Origin header, so nothing legitimate is refused here.
func canonicalOrigin(origin string) (string, bool) {
	parsed, err := url.Parse(origin)
	if err != nil {
		return "", false
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", false
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", false
	}

	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", false
	}
	// A bare host ("console.example.com") parses with an empty scheme,
	// and url.Parse happily reads "https://host:443" and "host:443" as
	// the same shape. Requiring the scheme is what keeps the first from
	// comparing equal to an allowlisted origin.
	if scheme != "http" && scheme != "https" {
		return "", false
	}

	port := parsed.Port()
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return scheme + "://" + host, true
	}
	return scheme + "://" + host + ":" + port, true
}
