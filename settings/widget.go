package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	crydenai "github.com/crydensync/cryden/v2/ai"
)

// ErrInvalidAskAIWidget means the supplied widget configuration cannot be
// stored: a scope that names something the query surface cannot bound, an
// origin that is not an origin, or copy too long for a settings form.
var ErrInvalidAskAIWidget = errors.New("settings: invalid ask-ai widget configuration")

// Bounds on the stored copy and the two lists. Small on purpose: this is
// text a widget renders inside a chat bubble and a list an operator ticks
// by hand, so a value beyond these is a mistake or an attempt to use the
// settings table as storage rather than a configuration anyone wants.
const (
	maxWidgetCopyLength = 200
	maxWidgetOrigins    = 20
	maxWidgetEntities   = 8
)

// AskAIWidgetConfig is what an operator configures about the ask-ai
// widget: whether it is offered, which origins may embed it, which
// entities it will answer over, and the copy it shows.
//
// This is the one setting in this package that is NOT a credential, and
// that is why it has no Redacted counterpart — the other two would put an
// API key and a database password in a response if a handler reached for
// the wrong type, and this one is safe to return exactly as stored. The
// distinction is worth keeping visible rather than papering over with a
// Redacted method that returns a copy of itself.
//
// What is genuinely load-bearing here is Entities, and it is not
// decorative: cryden's widget.Ask force-scopes every parsed intent to the
// calling end user's own rows, but it scopes over the whole of
// ai.AllowedEntities. Narrowing that further is a host decision, so this
// repo enforces the configured subset in front of the provider — see
// aiprovider.ScopedProvider. A "scope" setting that nothing consulted
// would be worse than no setting at all.
type AskAIWidgetConfig struct {
	// Enabled is whether the widget is offered to end users at all. A
	// disabled widget is a 404 from whatever serves it, not an empty
	// answer.
	Enabled bool `json:"enabled"`
	// AllowedOrigins are the sites permitted to embed the widget, as
	// origins ("https://console.example.com"), never as patterns.
	AllowedOrigins []string `json:"allowed_origins"`
	// Entities are the ai.AllowedEntities the widget will answer over.
	// Always a subset of cryden's own allowlist; cryden's list is the
	// vocabulary and this is the host narrowing it.
	Entities []string `json:"entities"`
	// Greeting and Placeholder are the copy the embed shows.
	Greeting    string `json:"greeting"`
	Placeholder string `json:"placeholder"`
}

// Validate checks a configuration about to be stored.
//
// A disabled widget is allowed to be otherwise empty: an operator
// switching the feature off should be able to save the form without first
// filling in fields that are about to stop mattering. Everything else is
// checked in full, because "disabled" is the only state where an unset
// scope is not a promise the widget would fail to keep.
func (c AskAIWidgetConfig) Validate() error {
	if len(c.Greeting) > maxWidgetCopyLength {
		return fmt.Errorf("%w: greeting is longer than %d characters", ErrInvalidAskAIWidget, maxWidgetCopyLength)
	}
	if len(c.Placeholder) > maxWidgetCopyLength {
		return fmt.Errorf("%w: placeholder is longer than %d characters", ErrInvalidAskAIWidget, maxWidgetCopyLength)
	}

	if !c.Enabled {
		// Still checked, so that a form which fills in the fields and then
		// ticks the box cannot store something that was never validated
		// and would be rejected the moment it was switched on.
		if err := validateWidgetEntities(c.Entities); err != nil {
			return err
		}
		return validateWidgetOrigins(c.AllowedOrigins)
	}

	if strings.TrimSpace(c.Greeting) == "" {
		return fmt.Errorf("%w: greeting is required when the widget is enabled", ErrInvalidAskAIWidget)
	}
	if err := validateWidgetEntities(c.Entities); err != nil {
		return err
	}
	if len(c.Entities) == 0 {
		return fmt.Errorf("%w: at least one entity is required when the widget is enabled — the query surface has nothing to answer over otherwise", ErrInvalidAskAIWidget)
	}
	if err := validateWidgetOrigins(c.AllowedOrigins); err != nil {
		return err
	}
	if len(c.AllowedOrigins) == 0 {
		return fmt.Errorf("%w: at least one allowed origin is required when the widget is enabled", ErrInvalidAskAIWidget)
	}
	return nil
}

// validateWidgetEntities refuses an entity cryden does not allowlist.
//
// The check is against cryden's own map rather than a list restated here,
// for the same reason aiprovider.intentSchema builds its enums from those
// maps: a second copy of the vocabulary is a second thing to forget to
// update, and the failure mode of a stale copy is silent — a valid entity
// refused, or a refused one stored.
//
// One asymmetry is accepted knowingly. cryden's widget.scopeToOwner is a
// private switch over today's three entities, so an entity added to
// ai.AllowedEntities without a matching case there would pass here and
// then fail at Ask time with ErrEntityNotAvailable. That is the safe
// direction: the widget refuses the question rather than answering it
// unscoped, which is exactly the fail-closed default that package
// documents.
func validateWidgetEntities(entities []string) error {
	if len(entities) > maxWidgetEntities {
		return fmt.Errorf("%w: at most %d entities may be selected, got %d",
			ErrInvalidAskAIWidget, maxWidgetEntities, len(entities))
	}
	seen := make(map[string]bool, len(entities))
	for _, entity := range entities {
		if !crydenai.AllowedEntities[entity] {
			return fmt.Errorf("%w: %q is not an entity the AI query surface may touch", ErrInvalidAskAIWidget, entity)
		}
		if seen[entity] {
			return fmt.Errorf("%w: %q is listed twice", ErrInvalidAskAIWidget, entity)
		}
		seen[entity] = true
	}
	return nil
}

// validateWidgetOrigins checks that each entry is an origin and nothing
// more. A path, a query or an embedded credential in this list would be
// silently ignored by any origin comparison, so accepting one would be
// storing a value that does not mean what the operator who typed it
// thinks it means.
func validateWidgetOrigins(origins []string) error {
	if len(origins) > maxWidgetOrigins {
		return fmt.Errorf("%w: at most %d allowed origins may be listed, got %d",
			ErrInvalidAskAIWidget, maxWidgetOrigins, len(origins))
	}
	for _, origin := range origins {
		if err := validateWidgetOrigin(origin); err != nil {
			return err
		}
	}
	return nil
}

func validateWidgetOrigin(origin string) error {
	if strings.TrimSpace(origin) != origin || origin == "" {
		return fmt.Errorf("%w: an allowed origin must be non-empty and have no surrounding whitespace", ErrInvalidAskAIWidget)
	}
	// A wildcard is refused by name so the message can say why, rather
	// than falling through to "not a parseable URL" and reading as a
	// formatting nit. It is not a formatting nit: this widget answers
	// questions about the signed-in end user's own sessions and audit
	// events, so an origin list of "*" means any page on the internet can
	// ask those questions through a visitor's browser.
	if origin == "*" {
		return fmt.Errorf("%w: \"*\" is not accepted — list the origins that may embed the widget, because this one answers questions about the signed-in user", ErrInvalidAskAIWidget)
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("%w: %q is not a parseable origin: %v", ErrInvalidAskAIWidget, origin, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: %q has scheme %q, want http or https", ErrInvalidAskAIWidget, origin, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: %q names no host", ErrInvalidAskAIWidget, origin)
	}
	// "/" is what url.Parse produces for "https://x.example.com/" and is
	// the same origin, so it is allowed; anything else is a path.
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("%w: %q carries a path — an origin is scheme, host and port only", ErrInvalidAskAIWidget, origin)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return fmt.Errorf("%w: %q carries a query, fragment or credentials — an origin is scheme, host and port only", ErrInvalidAskAIWidget, origin)
	}
	return nil
}

// MarshalAskAIWidget and UnmarshalAskAIWidget are the encode/decode pair
// for storage, the same shape as the other two settings so "JSON, then
// sealed" has one spelling per setting. Unlike those two the payload is
// not a credential, but it is stored through the same Secrets wrapper and
// so is sealed by the same key — one storage path with one rule about
// what reaches the table is worth more than saving a decryption on a
// value nobody reads often.
func MarshalAskAIWidget(c AskAIWidgetConfig) ([]byte, error) {
	return json.Marshal(c)
}

func UnmarshalAskAIWidget(plaintext []byte) (AskAIWidgetConfig, error) {
	var c AskAIWidgetConfig
	if err := json.Unmarshal(plaintext, &c); err != nil {
		return AskAIWidgetConfig{}, fmt.Errorf("settings: decoding the stored ask-ai widget config: %w", err)
	}
	return c, nil
}
