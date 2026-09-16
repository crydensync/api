package aiprovider

import (
	"context"
	"errors"

	crydenai "github.com/crydensync/cryden/v2/ai"
)

// ErrEntityOutOfScope means the parsed intent named an entity the
// deployment has not made available to the ask-ai widget.
var ErrEntityOutOfScope = errors.New("aiprovider: entity is outside the configured ask-ai scope")

// ScopedProvider narrows an ai.LLMProvider to a configured set of
// entities.
//
// It sits in front of the provider the widget uses, not in front of the
// admin one. cryden's widget.Ask already forces every intent to the
// calling end user's own rows — it discards whatever identity filter the
// model produced and substitutes the real one — and that is the security
// boundary, which this type does not touch or replace. What it adds is
// the layer above: which entities a deployment is willing to answer
// questions about at all, from a public-facing surface.
//
// The distinction matters because the two are decided by different
// people. cryden decides what can be scoped safely; the operator decides
// what this deployment offers. An operator who wants the widget to answer
// "when did I last log in" but not "what has been recorded against me"
// has no way to say so through cryden's fixed allowlist, and asking
// cryden to grow a per-host policy knob would be putting a host decision
// in the engine — the boundary CLAUDE.md draws.
//
// Wrapping ParseQueryIntent is the only place this can be done. By the
// time widget.Ask has an Answer, the query has already run, and the
// intent itself never leaves the package: Ask parses, scopes and executes
// in one call. Refusing at parse time is the one point where the entity
// is still visible to the host and nothing has been executed yet.
type ScopedProvider struct {
	inner    crydenai.LLMProvider
	entities map[string]bool
}

// NewScopedProvider wraps inner, refusing any entity not in entities.
//
// An empty entities set produces a provider that refuses everything,
// which is the correct reading of "no scope configured": a settings form
// that was never filled in should answer no questions rather than all of
// them. The caller is expected to check the widget's own Enabled flag
// before it gets this far; this is the second lock on the same door.
func NewScopedProvider(inner crydenai.LLMProvider, entities []string) *ScopedProvider {
	allowed := make(map[string]bool, len(entities))
	for _, entity := range entities {
		allowed[entity] = true
	}
	return &ScopedProvider{inner: inner, entities: allowed}
}

var _ crydenai.LLMProvider = (*ScopedProvider)(nil)

// ParseQueryIntent defers to the wrapped provider and then refuses an
// entity outside the configured scope.
//
// The refusal happens after the parse rather than before it, because the
// entity is the model's output and does not exist until then. That costs
// a model call on a question that will be rejected, which is the honest
// price: the alternative would be a second model call asking the model to
// classify its own question first, which is more expensive, less
// reliable, and still untrusted input.
//
// The error names neither the entity nor the scope. It reaches an end
// user through the widget, and telling them which entities this
// deployment does have configured would be describing the console's
// schema to whoever is typing questions at it.
func (p *ScopedProvider) ParseQueryIntent(ctx context.Context, naturalLanguage string) (crydenai.QueryIntent, error) {
	intent, err := p.inner.ParseQueryIntent(ctx, naturalLanguage)
	if err != nil {
		return crydenai.QueryIntent{}, err
	}
	if !p.entities[intent.Entity] {
		return crydenai.QueryIntent{}, ErrEntityOutOfScope
	}
	return intent, nil
}
