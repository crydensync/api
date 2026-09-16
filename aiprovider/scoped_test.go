package aiprovider

import (
	"context"
	"errors"
	"strings"
	"testing"

	crydenai "github.com/crydensync/cryden/v2/ai"
)

// fixedProvider returns whatever intent it was built with, which is what
// makes it usable as the inner provider here: the test controls exactly
// what the model "produced" without any network call.
type fixedProvider struct {
	intent crydenai.QueryIntent
	err    error

	calls int
}

func (p *fixedProvider) ParseQueryIntent(context.Context, string) (crydenai.QueryIntent, error) {
	p.calls++
	if p.err != nil {
		return crydenai.QueryIntent{}, p.err
	}
	return p.intent, nil
}

func TestScopedProviderPassesThroughAConfiguredEntity(t *testing.T) {
	inner := &fixedProvider{intent: crydenai.QueryIntent{Entity: "sessions"}}
	scoped := NewScopedProvider(inner, []string{"sessions", "audit_events"})

	intent, err := scoped.ParseQueryIntent(context.Background(), "when did I last log in")
	if err != nil {
		t.Fatalf("ParseQueryIntent: %v", err)
	}
	if intent.Entity != "sessions" {
		t.Errorf("entity = %q, want it passed through", intent.Entity)
	}
}

// The whole point of the type: an entity the deployment has not made
// available is refused, even though cryden's own allowlist permits it and
// widget.Ask would happily scope it.
func TestScopedProviderRefusesAnEntityOutsideTheConfiguredScope(t *testing.T) {
	inner := &fixedProvider{intent: crydenai.QueryIntent{Entity: "audit_events"}}
	scoped := NewScopedProvider(inner, []string{"sessions"})

	_, err := scoped.ParseQueryIntent(context.Background(), "what has been recorded against me")
	if !errors.Is(err, ErrEntityOutOfScope) {
		t.Fatalf("error = %v, want ErrEntityOutOfScope", err)
	}
}

// A scope that was never configured answers nothing rather than
// everything. A settings form nobody filled in is not permission.
func TestScopedProviderWithNoEntitiesRefusesEverything(t *testing.T) {
	for _, entities := range [][]string{nil, {}} {
		scoped := NewScopedProvider(&fixedProvider{intent: crydenai.QueryIntent{Entity: "users"}}, entities)

		_, err := scoped.ParseQueryIntent(context.Background(), "who am I")
		if !errors.Is(err, ErrEntityOutOfScope) {
			t.Errorf("scope %v: error = %v, want ErrEntityOutOfScope", entities, err)
		}
	}
}

// The inner provider's own failure is passed through unchanged: this
// wrapper narrows a scope, it does not reinterpret a model call that
// failed.
func TestScopedProviderPassesThroughTheInnerError(t *testing.T) {
	sentinel := errors.New("the provider refused")
	scoped := NewScopedProvider(&fixedProvider{err: sentinel}, []string{"sessions"})

	_, err := scoped.ParseQueryIntent(context.Background(), "anything")
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want the inner provider's error", err)
	}
}

// The refusal has to name nothing. It reaches an end user through the
// widget, and an error that listed the deployment's configured entities
// would be describing the console's schema to whoever is typing
// questions at it.
func TestScopedProviderRefusalNamesNeitherEntityNorScope(t *testing.T) {
	scoped := NewScopedProvider(
		&fixedProvider{intent: crydenai.QueryIntent{Entity: "audit_events"}},
		[]string{"sessions"},
	)

	_, err := scoped.ParseQueryIntent(context.Background(), "anything")
	if err == nil {
		t.Fatal("nothing was refused")
	}
	message := err.Error()
	for _, leak := range []string{"audit_events", "sessions"} {
		if strings.Contains(message, leak) {
			t.Errorf("error = %q, want it to name neither the refused entity nor the configured scope", message)
		}
	}
}
