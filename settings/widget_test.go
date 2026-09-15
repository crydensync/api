package settings

import (
	"errors"
	"strings"
	"testing"

	crydenai "github.com/crydensync/cryden/v2/ai"
)

// The accepting cases, including the two shapes that look wrong and are
// not: a trailing slash is the same origin, and a port is part of one.
func TestValidateWidgetOriginAcceptsRealOrigins(t *testing.T) {
	for _, origin := range []string{
		"https://console.example.com",
		"https://console.example.com/",
		"https://console.example.com:8443",
		"http://localhost:3000",
	} {
		if err := validateWidgetOrigin(origin); err != nil {
			t.Errorf("validateWidgetOrigin(%q) = %v, want nil", origin, err)
		}
	}
}

// Every one of these would be silently ignored by an origin comparison,
// so accepting one would store a value that does not mean what the
// operator who typed it thinks it means.
func TestValidateWidgetOriginRefusesAnythingThatIsNotAnOrigin(t *testing.T) {
	cases := []struct{ name, origin string }{
		{"wildcard", "*"},
		{"empty", ""},
		{"surrounding whitespace", " https://console.example.com"},
		{"a path", "https://console.example.com/widget"},
		{"a query", "https://console.example.com?tenant=1"},
		{"a fragment", "https://console.example.com#top"},
		{"embedded credentials", "https://user:pw@console.example.com"},
		{"no scheme", "console.example.com"},
		{"a non-http scheme", "ftp://console.example.com"},
		{"no host", "https://"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateWidgetOrigin(tc.origin); err == nil {
				t.Errorf("validateWidgetOrigin(%q) was accepted, want a refusal", tc.origin)
			} else if !errors.Is(err, ErrInvalidAskAIWidget) {
				t.Errorf("error = %v, want it to wrap ErrInvalidAskAIWidget", err)
			}
		})
	}
}

// The wildcard gets its own message, because "not a parseable origin"
// would read as a formatting nit and this is not one.
func TestWildcardOriginExplainsItself(t *testing.T) {
	err := validateWidgetOrigin("*")
	if err == nil {
		t.Fatal("the wildcard origin was accepted")
	}
	if !strings.Contains(err.Error(), "signed-in user") {
		t.Errorf("error = %q, want it to say why a wildcard is refused", err)
	}
}

// The entity list is checked against cryden's own map rather than a copy
// of it, so every entity the engine allowlists has to pass here. A
// restated list would drift, and this is what would catch it.
func TestValidateWidgetEntitiesAcceptsEverythingCrydenAllowlists(t *testing.T) {
	for entity := range crydenai.AllowedEntities {
		if err := validateWidgetEntities([]string{entity}); err != nil {
			t.Errorf("validateWidgetEntities(%q) = %v, want nil — cryden allowlists it", entity, err)
		}
	}
}

func TestValidateWidgetEntitiesRefusesUnknownAndRepeated(t *testing.T) {
	if err := validateWidgetEntities([]string{"password_hashes"}); err == nil {
		t.Error("an entity cryden does not allowlist was accepted")
	}
	if err := validateWidgetEntities([]string{"sessions", "sessions"}); err == nil {
		t.Error("a repeated entity was accepted")
	}
	if err := validateWidgetEntities([]string{""}); err == nil {
		t.Error("an empty entity was accepted")
	}
}

// A disabled widget may be otherwise empty — an operator switching the
// feature off should not have to fill in fields that are about to stop
// mattering. Anything that IS filled in is still validated, so a form
// cannot store a value that was never checked and would be rejected the
// moment it was switched on.
func TestValidateAcceptsADisabledEmptyWidgetButNotADisabledInvalidOne(t *testing.T) {
	if err := (AskAIWidgetConfig{Enabled: false}).Validate(); err != nil {
		t.Errorf("an empty disabled configuration = %v, want nil", err)
	}
	if err := (AskAIWidgetConfig{Enabled: false, Entities: []string{"password_hashes"}}).Validate(); err == nil {
		t.Error("a disabled configuration carrying an out-of-scope entity was accepted")
	}
	if err := (AskAIWidgetConfig{Enabled: false, AllowedOrigins: []string{"*"}}).Validate(); err == nil {
		t.Error("a disabled configuration carrying a wildcard origin was accepted")
	}
}

// An enabled widget has to say what it is and who may embed it; the zero
// values of those fields are not usable answers.
func TestValidateRequiresTheEnabledWidgetToBeComplete(t *testing.T) {
	complete := AskAIWidgetConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://console.example.com"},
		Entities:       []string{"sessions"},
		Greeting:       "Ask about your account",
	}
	if err := complete.Validate(); err != nil {
		t.Fatalf("a complete configuration = %v, want nil", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*AskAIWidgetConfig)
	}{
		{"no entities", func(c *AskAIWidgetConfig) { c.Entities = nil }},
		{"no origins", func(c *AskAIWidgetConfig) { c.AllowedOrigins = nil }},
		{"blank greeting", func(c *AskAIWidgetConfig) { c.Greeting = "   " }},
		{"greeting too long", func(c *AskAIWidgetConfig) { c.Greeting = strings.Repeat("x", maxWidgetCopyLength+1) }},
		{"placeholder too long", func(c *AskAIWidgetConfig) { c.Placeholder = strings.Repeat("x", maxWidgetCopyLength+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := complete
			tc.mutate(&config)
			if err := config.Validate(); err == nil {
				t.Error("accepted, want a refusal")
			}
		})
	}
}

// The two lists are bounded so a settings form cannot be used as storage.
func TestValidateBoundsTheWidgetLists(t *testing.T) {
	tooManyOrigins := AskAIWidgetConfig{Enabled: true, Entities: []string{"sessions"}, Greeting: "hi"}
	for i := 0; i <= maxWidgetOrigins; i++ {
		tooManyOrigins.AllowedOrigins = append(tooManyOrigins.AllowedOrigins, "https://c.example.com")
	}
	if err := tooManyOrigins.Validate(); err == nil {
		t.Errorf("accepted %d origins, want at most %d", len(tooManyOrigins.AllowedOrigins), maxWidgetOrigins)
	}

	// Distinct entities, because the duplicate rule would fire first.
	tooManyEntities := AskAIWidgetConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://console.example.com"},
		Greeting:       "hi",
	}
	for entity := range crydenai.AllowedEntities {
		tooManyEntities.Entities = append(tooManyEntities.Entities, entity)
	}
	for len(tooManyEntities.Entities) <= maxWidgetEntities {
		tooManyEntities.Entities = append(tooManyEntities.Entities, "sessions"+strings.Repeat("x", len(tooManyEntities.Entities)))
	}
	if err := tooManyEntities.Validate(); err == nil {
		t.Errorf("accepted %d entities, want at most %d", len(tooManyEntities.Entities), maxWidgetEntities)
	}
}

func TestAskAIWidgetMarshalRoundTrip(t *testing.T) {
	config := AskAIWidgetConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://console.example.com"},
		Entities:       []string{"sessions", "audit_events"},
		Greeting:       "Ask about your account",
		Placeholder:    "When did I last log in?",
	}

	encoded, err := MarshalAskAIWidget(config)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	decoded, err := UnmarshalAskAIWidget(encoded)
	if err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	if len(decoded.Entities) != 2 || decoded.Entities[0] != "sessions" {
		t.Errorf("entities = %v, want them back in order", decoded.Entities)
	}
	if decoded.Greeting != config.Greeting || decoded.Placeholder != config.Placeholder {
		t.Errorf("copy did not survive the round trip: %+v", decoded)
	}
}

func TestUnmarshalAskAIWidgetRefusesGarbage(t *testing.T) {
	if _, err := UnmarshalAskAIWidget([]byte("not json")); err == nil {
		t.Error("garbage was accepted as a stored configuration")
	}
}
