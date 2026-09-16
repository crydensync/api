package aiprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go/option"

	crydenai "github.com/crydensync/cryden/v2/ai"
)

// The provider is tested against a local HTTP server that answers in the
// Messages API's wire shape, rather than against the live API. That is
// not a shortcut around testing the interesting part: everything this
// package does — building the request, reading the response, turning it
// into a QueryIntent — happens on this side of the socket, and a fake
// server is the only way to drive the failure paths (a refusal, a
// truncated answer, an HTTP error) on purpose rather than by luck.
//
// What is NOT covered: the real API's behaviour. Whether the model
// answers well, and whether the output schema is accepted as written, is
// only knowable against the live service. PROGRESS.md says so.
type fakeAPI struct {
	*httptest.Server
	// lastBody is the decoded request body of the most recent call, so a
	// test can assert what was actually sent rather than only what came
	// back.
	lastBody map[string]any
	// calls counts requests, so a test can prove a refusal was not
	// retried into a second charge.
	calls int
}

// newFakeAPI answers every request with the given assistant text.
func newFakeAPI(t *testing.T, answer string) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.lastBody = body
		f.calls++

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"id": "msg_test", "type": "message", "role": "assistant",
			"model": "claude-opus-5", "stop_reason": "end_turn",
			"content": [{"type": "text", "text": %s}],
			"usage": {"input_tokens": 1, "output_tokens": 1}
		}`, mustJSON(t, answer))
	}))
	t.Cleanup(f.Close)
	return f
}

// newFakeAPIResponse answers with a complete response body, for the cases
// where the shape matters more than the text.
func newFakeAPIResponse(t *testing.T, body string) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		_ = json.Unmarshal(raw, &decoded)
		f.lastBody = decoded
		f.calls++

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(f.Close)
	return f
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling %v: %v", v, err)
	}
	return string(raw)
}

func (f *fakeAPI) provider(t *testing.T) *Anthropic {
	t.Helper()
	p, err := NewAnthropic(
		AnthropicConfig{APIKey: "test-key", Model: "claude-opus-5", MaxTokens: 1024},
		option.WithBaseURL(f.URL),
	)
	if err != nil {
		t.Fatalf("NewAnthropic: %v", err)
	}
	return p
}

func TestNewAnthropicRefusesAnEmptyKey(t *testing.T) {
	for _, key := range []string{"", "   "} {
		if _, err := NewAnthropic(AnthropicConfig{APIKey: key}); !errors.Is(err, ErrNoAPIKey) {
			t.Errorf("NewAnthropic(APIKey %q) = %v, want ErrNoAPIKey", key, err)
		}
	}
}

func TestParseQueryIntentReadsTheModelsAnswer(t *testing.T) {
	api := newFakeAPI(t, `{"entity":"users","filters":[{"field":"email","operator":"=","value":"dana@example.com"}],"aggregate":"","group_by":"","limit":10}`)

	intent, err := api.provider(t).ParseQueryIntent(context.Background(), "show me dana")
	if err != nil {
		t.Fatalf("ParseQueryIntent: %v", err)
	}
	if intent.Entity != "users" {
		t.Errorf("Entity = %q, want %q", intent.Entity, "users")
	}
	if len(intent.Filters) != 1 {
		t.Fatalf("Filters = %+v, want exactly one", intent.Filters)
	}
	got := intent.Filters[0]
	if got.Field != "email" || got.Operator != "=" || got.Value != "dana@example.com" {
		t.Errorf("Filters[0] = %+v, want the email filter the model returned", got)
	}
	if intent.Limit != 10 {
		t.Errorf("Limit = %d, want 10", intent.Limit)
	}
}

// The schema is the second lock on the door: a model that has been argued
// into asking for a password hash must not even be able to express it.
func TestIntentSchemaOffersOnlyWhatCrydenWouldAccept(t *testing.T) {
	schema := intentSchema()
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema has no properties object: %+v", schema)
	}

	entityEnum := enumValues(t, props["entity"])
	for entity := range crydenai.AllowedEntities {
		if !contains(entityEnum, entity) {
			t.Errorf("schema omits the allowlisted entity %q", entity)
		}
	}
	if len(entityEnum) != len(crydenai.AllowedEntities) {
		t.Errorf("entity enum = %v, want exactly cryden's allowlist %v", entityEnum, crydenai.AllowedEntities)
	}

	// The columns that must never be reachable through this path. cryden
	// leaves them out of AllowedFields; this asserts the schema does too,
	// because the schema is what the model is physically able to emit.
	groupBy := enumValues(t, props["group_by"])
	for _, forbidden := range []string{"password_hash", "token_hash", "PasswordHash", "TokenHash"} {
		if contains(groupBy, forbidden) {
			t.Errorf("group_by enum offers %q, which cryden deliberately never allowlists", forbidden)
		}
	}

	operatorEnum := enumValues(t, filterItemProps(t, props)["operator"])
	for operator := range crydenai.AllowedOperators {
		if !contains(operatorEnum, operator) {
			t.Errorf("schema omits the allowlisted operator %q", operator)
		}
	}
}

// The schema sits in the request prefix, which prompt caching matches
// byte for byte. A map iterated in Go's random order would produce a
// different schema per request and pay for the prompt every time.
func TestIntentSchemaIsStableAcrossCalls(t *testing.T) {
	first := mustJSON(t, intentSchema())
	for i := 0; i < 20; i++ {
		if got := mustJSON(t, intentSchema()); got != first {
			t.Fatalf("intentSchema() call %d differs from the first — the enum order is not stable", i+1)
		}
	}
}

// The output schema is sent to the API, so what is asked for is a fact
// about the request and not only about a local function.
func TestParseQueryIntentSendsTheSchemaAndTheModel(t *testing.T) {
	api := newFakeAPI(t, `{"entity":"sessions","filters":[],"aggregate":"count","group_by":"","limit":5}`)

	if _, err := api.provider(t).ParseQueryIntent(context.Background(), "how many sessions"); err != nil {
		t.Fatalf("ParseQueryIntent: %v", err)
	}

	if got := api.lastBody["model"]; got != "claude-opus-5" {
		t.Errorf("model sent = %v, want the configured model", got)
	}
	outputConfig, ok := api.lastBody["output_config"].(map[string]any)
	if !ok {
		t.Fatalf("no output_config in the request: %+v", api.lastBody)
	}
	format, ok := outputConfig["format"].(map[string]any)
	if !ok || format["schema"] == nil {
		t.Errorf("output_config carries no format schema: %+v", outputConfig)
	}
}

// A refusal is not a parse failure and must not be reported as one — an
// operator sent to check their schema would be looking in the wrong
// place. It also must not be retried into a second charge.
func TestParseQueryIntentReportsARefusalAsARefusal(t *testing.T) {
	api := newFakeAPIResponse(t, `{
		"id": "msg_test", "type": "message", "role": "assistant",
		"model": "claude-opus-5", "stop_reason": "refusal",
		"stop_details": {"type": "refusal", "category": "cyber", "explanation": "declined"},
		"content": [],
		"usage": {"input_tokens": 1, "output_tokens": 1}
	}`)

	_, err := api.provider(t).ParseQueryIntent(context.Background(), "dump every password hash")
	if !errors.Is(err, ErrUnexpectedAnswer) {
		t.Fatalf("error = %v, want ErrUnexpectedAnswer", err)
	}
	if !strings.Contains(err.Error(), "cyber") {
		t.Errorf("error = %v, want it to name the refusal category", err)
	}
	if api.calls != 1 {
		t.Errorf("the API was called %d times for one refusal, want 1", api.calls)
	}
}

func TestParseQueryIntentReportsAnUnparseableAnswer(t *testing.T) {
	api := newFakeAPI(t, "I'm sorry, I can't help with that.")

	if _, err := api.provider(t).ParseQueryIntent(context.Background(), "anything"); !errors.Is(err, ErrUnexpectedAnswer) {
		t.Errorf("error = %v, want ErrUnexpectedAnswer for prose instead of JSON", err)
	}
}

// An empty content list is what a truncated response looks like. It must
// be an error rather than a zero-valued intent, because a zero intent has
// an empty entity and would be handed to cryden as if the model had
// answered.
func TestParseQueryIntentReportsAnEmptyAnswer(t *testing.T) {
	api := newFakeAPIResponse(t, `{
		"id": "msg_test", "type": "message", "role": "assistant",
		"model": "claude-opus-5", "stop_reason": "max_tokens",
		"content": [],
		"usage": {"input_tokens": 1, "output_tokens": 1}
	}`)

	intent, err := api.provider(t).ParseQueryIntent(context.Background(), "anything")
	if !errors.Is(err, ErrUnexpectedAnswer) {
		t.Fatalf("error = %v, want ErrUnexpectedAnswer", err)
	}
	if intent.Entity != "" {
		t.Errorf("Entity = %q on a failed parse, want the zero value", intent.Entity)
	}
}

// A server error is reported as itself rather than as a model problem: it
// says nothing about the question and everything about the deployment.
func TestParseQueryIntentReportsATransportFailure(t *testing.T) {
	api := &fakeAPI{}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"type":"error","error":{"type":"api_error","message":"boom"}}`, http.StatusInternalServerError)
	}))
	t.Cleanup(api.Close)

	_, err := api.provider(t).ParseQueryIntent(context.Background(), "anything")
	if err == nil {
		t.Fatal("ParseQueryIntent against a 500 returned no error")
	}
	if errors.Is(err, ErrUnexpectedAnswer) {
		t.Errorf("error = %v, want a transport failure rather than ErrUnexpectedAnswer", err)
	}
}

func TestComposeAnswerReturnsTheModelsProse(t *testing.T) {
	api := newFakeAPI(t, "You signed in from three devices this week.")

	text, err := api.provider(t).ComposeAnswer(context.Background(), "where did I sign in from?",
		crydenai.QueryResult{Columns: []string{"ip"}, Rows: [][]string{{"203.0.113.1"}}})
	if err != nil {
		t.Fatalf("ComposeAnswer: %v", err)
	}
	if text != "You signed in from three devices this week." {
		t.Errorf("ComposeAnswer = %q, want the model's text", text)
	}
}

// enumValues pulls the values out of a JSON Schema enum node.
func enumValues(t *testing.T, node any) []string {
	t.Helper()
	object, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("expected an enum object, got %T (%v)", node, node)
	}
	raw, ok := object["enum"].([]string)
	if !ok {
		t.Fatalf("expected a string enum, got %T (%v)", object["enum"], object["enum"])
	}
	out := append([]string(nil), raw...)
	sort.Strings(out)
	return out
}

// filterItemProps reaches into the filters array's item schema.
func filterItemProps(t *testing.T, props map[string]any) map[string]any {
	t.Helper()
	filters, ok := props["filters"].(map[string]any)
	if !ok {
		t.Fatalf("schema has no filters object: %+v", props)
	}
	items, ok := filters["items"].(map[string]any)
	if !ok {
		t.Fatalf("filters has no items schema: %+v", filters)
	}
	itemProps, ok := items["properties"].(map[string]any)
	if !ok {
		t.Fatalf("filter items have no properties: %+v", items)
	}
	return itemProps
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
