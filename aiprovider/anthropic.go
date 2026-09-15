// Package aiprovider holds this repo's implementations of the interfaces
// cryden's ai and widget packages define.
//
// cryden ships none on purpose: ai.LLMProvider and ai.QueryableStore are
// shaped so a host brings its own vendor and its own database connection
// (see ai/types.go — "Ships zero implementations here — the consumer
// brings its own provider and API key, the same pattern as
// notify.EmailSender and logger.Logger"). This is that consumer.
//
// Nothing in this package is the safety boundary. cryden validates every
// QueryIntent against its allowlist before any query runs (ai.validateIntent)
// and widget.Ask force-scopes every intent to the calling user before
// that. What happens here is narrower and easier to state: turn a
// question into a candidate intent, and run an already-validated intent
// against a connection that has been checked to be read-only.
package aiprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	crydenai "github.com/crydensync/cryden/v2/ai"
)

// ErrNoAPIKey is returned when the provider was built without a
// credential. Constructing one anyway and failing at the first call would
// move the failure from startup to the middle of an admin's question.
var ErrNoAPIKey = errors.New("aiprovider: an API key is required")

// ErrUnexpectedAnswer means the model returned something that is not a
// QueryIntent. It is a real possibility even with the output schema
// enforced — a refusal, a truncated response — and it is reported as its
// own error rather than as a validation failure, because "the model did
// not answer the question" and "the model answered with something unsafe"
// call for different words in front of an operator.
var ErrUnexpectedAnswer = errors.New("aiprovider: the model did not return a query intent")

// Anthropic implements cryden's ai.LLMProvider (and widget.Composer)
// against the Anthropic Messages API.
//
// It is deliberately thin. The interesting work — deciding whether a
// model's answer is safe to run — belongs to cryden, and duplicating any
// of it here would create a second place for the rules to drift.
type Anthropic struct {
	client anthropic.Client
	model  string
	// maxTokens bounds one response. The answer is a small JSON object,
	// so this is a ceiling on cost rather than on usefulness.
	maxTokens int
}

// AnthropicConfig is what the settings table stores, unpacked into what
// this constructor needs.
type AnthropicConfig struct {
	APIKey    string
	Model     string
	MaxTokens int
}

// NewAnthropic builds a provider from a stored configuration.
func NewAnthropic(cfg AnthropicConfig, opts ...option.RequestOption) (*Anthropic, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, ErrNoAPIKey
	}
	opts = append(opts, option.WithAPIKey(cfg.APIKey))

	return &Anthropic{
		client:    anthropic.NewClient(opts...),
		model:     cfg.Model,
		maxTokens: cfg.MaxTokens,
	}, nil
}

var (
	_ crydenai.LLMProvider = (*Anthropic)(nil)
)

// intentSchema is the JSON schema the model's answer is constrained to.
//
// This is the second lock on a door cryden already bolts. The enums below
// are built from cryden's own allowlists rather than restated, so a model
// that has been talked into asking for the password hash cannot even
// express it: the field is not in the schema, and the API enforces the
// schema, not the prompt. cryden would reject the intent anyway — this
// just means the rejection almost never has to happen.
//
// Built from cryden's maps rather than hardcoded on purpose. If the
// engine allowlists a new field tomorrow, this schema follows it with no
// edit here; if the engine ever *removes* one, a hardcoded copy would
// keep offering it.
func intentSchema() map[string]any {
	entities := sortedKeys(crydenai.AllowedEntities)

	// group_by is a single string field, and the schema is flat — it has
	// no way to say "this enum depends on the entity you chose". So the
	// enum it offers is the union across every entity's allowed fields,
	// which is the honest superset: cryden checks group_by against the
	// chosen entity's own list and rejects a mismatch. Narrowing here
	// instead would mean duplicating cryden's per-entity rule in a form
	// JSON Schema cannot express, and a stale copy of it would silently
	// refuse a field the engine would have accepted.
	groupable := map[string]bool{}
	for _, fields := range crydenai.AllowedFields {
		for field := range fields {
			groupable[field] = true
		}
	}

	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"entity": enumOf(entities),
			"filters": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"field":    map[string]any{"type": "string"},
						"operator": enumOf(sortedKeys(crydenai.AllowedOperators)),
						"value":    map[string]any{"type": "string"},
					},
					"required":             []string{"field", "operator", "value"},
					"additionalProperties": false,
				},
			},
			"aggregate": enumOf([]string{"", "count", "group_by"}),
			"group_by":  enumOf(sortedKeys(groupable)),
			"limit":     map[string]any{"type": "integer"},
		},
		"required":             []string{"entity", "filters", "aggregate", "limit"},
		"additionalProperties": false,
	}
}

// systemPrompt is the whole of this repo's prompt. It is short because
// the schema does the constraining: the prompt's job is to say what the
// fields mean, not to enumerate what is allowed, and a prompt that listed
// the allowlist would be one more copy of it to keep in sync.
const systemPrompt = `You translate an administrator's question about their user database into a structured query intent.

The intent names one entity, any filters narrowing it, and how to present the result. Use "count" when the question asks how many, "group_by" when it asks for a breakdown, and the empty aggregate when it asks for the rows themselves.

Only the fields the schema offers exist. If the question cannot be expressed with them, choose the closest entity and omit the filters you cannot express rather than inventing a field name.`

// ParseQueryIntent asks the model for a QueryIntent. The returned intent
// is unvalidated: cryden's ai.ExecuteIntent checks it against the
// allowlist before anything runs, and this function must not be assumed
// to have done so.
func (p *Anthropic) ParseQueryIntent(ctx context.Context, naturalLanguage string) (crydenai.QueryIntent, error) {
	response, err := p.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(p.model),
		MaxTokens: int64(p.maxTokens),
		System: []anthropic.TextBlockParam{{
			Text: systemPrompt,
			// The prompt and the schema are fixed for the life of the
			// process, so every request after the first reads this from
			// cache instead of paying for it again.
			CacheControl: anthropic.NewCacheControlEphemeralParam(),
		}},
		OutputConfig: anthropic.OutputConfigParam{
			Format: anthropic.JSONOutputFormatParam{Schema: intentSchema()},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(naturalLanguage)),
		},
	})
	if err != nil {
		return crydenai.QueryIntent{}, fmt.Errorf("aiprovider: asking the model: %w", err)
	}

	// Checked before the content is read, because a refusal carries no
	// usable text and reading it first would report a refusal as a parse
	// failure — sending an operator to look at their schema when the
	// model simply declined the question.
	if response.StopReason == anthropic.StopReasonRefusal {
		return crydenai.QueryIntent{}, fmt.Errorf("%w: the model declined to answer (%s)",
			ErrUnexpectedAnswer, response.StopDetails.Category)
	}

	text := firstText(response.Content)
	if text == "" {
		return crydenai.QueryIntent{}, fmt.Errorf("%w: the response carried no text (stop reason %q)",
			ErrUnexpectedAnswer, response.StopReason)
	}

	var payload queryIntentPayload
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		return crydenai.QueryIntent{}, fmt.Errorf("%w: %v", ErrUnexpectedAnswer, err)
	}

	intent := crydenai.QueryIntent{
		Entity:    payload.Entity,
		Aggregate: payload.Aggregate,
		GroupBy:   payload.GroupBy,
		Limit:     payload.Limit,
	}
	for _, f := range payload.Filters {
		intent.Filters = append(intent.Filters, crydenai.QueryFilter{
			Field:    f.Field,
			Operator: f.Operator,
			Value:    f.Value,
		})
	}
	return intent, nil
}

// queryIntentPayload mirrors cryden's ai.QueryIntent as JSON. A separate
// type rather than unmarshalling into ai.QueryIntent directly, because
// the wire shape and the engine's own struct are allowed to differ —
// QueryFilter is a struct here and an element of a slice there — and
// because a named type is where the JSON tags can be documented.
type queryIntentPayload struct {
	Entity    string               `json:"entity"`
	Filters   []queryFilterPayload `json:"filters"`
	Aggregate string               `json:"aggregate"`
	GroupBy   string               `json:"group_by"`
	Limit     int                  `json:"limit"`
}

type queryFilterPayload struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// ComposeAnswer implements widget.Composer: it turns an already-validated,
// already-owner-scoped result into a sentence for an end user.
//
// The result it is given has been scoped to one identity by cryden's
// widget.Ask before it arrives — this function never sees another user's
// rows, and does not need to know that scoping exists. That is why it can
// be a plain presentation call with nothing to check.
func (p *Anthropic) ComposeAnswer(ctx context.Context, question string, result crydenai.QueryResult) (string, error) {
	response, err := p.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(p.model),
		MaxTokens: int64(p.maxTokens),
		System: []anthropic.TextBlockParam{{
			Text:         "You answer a user's question using only the rows provided. If the rows do not answer it, say so plainly. Never mention SQL, tables or column names.",
			CacheControl: anthropic.NewCacheControlEphemeralParam(),
		}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(
				anthropic.NewTextBlock("Question: "+question),
				anthropic.NewTextBlock("Rows:\n"+renderRows(result)),
			),
		},
	})
	if err != nil {
		return "", fmt.Errorf("aiprovider: composing an answer: %w", err)
	}
	if response.StopReason == anthropic.StopReasonRefusal {
		return "", fmt.Errorf("%w: the model declined to answer (%s)",
			ErrUnexpectedAnswer, response.StopDetails.Category)
	}
	return firstText(response.Content), nil
}

// renderRows is a compact, positional rendering of a QueryResult for the
// composer. Headers once, then one line per row — the model is reading
// this, so a repeated header would be noise it might mistake for data.
func renderRows(result crydenai.QueryResult) string {
	var b strings.Builder
	b.WriteString(strings.Join(result.Columns, ", "))
	for _, row := range result.Rows {
		b.WriteString("\n")
		b.WriteString(strings.Join(row, ", "))
	}
	return b.String()
}

// firstText returns the first text block's content, or "". A response can
// carry thinking blocks before the text one, so this walks rather than
// indexing.
func firstText(blocks []anthropic.ContentBlockUnion) string {
	for _, block := range blocks {
		if text, ok := block.AsAny().(anthropic.TextBlock); ok {
			return text.Text
		}
	}
	return ""
}
