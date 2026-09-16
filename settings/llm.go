package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// LLMProviderKindAnthropic is the one provider this repo can construct a
// live ai.LLMProvider for. A kind rather than a hardcoded shape, because
// the stored config has to say which client to build and a console needs
// something to put in a dropdown — but the list is deliberately short:
// this repo ships an implementation for what it names and nothing else,
// so "openai" here would be a setting that saves and then does nothing.
const LLMProviderKindAnthropic = "anthropic"

// DefaultLLMModel is what an operator gets if they configure a provider
// without naming a model. Claude Opus 5 is the current default for this
// kind of work.
const DefaultLLMModel = "claude-opus-5"

// The bounds on MaxTokens. The floor is not zero: a provider asked for
// zero output tokens would answer with an empty response that this repo
// would then fail to parse, which reads as a broken provider rather than
// as a bad setting. The ceiling keeps one AI query from consuming a
// month's budget in a single call.
const (
	MinLLMMaxTokens = 256
	MaxLLMMaxTokens = 8192
	// DefaultLLMMaxTokens is room for a QueryIntent plus the model's
	// reasoning about it. The output here is a small JSON object, not
	// prose, so this is generous rather than tight.
	DefaultLLMMaxTokens = 2048
)

// ErrInvalidLLMProvider means the supplied configuration cannot back a
// working provider. Returned instead of storing it, because a saved
// setting that fails at the first real use is worse than a refused save:
// the operator finds out from a user, not from the form.
var ErrInvalidLLMProvider = errors.New("settings: invalid LLM provider configuration")

// LLMProviderConfig is what a console reads and writes. It is the
// plaintext shape — it is marshalled to JSON, sealed, and only then
// handed to Secrets, so it exists in memory and inside the ciphertext and
// nowhere else.
type LLMProviderConfig struct {
	// Kind names which client to build. See LLMProviderKindAnthropic.
	Kind string `json:"kind"`
	// Model is the vendor's model id.
	Model string `json:"model"`
	// APIKey is the credential. Never returned by a read — see Redacted.
	APIKey string `json:"api_key"`
	// MaxTokens bounds one response.
	MaxTokens int `json:"max_tokens"`
}

// Validate checks a configuration that is about to be stored. The stored
// value is the one every later read has to work with, so this is the only
// place the rule can be enforced — a handler that trusted a form would be
// enforcing it in the wrong layer.
func (c LLMProviderConfig) Validate() error {
	if c.Kind != LLMProviderKindAnthropic {
		return fmt.Errorf("%w: unknown provider kind %q, this api can only build %q",
			ErrInvalidLLMProvider, c.Kind, LLMProviderKindAnthropic)
	}
	if strings.TrimSpace(c.Model) == "" {
		return fmt.Errorf("%w: model is required", ErrInvalidLLMProvider)
	}
	if strings.TrimSpace(c.APIKey) == "" {
		return fmt.Errorf("%w: api_key is required", ErrInvalidLLMProvider)
	}
	if c.MaxTokens < MinLLMMaxTokens || c.MaxTokens > MaxLLMMaxTokens {
		return fmt.Errorf("%w: max_tokens must be between %d and %d, got %d",
			ErrInvalidLLMProvider, MinLLMMaxTokens, MaxLLMMaxTokens, c.MaxTokens)
	}
	return nil
}

// Redacted returns the copy of this configuration that is safe to send to
// a console: everything except the credential, with a flag saying whether
// one is set.
//
// This is a method on the config rather than something each handler
// remembers to do, and that is the point. A response that carried the API
// key would put it in a browser's memory, in a devtools panel, in a
// screenshot of the settings screen — and the whole reason the key is
// encrypted at rest is that it is worth stealing.
func (c LLMProviderConfig) Redacted() RedactedLLMProvider {
	return RedactedLLMProvider{
		Kind:       c.Kind,
		Model:      c.Model,
		MaxTokens:  c.MaxTokens,
		APIKeySet:  c.APIKey != "",
		Configured: true,
	}
}

// RedactedLLMProvider is what GET returns. Separate from
// LLMProviderConfig rather than the same struct with an empty APIKey
// field, so a handler cannot accidentally serialise the credential by
// using the wrong type — the credential is not a field here at all.
type RedactedLLMProvider struct {
	Kind      string `json:"kind"`
	Model     string `json:"model"`
	MaxTokens int    `json:"max_tokens"`
	// APIKeySet says whether a credential is stored. Enough for a console
	// to render "••••••••  saved" versus "not set", and not enough to
	// reconstruct anything.
	APIKeySet bool `json:"api_key_set"`
	// Configured distinguishes a stored provider from the zero value this
	// struct has when nothing is stored. Both have empty strings, and a
	// console that cannot tell them apart shows a blank form where it
	// should show "not configured yet".
	Configured bool `json:"configured"`
}

// MarshalLLMProvider seals and encodes a configuration for storage.
//
// The seal-and-encode pair lives here rather than in the handler so that
// "JSON, then encrypted" has exactly one spelling: a second caller that
// encoded differently would produce rows the reader below cannot open.
func MarshalLLMProvider(c LLMProviderConfig) ([]byte, error) {
	return json.Marshal(c)
}

// UnmarshalLLMProvider decodes what MarshalLLMProvider produced. It
// receives plaintext, so it must only ever be handed the output of
// Secrets.Get.
func UnmarshalLLMProvider(plaintext []byte) (LLMProviderConfig, error) {
	var c LLMProviderConfig
	if err := json.Unmarshal(plaintext, &c); err != nil {
		return LLMProviderConfig{}, fmt.Errorf("settings: decoding the stored LLM provider: %w", err)
	}
	return c, nil
}
