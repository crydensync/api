// Package settings stores the runtime configuration an operator changes
// through a settings screen, as opposed to the environment variables
// everything else in this repo is configured by at startup.
//
// What lives here is exactly the configuration cryden cannot own, because
// cryden has no settings concept at all: ai.LLMProvider and
// ai.QueryableStore are Go interfaces a host implements in code, so the
// credential behind each one is the host's to store. The table is
// migrations/013_settings.up.sql.
//
// The one rule this package exists to make unavoidable: **a credential
// never reaches the store as plaintext.** The store below deals in opaque
// bytes and knows nothing about what they mean; encryption happens in
// Secrets, which is the only thing a handler is given. A caller who
// reaches for the Store directly is writing ciphertext-shaped bytes or
// nothing, because the Store has no other interface to offer — see the
// migration's own comment on why the column is BYTEA.
package settings

import (
	"context"
	"errors"
)

// The names this package stores under. Constants rather than string
// literals at each call site, so a typo is a compile error rather than a
// second, silently-empty setting nobody reads.
const (
	// KeyLLMProvider is the provider backing ai.LLMProvider: which model,
	// and the API key to reach it with.
	KeyLLMProvider = "llm_provider"
	// KeyDatabaseProvider is the connection ai.QueryableStore runs
	// against. It MUST be a read-only role — see
	// httpapi/database_provider_handlers.go for the check that enforces
	// it rather than trusting the form.
	KeyDatabaseProvider = "database_provider"
	// KeyAskAIWidget is the embed and scope configuration for the
	// end-user ask-ai widget. Contains no credential: it is snippets and
	// limits a console renders, so it is the one key here that is not
	// secret.
	KeyAskAIWidget = "ask_ai_widget"
)

// ErrNotFound means nothing is stored under that key yet. Reported
// rather than returning empty bytes, because "never configured" and
// "configured as empty" are different answers and an endpoint that
// conflates them cannot tell an operator which one they are looking at.
var ErrNotFound = errors.New("settings: no such setting")

// Store is the persistence. It deals in opaque bytes on purpose: nothing
// above it can store a readable credential through this interface without
// having encrypted it first, because this interface has no way to know
// the difference and no helper that would hide the step.
//
// Two implementations, the same reason every other store in this repo has
// two: the handlers have to be testable without a database.
type Store interface {
	// Get returns the stored bytes for key, or ErrNotFound. The returned
	// slice is a copy, so a caller mutating it does not reach into the
	// store's own memory.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put creates or replaces key. One statement, so two operators
	// saving at the same moment cannot lose one of the writes.
	Put(ctx context.Context, key string, value []byte) error

	// Delete removes key, or returns ErrNotFound. Deleting an absent
	// setting is reported rather than ignored, so a console that cleared
	// the wrong row says so instead of showing success.
	Delete(ctx context.Context, key string) error

	// Keys lists every stored key, sorted. Names only — never values,
	// which is what makes it safe to answer a diagnostic question with.
	Keys(ctx context.Context) ([]string, error)
}
