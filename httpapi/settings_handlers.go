package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/crydensync/api/aiprovider"
	"github.com/crydensync/api/settings"
)

// The errors these handlers add to the map. Declared here rather than in
// errors.go because they belong to this surface and mapError reaches them
// through errors.Is like everything else — see writeErr.
// errSettingsNotConfigured means SETTINGS_ENCRYPTION_KEY is unset, so
// there is nowhere to put a credential. A wiring fact, not a fault: 404
// not_configured, the same shape every unconfigured feature in this api
// uses. Declared here rather than in errors.go because it belongs to this
// surface, and mapError reaches it through errors.Is like everything else
// — see writeErr.
var errSettingsNotConfigured = errors.New("the AI settings endpoints are not configured on this deployment")

// SettingsHandlers serves the runtime configuration behind the AI-assisted
// admin features: which LLM provider to call, and which read-only database
// the ask-ai widget queries.
//
// This is the one admin surface in this repo that WRITES, and that is not
// a hole in the read-only rule — it is the rule's other half. CLAUDE.md's
// constraint is that the AI *tools* must stay read-only, and the decision
// recorded in NEXT.md is pre-fill, never auto-apply: a tuning suggestion
// pre-fills a settings field and a human saves it. These endpoints are
// that save. They store what an operator typed into the form; they do not
// accept a suggestion from any AI feature, and no AI feature can reach
// them — the tuning advisor's handler is built with no reference to this
// one at all.
//
// Every write here is also gated on RequireAdmin in the router, and every
// stored credential is sealed by settings.Secrets before it reaches the
// table. Nothing on this surface ever returns a credential back.
type SettingsHandlers struct {
	Secrets *settings.Secrets
}

// llmProviderDTO is the PUT body. Separate from settings.LLMProviderConfig
// rather than reusing it, so the wire shape and the stored shape can
// differ — and so a future field on the stored config is not silently
// accepted from a request that predates it.
type llmProviderDTO struct {
	Kind      string `json:"kind"`
	Model     string `json:"model"`
	APIKey    string `json:"api_key"`
	MaxTokens int    `json:"max_tokens"`
}

// LLMProvider returns the stored provider with its credential removed.
//
// The API key is never in the response in any form — not masked, not
// truncated to its last four characters. A console does not need it: it
// renders "saved" from api_key_set. Anything more would put the
// credential in a browser's memory and a devtools panel, which is exactly
// what encrypting it at rest was meant to avoid.
func (h *SettingsHandlers) LLMProvider(w http.ResponseWriter, r *http.Request) {
	if !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}

	plaintext, err := h.Secrets.Get(r.Context(), settings.KeyLLMProvider)
	if errors.Is(err, settings.ErrNotFound) {
		// Not an error: "nothing configured yet" is an answer a settings
		// screen needs, and a 404 would make a console render a broken
		// panel rather than an empty form.
		writeData(w, http.StatusOK, settings.RedactedLLMProvider{})
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}

	stored, err := settings.UnmarshalLLMProvider(plaintext)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, stored.Redacted())
}

// PutLLMProvider stores a provider configuration.
//
// The credential is required on every write rather than being optional
// with "blank means keep the existing one". That convention is the usual
// one and it is the wrong one here: an omitted field and a deliberately
// cleared one would be the same request, and the failure mode of getting
// it wrong is a settings form that appears to save an unchanged key while
// silently storing an empty one. Requiring it means the console always
// sends what it means.
func (h *SettingsHandlers) PutLLMProvider(w http.ResponseWriter, r *http.Request) {
	if !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}

	var dto llmProviderDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}

	// An omitted max_tokens is the common case — a console that does not
	// ask, or asks with the field left empty — so it defaults here rather
	// than being a validation failure. Any other value is passed through
	// to Validate, which is the one place the bounds live.
	if dto.MaxTokens == 0 {
		dto.MaxTokens = settings.DefaultLLMMaxTokens
	}

	config := settings.LLMProviderConfig{
		Kind:      dto.Kind,
		Model:     dto.Model,
		APIKey:    dto.APIKey,
		MaxTokens: dto.MaxTokens,
	}
	if err := config.Validate(); err != nil {
		// The engine's message names the offending field and bound, which
		// is what the operator needs to fix the form. Unlike an
		// authentication error there is nothing secret in it, and the
		// caller is already an operator.
		writeErr(w, err)
		return
	}

	plaintext, err := settings.MarshalLLMProvider(config)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Secrets.Put(r.Context(), settings.KeyLLMProvider, plaintext); err != nil {
		writeErr(w, err)
		return
	}

	writeData(w, http.StatusOK, config.Redacted())
}

// DeleteLLMProvider clears the stored provider, which switches the
// AI-assisted query features off until one is configured again.
//
// No key is needed to do this — see settings.Secrets.Delete — which is
// what makes it the way out for a deployment that has lost
// SETTINGS_ENCRYPTION_KEY and can no longer read what it stored.
func (h *SettingsHandlers) DeleteLLMProvider(w http.ResponseWriter, r *http.Request) {
	if !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	if err := h.Secrets.Delete(r.Context(), settings.KeyLLMProvider); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, settings.RedactedLLMProvider{})
}

// databaseProviderDTO is the PUT body for the read-only database.
type databaseProviderDTO struct {
	Label   string `json:"label"`
	DSN     string `json:"dsn"`
	MaxRows int    `json:"max_rows"`
}

// DatabaseProvider returns the stored connection with its credential
// removed. The host and database come back so an operator can tell which
// one is configured; the user and password never do.
func (h *SettingsHandlers) DatabaseProvider(w http.ResponseWriter, r *http.Request) {
	if !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}

	plaintext, err := h.Secrets.Get(r.Context(), settings.KeyDatabaseProvider)
	if errors.Is(err, settings.ErrNotFound) {
		writeData(w, http.StatusOK, settings.RedactedDatabaseProvider{})
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}

	stored, err := settings.UnmarshalDatabaseProvider(plaintext)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, stored.Redacted())
}

// PutDatabaseProvider stores a connection, but only after checking that
// its role genuinely cannot write.
//
// This is the check NEXT.md calls for by name and the one cryden's own
// ai.QueryableStore interface demands: "the credential boundary, not just
// the allowlist, is the real safety guarantee." The allowlist in
// cryden's ai package is the first line; a role that cannot INSERT is
// what still holds when the first line has a bug.
//
// So the order matters and is the whole design of this handler:
//
//  1. Check the shape, which is cheap and local.
//  2. Connect with the supplied credentials and TRY TO WRITE — see
//     aiprovider.CheckReadOnly. Nothing is stored until the server has
//     refused a write on that connection, with those credentials,
//     against that database.
//  3. Only then store it.
//
// A "read-only?" checkbox in the console would be a claim about a
// database made by whoever ticked it. This is the database answering for
// itself. It cannot be done on the client side either — a browser cannot
// open a Postgres connection, and if it could, its answer would be no
// more trustworthy than the form.
//
// The cost is that this endpoint is slower than the others: it opens a
// connection and runs two statements before it answers. That is the price
// of the guarantee, and it is paid once per save rather than per query.
func (h *SettingsHandlers) PutDatabaseProvider(w http.ResponseWriter, r *http.Request) {
	if !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}

	var dto databaseProviderDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}
	if dto.MaxRows == 0 {
		dto.MaxRows = settings.DefaultDatabaseMaxRows
	}

	config := settings.DatabaseProviderConfig{
		Label:   dto.Label,
		DSN:     dto.DSN,
		MaxRows: dto.MaxRows,
	}
	if err := config.Validate(); err != nil {
		writeErr(w, err)
		return
	}

	// The read-only check, on a live connection, before anything is
	// stored. Its own timeout bounds it — see readOnlyProbeTimeout — so a
	// host that black-holes the connection answers rather than hanging
	// the request.
	if err := aiprovider.CheckReadOnly(r.Context(), config.DSN); err != nil {
		writeErr(w, err)
		return
	}

	plaintext, err := settings.MarshalDatabaseProvider(config)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Secrets.Put(r.Context(), settings.KeyDatabaseProvider, plaintext); err != nil {
		writeErr(w, err)
		return
	}

	writeData(w, http.StatusOK, config.Redacted())
}

// DeleteDatabaseProvider clears the stored connection. Like the LLM
// provider's, it needs no encryption key.
func (h *SettingsHandlers) DeleteDatabaseProvider(w http.ResponseWriter, r *http.Request) {
	if !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	if err := h.Secrets.Delete(r.Context(), settings.KeyDatabaseProvider); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, settings.RedactedDatabaseProvider{})
}

// AskAIWidget returns the stored widget configuration.
//
// Unlike the other two GETs there is no redaction here, because there is
// nothing to redact: origins, entity names and copy are what the console
// shows an operator anyway. See settings.AskAIWidgetConfig for why that
// difference is real rather than an oversight.
//
// There is also no embed snippet in the response. The snippet is markup
// the csax+ console renders into its own pages, and this package has no
// opinion on what another repo's pages should contain. An earlier
// version of this comment gave a different reason — that the URL in a
// snippet would name an endpoint this repo did not serve yet — and that
// one has expired: POST /v1/ask-ai serves the widget as of spec 1.7.
// What this endpoint owes the console is the configuration the snippet
// is built from, which is exactly what it returns; the path it posts to
// is in the spec with every other path, rather than returned as a string
// from here.
func (h *SettingsHandlers) AskAIWidget(w http.ResponseWriter, r *http.Request) {
	if !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}

	plaintext, err := h.Secrets.Get(r.Context(), settings.KeyAskAIWidget)
	if errors.Is(err, settings.ErrNotFound) {
		// A disabled widget is the honest default for "nothing has been
		// configured": the zero value is Enabled=false, so a console that
		// renders it shows the feature as off rather than showing a form
		// that looks saved.
		writeData(w, http.StatusOK, settings.AskAIWidgetConfig{})
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}

	stored, err := settings.UnmarshalAskAIWidget(plaintext)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, stored)
}

// PutAskAIWidget stores the widget configuration.
//
// This is the endpoint the config-tuning advisor's suggestions pre-fill,
// in the sense NEXT.md records: a suggestion about, say, scope ends up as
// a value in this form, and this handler is what writes it once a human
// has read it and pressed save. Nothing calls it automatically, and no
// AI-assisted handler in this repo holds a reference to it.
func (h *SettingsHandlers) PutAskAIWidget(w http.ResponseWriter, r *http.Request) {
	if !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}

	var config settings.AskAIWidgetConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		writeBadRequest(w, "malformed request body")
		return
	}
	if err := config.Validate(); err != nil {
		writeErr(w, err)
		return
	}

	plaintext, err := settings.MarshalAskAIWidget(config)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Secrets.Put(r.Context(), settings.KeyAskAIWidget, plaintext); err != nil {
		writeErr(w, err)
		return
	}

	writeData(w, http.StatusOK, config)
}

// DeleteAskAIWidget clears the stored configuration, which leaves the
// widget disabled — the zero value — until it is configured again.
func (h *SettingsHandlers) DeleteAskAIWidget(w http.ResponseWriter, r *http.Request) {
	if !h.Secrets.Configured() {
		writeErr(w, errSettingsNotConfigured)
		return
	}
	if err := h.Secrets.Delete(r.Context(), settings.KeyAskAIWidget); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, settings.AskAIWidgetConfig{})
}
