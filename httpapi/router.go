package httpapi

import (
	"database/sql"
	"net/http"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store"

	"github.com/crydensync/api/anomalyreview"
	"github.com/crydensync/api/askai"
	"github.com/crydensync/api/config"
	"github.com/crydensync/api/digest"
	"github.com/crydensync/api/settings"
	"github.com/crydensync/api/shiplog"
	"github.com/crydensync/api/usermeta"
	"github.com/crydensync/api/webhook"
)

// Deps is everything the route table needs to build its handlers. It is a
// struct rather than a parameter list because the admin surface keeps
// growing: the hash-migration report alone needs stores the engine holds
// unexported, so they can only come from whoever constructed them
// (main.go). A struct also lets a test build a router with exactly the
// dependencies the endpoint under test needs and leave the rest nil.
//
// Every store here is the SAME instance main.go handed to cryden. Building
// a second one would be worse than wasteful — the hash-migration count and
// the engine's own writes would be reading different objects, and a
// repo-owned store the engine writes through would be invisible to the
// endpoint that reports on it.
type Deps struct {
	Engine *cryden.Engine

	// DB is used only by the health handler, which pings it. Nil is fine
	// for a router built without a database (tests); /v1/health then
	// reports the database as unconfigured rather than panicking.
	DB     *sql.DB
	Config config.Config

	// Audit and Users back GET /v1/admin/security/hash-migration — cryden
	// exposes no bulk way to inspect stored password hashes, so the
	// migration is measured from the audit events the engine already
	// records against the user total.
	Audit store.AuditStore
	Users store.UserStore

	// Sessions backs the live-session count on GET
	// /v1/admin/users/{userID}. The same instance the engine holds, so
	// the count describes the sessions the engine would revoke.
	Sessions store.SessionStore

	// Meta backs the per-user metadata endpoints. This repo's own table
	// and package — cryden's store.User has no metadata concept and will
	// not gain one (see usermeta's package doc).
	Meta usermeta.Store

	// Hooks backs the admin webhook delivery log. Nil unless WEBHOOK_URL is
	// set, because the log is only written by a running delivery worker —
	// there is nothing to report on in a deployment that dispatches no
	// webhooks, and the handler answers 404 rather than an empty list an
	// operator would read as "nothing has failed".
	Hooks webhook.Store

	// Shipped backs the admin shipped-events log — the redacted copy of
	// the engine's log records that the cloud sink was handed. Nil unless
	// CLOUD_LOGGING is set, for the same reason Hooks is: with the sink
	// off, nothing writes rows, and an empty list would be a lie about a
	// deployment that ships nothing.
	Shipped shiplog.Store

	// Digests backs GET /v1/admin/digest/history. Nil unless
	// DIGEST_INTERVAL_HOURS asked for a schedule: the table is only ever
	// written by the scheduler, so with no schedule there is no history to
	// read, and the handler answers 404 rather than an empty list an
	// operator would read as "nothing has ever happened".
	//
	// The on-demand GET /v1/admin/digest needs nothing from here — it
	// reads the engine's audit history and records nothing.
	Digests digest.Store

	// Settings backs the /v1/admin/settings/* endpoints: the LLM provider
	// and the read-only database behind the AI-assisted admin features.
	// Nil unless SETTINGS_ENCRYPTION_KEY is set — without a key there is
	// nowhere safe to put a credential, so those endpoints answer 404
	// not_configured rather than accepting one they would have to store in
	// the clear. See settings.Secrets.
	Settings *settings.Secrets

	// Reviews backs the flagged-event review queue. This repo's own table
	// (migrations/014) and package — cryden records that a login tripped
	// anomaly signals and has no concept of a person having read one, so
	// the judgement lives here rather than in the engine's audit history.
	// See anomalyreview's package doc.
	Reviews anomalyreview.Store

	// AskAI backs the ask-ai widget's serving endpoint. Unlike every other
	// AI-assisted dependency here it is not admin-scoped: it answers the
	// signed-in end user's questions about their own account. Nil unless
	// main.go built one; the handler then answers 404 rather than
	// panicking.
	AskAI *askai.Service
}

// NewRouter builds the full route table. Called once from main.go.
func NewRouter(d Deps) http.Handler {
	engine := d.Engine

	auth := &AuthHandlers{Engine: engine}
	sessions := &SessionHandlers{Engine: engine}
	account := &AccountHandlers{Engine: engine}
	email := &EmailHandlers{Engine: engine}
	health := &HealthHandler{DB: d.DB}
	oauth := &OAuthHandlers{Engine: engine, Config: d.Config}
	oauthHealth := NewOAuthHealthHandlers(oauth)
	totp := &TOTPHandlers{Engine: engine}
	passkeys := &PasskeyHandlers{Engine: engine}
	magicLink := &MagicLinkHandlers{Engine: engine}
	recovery := &RecoveryHandlers{Engine: engine}
	apiKeys := &APIKeyHandlers{Engine: engine}
	security := &SecurityHandlers{Audit: d.Audit, Users: d.Users, Config: d.Config}
	metadata := &MetadataHandlers{Users: d.Users, Meta: d.Meta}
	users := &UserHandlers{Engine: engine, Users: d.Users, Sessions: d.Sessions, Audit: d.Audit}
	hooks := &WebhookHandlers{Store: d.Hooks}
	logging := &LoggingHandlers{Store: d.Shipped}
	digests := &DigestHandlers{Engine: engine, Store: d.Digests}
	support := &SupportHandlers{Engine: engine}
	tuning := &TuningHandlers{Audit: d.Audit, Config: d.Config}
	aiSettings := &SettingsHandlers{Secrets: d.Settings}
	anomalies := &AnomalyHandlers{Audit: d.Audit, Reviews: d.Reviews}
	askAI := &WidgetHandlers{Service: d.AskAI}

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("POST /v1/signup", auth.SignUp)
	mux.HandleFunc("POST /v1/login", auth.Login)
	mux.HandleFunc("POST /v1/refresh", auth.Refresh)
	mux.HandleFunc("POST /v1/email/confirm-change", email.ConfirmChange)
	mux.HandleFunc("GET /v1/health", health.Health)

	// Second-factor login completion — public for the same reason
	// /v1/login is: this IS how the caller gets authenticated. Each of
	// these takes the pending_token from a login that paused with a
	// second_factor_required response.
	mux.HandleFunc("POST /v1/login/totp", totp.Login)
	mux.HandleFunc("POST /v1/login/passkey/begin", passkeys.LoginBegin)
	mux.HandleFunc("POST /v1/login/passkey/finish", passkeys.LoginFinish)
	mux.HandleFunc("POST /v1/login/recovery-code", recovery.Login)
	mux.HandleFunc("POST /v1/magic-link/request", magicLink.Request)
	mux.HandleFunc("POST /v1/magic-link/complete", magicLink.Complete)

	// OAuth — Start and Callback are public (they're the login/signup
	// path itself, same as /v1/login). Link requires auth since it
	// attaches an identity to an already-authenticated user.
	mux.HandleFunc("GET /v1/oauth/{provider}", func(w http.ResponseWriter, r *http.Request) {
		oauth.Start(w, r, r.PathValue("provider"))
	})
	mux.HandleFunc("GET /v1/oauth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		oauth.Callback(w, r, r.PathValue("provider"))
	})
	mux.HandleFunc("GET /v1/oauth/{provider}/link", RequireAuth(engine, func(w http.ResponseWriter, r *http.Request) {
		oauth.LinkStart(w, r, r.PathValue("provider"))
	}))
	// NOT behind RequireAuth — a browser redirect from the provider
	// carries no Authorization header. The linking user's identity
	// instead comes from the signed cookie LinkStart set; see
	// oauth_handlers.go's LinkCallback for why.
	mux.HandleFunc("GET /v1/oauth/{provider}/link/callback", func(w http.ResponseWriter, r *http.Request) {
		oauth.LinkCallback(w, r, r.PathValue("provider"))
	})

	// Authenticated
	mux.HandleFunc("POST /v1/logout", RequireAuth(engine, auth.Logout))
	mux.HandleFunc("POST /v1/logout-all", RequireAuth(engine, auth.LogoutAll))
	mux.HandleFunc("GET /v1/verify", RequireAuth(engine, auth.Verify))

	mux.HandleFunc("GET /v1/sessions", RequireAuth(engine, sessions.List))
	mux.HandleFunc("DELETE /v1/sessions/{id}", RequireAuth(engine, func(w http.ResponseWriter, r *http.Request) {
		sessions.Revoke(w, r, r.PathValue("id"))
	}))

	mux.HandleFunc("POST /v1/change-password", RequireAuth(engine, account.ChangePassword))
	mux.HandleFunc("POST /v1/delete-account", RequireAuth(engine, account.DeleteAccount))

	mux.HandleFunc("POST /v1/email/request-change", RequireAuth(engine, email.RequestChange))

	// Second-factor enrollment and management. TOTP and passkeys are
	// optional per deployment (see main.go's ENCRYPTION_KEY gate): an
	// unconfigured one answers 404 from mapError, the same shape an
	// unconfigured OAuth provider already uses — the routes exist either
	// way, so a client never has to discover availability from a routing
	// table it can't see.
	mux.HandleFunc("POST /v1/totp/enroll", RequireAuth(engine, totp.Enroll))
	mux.HandleFunc("POST /v1/totp/confirm", RequireAuth(engine, totp.Confirm))
	mux.HandleFunc("POST /v1/totp/disable", RequireAuth(engine, totp.Disable))

	mux.HandleFunc("POST /v1/passkeys/register/begin", RequireAuth(engine, passkeys.RegisterBegin))
	mux.HandleFunc("POST /v1/passkeys/register/finish", RequireAuth(engine, passkeys.RegisterFinish))
	mux.HandleFunc("GET /v1/passkeys", RequireAuth(engine, passkeys.List))
	mux.HandleFunc("DELETE /v1/passkeys/{credentialID}", RequireAuth(engine, func(w http.ResponseWriter, r *http.Request) {
		passkeys.Delete(w, r, r.PathValue("credentialID"))
	}))

	mux.HandleFunc("POST /v1/recovery-codes/generate", RequireAuth(engine, recovery.Generate))

	// API keys — machine-to-machine credentials belonging to the calling
	// user. Every handler here is scoped by cryden itself (auth.GenerateAPIKey/
	// ListAPIKeys/RevokeAPIKey all take the userID straight from the verified
	// token and never from the request), so one account can never read or
	// revoke another's key. Optional per deployment: unset Config.APIKeys
	// answers 404 api_keys_not_configured, the same shape as every other
	// unconfigured engine feature.
	mux.HandleFunc("POST /v1/api-keys", RequireAuth(engine, apiKeys.Create))
	mux.HandleFunc("GET /v1/api-keys", RequireAuth(engine, apiKeys.List))
	mux.HandleFunc("DELETE /v1/api-keys/{keyID}", RequireAuth(engine, func(w http.ResponseWriter, r *http.Request) {
		apiKeys.Revoke(w, r, r.PathValue("keyID"))
	}))

	// The ask-ai widget. Authenticated as an ordinary end user rather than
	// an operator, and that is the whole shape of the feature: it answers
	// questions about the caller's OWN account, scoped by cryden's
	// widget.Ask to the identity this repo verified from their token. It
	// sits here among the authenticated routes rather than in the /v1/admin
	// block below because an end user is not an operator and this is not an
	// admin surface — see WidgetHandlers.
	mux.HandleFunc("POST /v1/ask-ai", RequireAuth(engine, askAI.Ask))

	// Admin endpoints. Everything under /v1/admin goes through RequireAdmin
	// (middleware.go), which needs the `role` claim an operator's token
	// carries. OAuth provider health and the hash-migration report are both
	// this repo's own logic — cryden has no concept of a provider being
	// reachable, and no bulk way to read stored hash algorithms.
	//
	// Read-only is the default and every write here is deliberate. There
	// are three, and each is a named exception rather than a category: the
	// per-user metadata block below (a write is the whole feature), the
	// flagged-event review block (an operator recording a judgement they
	// made by hand), and the settings block at the bottom (a settings
	// save, the one path a tuning suggestion may pre-fill). None is
	// reachable from an AI tool, which is what CLAUDE.md's hard rule
	// actually protects. See README's note on the admin surface.
	mux.HandleFunc("GET /v1/admin/oauth/health", RequireAdmin(engine, oauthHealth.Health))
	mux.HandleFunc("GET /v1/admin/security/hash-migration", RequireAdmin(engine, security.HashMigration))
	// Second-factor enrolment, as the engine's own audit events against the
	// user total. Reports events rather than users, and says so — cryden
	// has no count of accounts with a factor enrolled, and getting one from
	// here would mean SQL against the engine's schema. See MFAAdoption.
	mux.HandleFunc("GET /v1/admin/security/mfa-adoption", RequireAdmin(engine, security.MFAAdoption))

	// The user surface — finding an account, and reading one account's
	// state. Read-only: there is no lock, unlock, password reset or
	// delete here, deliberately (see UserHandlers). This is the only
	// place an operator sees an account that is not their own, so the
	// detail view reports a lockout and cannot clear one, and shows a
	// session count rather than an account's devices.
	//
	// GET /v1/admin/users is registered without a trailing segment and
	// the detail route with one, which Go's ServeMux distinguishes; the
	// metadata routes below are more specific still and win over the
	// detail route for their own paths.
	mux.HandleFunc("GET /v1/admin/users", RequireAdmin(engine, users.List))
	mux.HandleFunc("GET /v1/admin/users/{userID}", RequireAdmin(engine, func(w http.ResponseWriter, r *http.Request) {
		users.Detail(w, r, r.PathValue("userID"))
	}))

	// Per-user metadata — the table behind JWT claim mapping. Per key
	// rather than a whole-map PUT, so two operators editing different
	// fields of one user cannot overwrite each other's work. The user id
	// is a path segment and is never read from the body, so there is no
	// second place it could come from.
	mux.HandleFunc("GET /v1/admin/users/{userID}/metadata", RequireAdmin(engine, func(w http.ResponseWriter, r *http.Request) {
		metadata.List(w, r, r.PathValue("userID"))
	}))
	mux.HandleFunc("PUT /v1/admin/users/{userID}/metadata/{key}", RequireAdmin(engine, func(w http.ResponseWriter, r *http.Request) {
		metadata.Put(w, r, r.PathValue("userID"), r.PathValue("key"))
	}))
	mux.HandleFunc("DELETE /v1/admin/users/{userID}/metadata/{key}", RequireAdmin(engine, func(w http.ResponseWriter, r *http.Request) {
		metadata.Delete(w, r, r.PathValue("userID"), r.PathValue("key"))
	}))

	// The webhook delivery log — what this deployment has announced to the
	// operator's endpoint, and what it failed to. Read-only: there is no
	// endpoint here that re-queues or deletes a delivery, deliberately (see
	// WebhookHandlers).
	mux.HandleFunc("GET /v1/admin/webhooks/deliveries", RequireAdmin(engine, hooks.Deliveries))

	// The shipped-events log — the redacted, filtered copy of the engine's
	// own log records that the cloud sink was handed, which is what a
	// hosted aggregator would have received. Read-only, and the only way
	// to see it: cryden keeps no history of what it logged, so this table
	// is the history.
	mux.HandleFunc("GET /v1/admin/logging/recent", RequireAdmin(engine, logging.Recent))

	// The weekly digest, and the history of the ones the schedule built.
	//
	// Two endpoints rather than one, because they answer different
	// questions and only one of them can write. GET /v1/admin/digest
	// reports on the window ending now and records nothing — asking twice
	// leaves no trace. GET /v1/admin/digest/history reads what the
	// scheduled job recorded, and nothing on this surface can create a
	// row there. Both are read-only; see DigestHandlers.
	mux.HandleFunc("GET /v1/admin/digest", RequireAdmin(engine, digests.Digest))
	mux.HandleFunc("GET /v1/admin/digest/history", RequireAdmin(engine, digests.DigestHistory))

	// The support-ticket assistant: "why can't this person log in",
	// answered from the account's own recorded history. Read-only by
	// construction — cryden builds it through interfaces carrying no way
	// to clear a lockout or reset a counter, so it cannot fix the account
	// it is describing. See SupportHandlers.
	mux.HandleFunc("GET /v1/admin/support/diagnose", RequireAdmin(engine, support.Diagnose))

	// The config tuning advisor. Suggestions only: there is no endpoint
	// that applies one, and no parameter that changes a setting — the
	// recorded decision is that a suggestion pre-fills the settings field
	// it concerns and a human saves that change through the ordinary
	// settings path. See TuningHandlers and CLAUDE.md's hard rule.
	mux.HandleFunc("GET /v1/admin/config-tuning", RequireAdmin(engine, tuning.ConfigTuning))

	// The flagged-event review queue — what the engine flagged, and what a
	// human decided about it. GET is read-only; PUT records a judgement
	// and nothing else, which is the third write on this surface. A
	// confirmation takes no action on any account, deliberately: there is
	// no machinery here that acts, so there is nothing for a confirm
	// button to trigger. See AnomalyHandlers.
	mux.HandleFunc("GET /v1/admin/anomalies", RequireAdmin(engine, anomalies.List))
	mux.HandleFunc("PUT /v1/admin/anomalies/{eventID}", RequireAdmin(engine, func(w http.ResponseWriter, r *http.Request) {
		anomalies.Review(w, r, r.PathValue("eventID"))
	}))

	// The AI settings surface — the "human saves it" half of
	// pre-fill-never-auto-apply, and the third of the three write blocks
	// on this surface (the others are the per-user metadata block and the
	// flagged-event review block above; an earlier version of this comment
	// claimed there was only one, which was wrong).
	//
	// The read-only rule above is about the AI *tools*, which are what the
	// engine's interfaces make read-only by carrying no method that can
	// act. These endpoints are the ordinary settings save path those tools'
	// output is allowed to pre-fill, and they are where the credentials
	// behind the tools live; they do not accept a suggestion, and no AI
	// feature holds a reference to this handler. See SettingsHandlers.
	//
	// PUT database-provider is not a plain write: it connects with the
	// supplied credentials and confirms the server refuses a write before
	// storing anything, so a role that can modify the database is rejected
	// at the form rather than trusted. That is why the endpoint is
	// noticeably slower than its neighbours.
	mux.HandleFunc("GET /v1/admin/settings/llm-provider", RequireAdmin(engine, aiSettings.LLMProvider))
	mux.HandleFunc("PUT /v1/admin/settings/llm-provider", RequireAdmin(engine, aiSettings.PutLLMProvider))
	mux.HandleFunc("DELETE /v1/admin/settings/llm-provider", RequireAdmin(engine, aiSettings.DeleteLLMProvider))
	mux.HandleFunc("GET /v1/admin/settings/database-provider", RequireAdmin(engine, aiSettings.DatabaseProvider))
	mux.HandleFunc("PUT /v1/admin/settings/database-provider", RequireAdmin(engine, aiSettings.PutDatabaseProvider))
	mux.HandleFunc("DELETE /v1/admin/settings/database-provider", RequireAdmin(engine, aiSettings.DeleteDatabaseProvider))
	mux.HandleFunc("GET /v1/admin/settings/ask-ai-widget", RequireAdmin(engine, aiSettings.AskAIWidget))
	mux.HandleFunc("PUT /v1/admin/settings/ask-ai-widget", RequireAdmin(engine, aiSettings.PutAskAIWidget))
	mux.HandleFunc("DELETE /v1/admin/settings/ask-ai-widget", RequireAdmin(engine, aiSettings.DeleteAskAIWidget))

	return mux
}
