package httpapi

import (
	"database/sql"
	"net/http"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store"

	"github.com/crydensync/api/config"
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
	hooks := &WebhookHandlers{Store: d.Hooks}

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

	// Admin endpoints. Everything under /v1/admin goes through RequireAdmin
	// (middleware.go), which needs the `role` claim an operator's token
	// carries. OAuth provider health and the hash-migration report are both
	// this repo's own logic — cryden has no concept of a provider being
	// reachable, and no bulk way to read stored hash algorithms.
	//
	// Every endpoint here is read-only, and has to stay that way: see
	// CLAUDE.md's hard rule about the admin surface.
	mux.HandleFunc("GET /v1/admin/oauth/health", RequireAdmin(engine, oauthHealth.Health))
	mux.HandleFunc("GET /v1/admin/security/hash-migration", RequireAdmin(engine, security.HashMigration))

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

	return mux
}
