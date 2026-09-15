package httpapi

import (
	"database/sql"
	"net/http"

	"github.com/crydensync/cryden/v2"

	"github.com/crydensync/api/config"
)

// Deps is everything the route table needs to build its handlers. It is a
// struct rather than a parameter list because the admin surface keeps
// growing: every endpoint added under /v1/admin needs something the route
// table does not have today, and a struct absorbs that without every
// existing call site growing a positional argument. It also lets a test
// build a router with exactly the dependencies the endpoint under test
// needs and leave the rest nil.
type Deps struct {
	Engine *cryden.Engine

	// DB is used only by the health handler, which pings it. Nil is fine
	// for a router built without a database (tests); /v1/health then
	// reports the database as unconfigured rather than panicking.
	DB     *sql.DB
	Config config.Config
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

	// Admin endpoints — the first in this repo, hence the note. Everything
	// under /v1/admin goes through RequireAdmin (middleware.go), which
	// needs the `role` claim an operator's token carries. OAuth provider
	// health is this repo's own logic: cryden has no concept of a provider
	// being reachable, only of whether it is configured.
	mux.HandleFunc("GET /v1/admin/oauth/health", RequireAdmin(engine, oauthHealth.Health))

	return mux
}
