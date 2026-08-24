package httpapi

import (
	"database/sql"
	"net/http"

	"github.com/crydensync/cryden/v2"

	"github.com/crydensync/api/config"
)

// NewRouter builds the full route table. Called once from main.go.
func NewRouter(engine *cryden.Engine, db *sql.DB, cfg config.Config) http.Handler {
	auth := &AuthHandlers{Engine: engine}
	sessions := &SessionHandlers{Engine: engine}
	account := &AccountHandlers{Engine: engine}
	email := &EmailHandlers{Engine: engine}
	health := &HealthHandler{DB: db}
	oauth := &OAuthHandlers{Engine: engine, Config: cfg}

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("POST /v1/signup", auth.SignUp)
	mux.HandleFunc("POST /v1/login", auth.Login)
	mux.HandleFunc("POST /v1/refresh", auth.Refresh)
	mux.HandleFunc("POST /v1/email/confirm-change", email.ConfirmChange)
	mux.HandleFunc("GET /v1/health", health.Health)

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

	return mux
}
