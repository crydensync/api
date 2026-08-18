package httpapi

import (
	"database/sql"
	"net/http"

	"github.com/crydensync/cryden/v2"
)

// NewRouter builds the full route table. Called once from main.go.
func NewRouter(engine *cryden.Engine, db *sql.DB) http.Handler {
	auth := &AuthHandlers{Engine: engine}
	sessions := &SessionHandlers{Engine: engine}
	account := &AccountHandlers{Engine: engine}
	email := &EmailHandlers{Engine: engine}
	health := &HealthHandler{DB: db}

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("POST /v1/signup", auth.SignUp)
	mux.HandleFunc("POST /v1/login", auth.Login)
	mux.HandleFunc("POST /v1/refresh", auth.Refresh)
	mux.HandleFunc("POST /v1/email/confirm-change", email.ConfirmChange)
	mux.HandleFunc("GET /v1/health", health.Health)

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
