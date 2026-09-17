package httpapi

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/crydensync/cryden/v2"

	"github.com/crydensync/api/config"
)

type contextKey string

const userIDContextKey contextKey = "userID"

// CallerIP extracts the real client IP — checks X-Forwarded-For first
// (set by reverse proxies in real deployments), falls back to the raw
// connection address. The engine deliberately never does this itself;
// it's the HTTP layer's job by design.
func CallerIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func UserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

// RequireAuth verifies the Bearer access token and injects the
// authenticated user ID into the request context.
func RequireAuth(engine *cryden.Engine, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeErr(w, errMissingAuthHeader)
			return
		}
		tok := strings.TrimPrefix(authHeader, "Bearer ")

		userID, err := cryden.VerifyToken(engine, tok)
		if err != nil {
			writeErr(w, err)
			return
		}

		ctx := context.WithValue(r.Context(), userIDContextKey, userID)
		next(w, r.WithContext(ctx))
	}
}

func UserIDFromContext(r *http.Request) string {
	id, _ := r.Context().Value(userIDContextKey).(string)
	return id
}

// RequireAdmin verifies the Bearer access token exactly like
// RequireAuth, and additionally requires its "role" claim to be
// "admin". That claim is set by main.go's AccessTokenClaims provider,
// backed by operator.Store — an ordinary end user's token carries no
// role claim at all, so an unknown user, a revoked operator, and
// someone who was simply never an operator all fail identically here.
// There is deliberately no separate "not an operator, but otherwise
// valid" response — that distinction is not the caller's to learn.
//
// The router must not call this directly for an admin route; it goes
// through AdminOnly, which is this on a Postgres deployment and a flat
// 501 on a SQLite one. See AdminOnly.
func RequireAdmin(engine *cryden.Engine, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeErr(w, errMissingAuthHeader)
			return
		}
		tok := strings.TrimPrefix(authHeader, "Bearer ")

		userID, claims, err := cryden.VerifyTokenWithClaims(engine, tok)
		if err != nil {
			writeErr(w, err)
			return
		}
		if role, _ := claims["role"].(string); role != "admin" {
			writeErr(w, errNotOperator)
			return
		}

		ctx := context.WithValue(r.Context(), userIDContextKey, userID)
		next(w, r.WithContext(ctx))
	}
}

// WithCORS restricts which origins may call this API. allowedOrigins
// should be an explicit list from config — never "*" for an API that
// handles auth tokens and cookies-adjacent credentials.
func WithCORS(allowedOrigins []string, next http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AdminOnly returns the middleware for every route under /v1/admin.
//
// On a Postgres deployment it is RequireAdmin. On a SQLite one it is a
// flat 501 that never looks at the token, and the reason is worth
// stating because the easy implementation — let RequireAdmin run and
// deny — would be wrong in a way that takes a while to notice:
//
//   - The admin console's tables are this repo's own and Postgres-only
//     by decision (NEXT.md Tier 6), and RequireAdmin itself depends on
//     the operators table via the token's "role" claim. A SQLite
//     deployment therefore has no operators, so no token can carry the
//     claim, so RequireAdmin would answer 403 not_operator to everyone
//     including a legitimate operator. That reads as "you personally
//     lack access" when the truth is "this backend has no console".
//   - main.go does not wire the claims provider on SQLite for the same
//     reason, so the 403 would be doubly misleading.
//
// Doing it here rather than per-route is the point: a route added later
// inherits the answer, and there is no second list to keep in sync.
// Every admin route in the router goes through the value this returns —
// which is why RequireAdmin's own doc says not to call it directly.
func AdminOnly(engine *cryden.Engine, cfg config.Config) func(http.HandlerFunc) http.HandlerFunc {
	if cfg.UsesSQLite() {
		return func(http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				writeErr(w, errNotImplementedOnSQLite)
			}
		}
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return RequireAdmin(engine, next)
	}
}
