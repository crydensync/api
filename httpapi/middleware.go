package httpapi

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/crydensync/cryden/v2"
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
