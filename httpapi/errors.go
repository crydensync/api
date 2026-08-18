package httpapi

import (
	"errors"
	"net/http"

	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// apiError is the (status, code, message) triple every handler
// resolves an engine error into. code is the stable string an SDK or
// frontend branches on programmatically — message is human-readable,
// never machine-parsed.
type apiError struct {
	Status  int
	Code    string
	Message string
}

// mapError is the single place engine errors become HTTP responses.
// Add a new engine error here once, every handler that might return
// it benefits automatically — this is what keeps handlers thin.
// errMissingAuthHeader is a local, API-layer-only error — not
// something the engine returns, since the engine never deals with
// HTTP headers at all. Mapped here alongside engine errors so
// RequireAuth can route it through the same writeErr/mapError path.
var errMissingAuthHeader = errors.New("missing or malformed Authorization header")

// errEdgeRateLimited is the coarse, per-IP, whole-API rate limit —
// distinct from auth.ErrRateLimited, which is the engine's own
// per-user login/signup limiter. Both surface the same "rate_limited"
// code to the client; the distinction only matters server-side.
var errEdgeRateLimited = errors.New("too many requests")

func mapError(err error) apiError {
	switch {
	case errors.Is(err, errMissingAuthHeader):
		return apiError{http.StatusUnauthorized, "missing_auth_header", "missing or malformed Authorization header"}
	case errors.Is(err, errEdgeRateLimited):
		return apiError{http.StatusTooManyRequests, "rate_limited", "too many requests, please slow down"}
	case errors.Is(err, auth.ErrInvalidCredentials):
		return apiError{http.StatusUnauthorized, "invalid_credentials", "invalid email or password"}
	case errors.Is(err, auth.ErrUserExists):
		return apiError{http.StatusConflict, "user_exists", "an account with this email already exists"}
	case errors.Is(err, auth.ErrRateLimited):
		return apiError{http.StatusTooManyRequests, "rate_limited", "too many attempts, please try again later"}
	case errors.Is(err, auth.ErrAccountLocked):
		return apiError{http.StatusForbidden, "account_locked", "account temporarily locked due to failed login attempts"}
	case errors.Is(err, auth.ErrVerificationTokenInvalid):
		return apiError{http.StatusBadRequest, "verification_token_invalid", "verification token is invalid or already used"}
	case errors.Is(err, auth.ErrVerificationTokenExpired):
		return apiError{http.StatusBadRequest, "verification_token_expired", "verification token has expired"}
	case errors.Is(err, store.ErrSessionNotOwned):
		return apiError{http.StatusForbidden, "session_not_owned", "this session does not belong to you"}
	case errors.Is(err, store.ErrNotFound):
		return apiError{http.StatusNotFound, "not_found", "resource not found"}
	case errors.Is(err, token.ErrInvalidToken):
		return apiError{http.StatusUnauthorized, "invalid_token", "refresh token is invalid"}
	case errors.Is(err, token.ErrTokenReused):
		// The entire session family was just revoked by the engine —
		// the client MUST discard all tokens and force a full re-login,
		// not just retry the refresh.
		return apiError{http.StatusUnauthorized, "token_reused", "token reuse detected, all sessions for this device chain have been revoked"}
	case errors.Is(err, token.ErrInvalidAccessToken):
		return apiError{http.StatusUnauthorized, "invalid_access_token", "access token is invalid or expired"}
	default:
		// Anything unmapped is treated as internal — deliberately
		// vague to the client (never leak internal error strings,
		// e.g. raw DB errors, over the API), logged server-side by
		// the caller instead.
		return apiError{http.StatusInternalServerError, "internal_error", "an unexpected error occurred"}
	}
}
