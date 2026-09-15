package httpapi

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/crydensync/cryden/v2"
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

// errNotOperator is returned by RequireAdmin when a valid, verified
// token has no "role" claim of "admin" — an ordinary end user, a
// revoked operator, and an unrecognized user all look identical here
// on purpose (see operator/store.go and RequireAdmin).
var errNotOperator = errors.New("this account does not have console operator access")

// errEdgeRateLimited is the coarse, per-IP, whole-API rate limit —
// distinct from auth.ErrRateLimited, which is the engine's own
// per-user login/signup limiter. Both surface the same "rate_limited"
// code to the client; the distinction only matters server-side.
var errEdgeRateLimited = errors.New("too many requests")

// errAdminStoresUnavailable is returned by an admin handler whose backing
// stores were never wired — see httpapi.Deps, whose store fields a test
// may legitimately leave nil. That is a wiring fact and not a server
// fault, so it answers 404 like every other unconfigured feature in this
// API rather than a 500 an operator would read as a bug.
var errAdminStoresUnavailable = errors.New("this report requires stores that are not configured on this deployment")

// The following three are local, API-layer-only errors from the
// OAuth redirect/callback flow itself — never returned by the engine,
// which never touches HTTP or a specific provider.
var errOAuthProviderNotConfigured = errors.New("oauth provider not configured")
var errOAuthStateMismatch = errors.New("oauth state parameter missing or mismatched")
var errOAuthEmailNotAvailable = errors.New("oauth provider did not return a usable email address")
var errOAuthLinkNotConfigured = errors.New("oauth linking is not available: server is missing a signing secret")
var errOAuthIdentityVerificationFailed = errors.New("could not verify the identity the provider returned")
var errOAuthLinkSessionMissing = errors.New("oauth link session missing, expired, or tampered with — please retry")

func mapError(err error) apiError {
	switch {
	case errors.Is(err, errMissingAuthHeader):
		return apiError{http.StatusUnauthorized, "missing_auth_header", "missing or malformed Authorization header"}
	case errors.Is(err, errNotOperator):
		return apiError{http.StatusForbidden, "not_operator", "this account does not have console operator access"}
	case errors.Is(err, errEdgeRateLimited):
		return apiError{http.StatusTooManyRequests, "rate_limited", "too many requests, please slow down"}
	case errors.Is(err, errAdminStoresUnavailable):
		return apiError{http.StatusNotFound, "not_configured", "this report is not available on this deployment"}
	case errors.Is(err, errOAuthProviderNotConfigured):
		return apiError{http.StatusNotFound, "oauth_provider_not_configured", "this OAuth provider is not configured on this deployment"}
	case errors.Is(err, errOAuthStateMismatch):
		return apiError{http.StatusBadRequest, "oauth_state_mismatch", "oauth state parameter missing or mismatched — please retry the login"}
	case errors.Is(err, errOAuthEmailNotAvailable):
		return apiError{http.StatusBadRequest, "oauth_email_not_available", "could not retrieve a usable email address from the provider"}
	case errors.Is(err, errOAuthIdentityVerificationFailed):
		return apiError{http.StatusBadRequest, "oauth_identity_verification_failed", "could not verify the identity the provider returned — please try again"}
	case errors.Is(err, errOAuthLinkNotConfigured):
		return apiError{http.StatusInternalServerError, "oauth_link_not_configured", "oauth linking is not available on this deployment"}
	case errors.Is(err, errOAuthLinkSessionMissing):
		return apiError{http.StatusBadRequest, "oauth_link_session_missing", "oauth link session missing, expired, or invalid — please retry"}
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
	case errors.Is(err, auth.ErrOAuthIdentityAlreadyLinked):
		return apiError{http.StatusConflict, "oauth_identity_already_linked", "this provider account is already linked to a different user"}
	case errors.Is(err, auth.ErrTOTPNotEnabled):
		return apiError{http.StatusBadRequest, "totp_not_enabled", "TOTP is not enabled for this account"}
	case errors.Is(err, auth.ErrTOTPAlreadyEnabled):
		return apiError{http.StatusConflict, "totp_already_enabled", "TOTP is already enabled for this account"}
	case errors.Is(err, auth.ErrInvalidTOTPCode):
		return apiError{http.StatusUnauthorized, "invalid_totp_code", "that code is invalid or has expired"}
	case errors.Is(err, auth.ErrInvalidPendingLogin):
		return apiError{http.StatusUnauthorized, "invalid_pending_login", "this login attempt has expired — please log in again"}
	case errors.Is(err, auth.ErrNoPasskeysEnrolled):
		return apiError{http.StatusBadRequest, "no_passkeys_enrolled", "no passkeys are registered for this account"}
	case errors.Is(err, auth.ErrInvalidWebAuthnResponse):
		return apiError{http.StatusUnauthorized, "invalid_passkey_response", "the passkey response could not be verified — please try again"}
	case errors.Is(err, auth.ErrInvalidCeremonyToken):
		return apiError{http.StatusBadRequest, "invalid_ceremony_token", "this passkey ceremony has expired — please start again"}
	case errors.Is(err, auth.ErrPasswordBreached):
		return apiError{http.StatusBadRequest, "password_breached", "this password has appeared in a known data breach and cannot be used"}
	// API key errors. ErrInvalidAPIKey is what a presented key fails with
	// — unknown, revoked, expired, malformed, empty, all one error on
	// purpose so a caller cannot probe which of the keys it holds are
	// still live. No endpoint in this repo accepts an API key yet, so
	// nothing returns it today; it is mapped here so the first one that
	// does cannot ship without it, which is the entire reason mapError is
	// a single site.
	case errors.Is(err, auth.ErrInvalidAPIKey):
		return apiError{http.StatusUnauthorized, "invalid_api_key", "this API key is invalid, revoked or expired"}
	case errors.Is(err, auth.ErrAPIKeyNotFound):
		return apiError{http.StatusNotFound, "api_key_not_found", "no such API key"}
	case errors.Is(err, auth.ErrInvalidAPIKeyScope):
		return apiError{http.StatusBadRequest, "invalid_api_key_scope", "a scope must be non-empty and contain no whitespace"}
	case errors.Is(err, auth.ErrInvalidAPIKeyTTL):
		return apiError{http.StatusBadRequest, "invalid_api_key_ttl", "expiry cannot be in the past"}
	// The five "not configured" sentinels below mean this deployment has
	// not enabled that feature, not that the caller did anything wrong.
	// 404 rather than 500 so a client can hide the option instead of
	// reporting a server fault, matching oauth_provider_not_configured.
	case errors.Is(err, cryden.ErrTOTPNotConfigured):
		return apiError{http.StatusNotFound, "totp_not_configured", "TOTP is not enabled on this deployment"}
	case errors.Is(err, cryden.ErrWebAuthnNotConfigured):
		return apiError{http.StatusNotFound, "passkeys_not_configured", "passkeys are not enabled on this deployment"}
	case errors.Is(err, cryden.ErrMagicLinkNotConfigured):
		return apiError{http.StatusNotFound, "magic_link_not_configured", "magic-link login is not enabled on this deployment"}
	case errors.Is(err, cryden.ErrRecoveryCodesNotConfigured):
		return apiError{http.StatusNotFound, "recovery_codes_not_configured", "recovery codes are not enabled on this deployment"}
	// main.go always wires the API key store, so this is not reachable on
	// this repo's own deployments — it is mapped so an engine built
	// without Config.APIKeys answers a real shape rather than a 500,
	// which is what a test or an embedding host would otherwise get.
	case errors.Is(err, cryden.ErrAPIKeysNotConfigured):
		return apiError{http.StatusNotFound, "api_keys_not_configured", "API keys are not enabled on this deployment"}
	default:
		// Struct-typed errors (not plain sentinels) need errors.As,
		// not errors.Is — ErrOAuthEmailConflict carries Email and
		// Provider that the client needs, so it can't just be a case
		// in the switch above like the sentinel errors.
		// Struct-typed for the same reason as ErrOAuthEmailConflict
		// below: it carries every violated rule at once (stable codes
		// like "min_length"), and writeErr reads them back off the error
		// itself — see its details handling, which is why nothing needs
		// to be added to this table for them to reach the client.
		var policy *auth.ErrPasswordPolicyViolation
		if errors.As(err, &policy) {
			return apiError{http.StatusBadRequest, "password_policy_violation", "password does not meet the required policy"}
		}
		var conflict *auth.ErrOAuthEmailConflict
		if errors.As(err, &conflict) {
			return apiError{
				Status:  http.StatusConflict,
				Code:    "oauth_email_conflict",
				Message: fmt.Sprintf("an account with this email already exists; log in with your password to link %s", conflict.Provider),
			}
		}
		// Anything unmapped is treated as internal — deliberately
		// vague to the client (never leak internal error strings,
		// e.g. raw DB errors, over the API), logged server-side by
		// the caller instead.
		return apiError{http.StatusInternalServerError, "internal_error", "an unexpected error occurred"}
	}
}
