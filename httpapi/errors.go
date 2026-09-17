package httpapi

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
	"github.com/crydensync/cryden/v2/widget"

	"github.com/crydensync/api/aiprovider"
	"github.com/crydensync/api/anomalyreview"
	"github.com/crydensync/api/askai"
	"github.com/crydensync/api/settings"
	"github.com/crydensync/api/usermeta"
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

// errAskAIUnavailable is the same wiring fact as errAdminStoresUnavailable
// one surface over: a router built without an askai.Service cannot serve
// the widget. 404 for the same reason — nothing is wrong with the server,
// the feature simply is not configured here.
var errAskAIUnavailable = errors.New("the ask-ai widget is not configured on this deployment")

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
	// Per-user metadata. The two 400s are the reserved-claim rule reaching
	// the client: a key of "sub" would not be ignored at login, it would
	// fail the login, so it is refused where an operator can still see
	// why. "role" is refused with it — see usermeta.RoleClaim.
	case errors.Is(err, usermeta.ErrReservedKey):
		return apiError{http.StatusBadRequest, "reserved_metadata_key", "that key names a claim this deployment sets itself, so it cannot be mapped as metadata"}
	case errors.Is(err, usermeta.ErrInvalidKey):
		return apiError{http.StatusBadRequest, "invalid_metadata_key", "a metadata key must start with a letter or underscore and contain only letters, digits, underscores, dots and dashes, up to 64 characters"}
	case errors.Is(err, usermeta.ErrNotFound):
		return apiError{http.StatusNotFound, "metadata_key_not_found", "no such metadata key on this user"}
	// A review of a flagged event. "No such audit event" is answered by the
	// database rather than by Go — cryden exposes no lookup-by-event-id, so
	// the foreign key on reviewed_anomalies is what refuses it (see
	// anomalyreview.PostgresStore.Set). It reads as 404 because that is what
	// it is: a console acting on a stale list, not a server fault.
	case errors.Is(err, anomalyreview.ErrNoSuchEvent):
		return apiError{http.StatusNotFound, "audit_event_not_found", "no such audit event, so there is nothing to review"}
	case errors.Is(err, anomalyreview.ErrInvalidStatus):
		return apiError{http.StatusBadRequest, "invalid_review_status", "a review status must be one of unreviewed, confirmed or dismissed"}
	case errors.Is(err, anomalyreview.ErrNoteTooLong):
		return apiError{http.StatusBadRequest, "invalid_review_note", "that note is longer than the 500-character limit"}
	// The settings behind the AI-assisted admin features. The two invalid
	// cases are a form the operator can fix, so they say which field and
	// which bound rather than a generic "bad request" — the caller is
	// already an operator, and none of it is secret.
	case errors.Is(err, errSettingsNotConfigured):
		return apiError{http.StatusNotFound, "not_configured", "the AI settings endpoints are not configured on this deployment"}
	case errors.Is(err, settings.ErrInvalidLLMProvider):
		return apiError{http.StatusBadRequest, "invalid_llm_provider", "that LLM provider configuration is not usable"}
	case errors.Is(err, settings.ErrInvalidDatabaseProvider):
		return apiError{http.StatusBadRequest, "invalid_database_provider", "that database provider configuration is not usable"}
	case errors.Is(err, settings.ErrInvalidAskAIWidget):
		return apiError{http.StatusBadRequest, "invalid_ask_ai_widget", "that ask-ai widget configuration is not usable"}
	// The read-only check. A role that can write is refused outright
	// rather than stored with a warning: cryden's design decision is that
	// this credential boundary, not the allowlist, is what makes the AI
	// query surface safe, so a writable role is a broken guarantee and
	// not a preference. "Could not verify" is a different answer for the
	// same reason — it is not a pass.
	case errors.Is(err, aiprovider.ErrNotReadOnly):
		return apiError{http.StatusBadRequest, "database_role_not_read_only", "that database role can write, so it cannot back the AI query surface — create a role with SELECT only and use that"}
	case errors.Is(err, aiprovider.ErrCannotVerifyReadOnly):
		return apiError{http.StatusBadRequest, "database_role_unverified", "could not verify that the database role is read-only, so it was not stored — check the connection string and that the role can connect"}
	// The ask-ai widget's serving side. Three of these are the same
	// "not enabled here" family as the settings endpoints above: a
	// deployment that has switched the widget off, or switched it on
	// without configuring a provider, answers 404 so a console hides the
	// launcher rather than reporting a fault.
	//
	// The entity refusal is one case covering two sentinels from two
	// packages, and that is deliberate. aiprovider.ErrEntityOutOfScope is
	// the deployment's own scope setting refusing, and
	// widget.ErrEntityNotAvailable is cryden's fail-closed default for an
	// entity it has not been taught to bound to one user. A caller can
	// distinguish neither, and must not: the message names no entity and
	// no scope, because it reaches an end user and describing this
	// deployment's schema to whoever is typing questions at it is exactly
	// what aiprovider.ScopedProvider exists to avoid.
	case errors.Is(err, errAskAIUnavailable):
		return apiError{http.StatusNotFound, "not_configured", "the ask-ai widget is not available on this deployment"}
	case errors.Is(err, askai.ErrWidgetDisabled):
		return apiError{http.StatusNotFound, "ask_ai_widget_disabled", "the ask-ai widget is switched off on this deployment"}
	case errors.Is(err, askai.ErrNotConfigured):
		return apiError{http.StatusNotFound, "not_configured", "the ask-ai widget is not available on this deployment"}
	case errors.Is(err, askai.ErrOriginNotAllowed):
		return apiError{http.StatusForbidden, "origin_not_allowed", "this page is not allowed to embed the ask-ai widget"}
	case errors.Is(err, askai.ErrInvalidQuestion):
		return apiError{http.StatusBadRequest, "invalid_question", "that question is empty or too long — see the message for which"}
	case errors.Is(err, aiprovider.ErrEntityOutOfScope), errors.Is(err, widget.ErrEntityNotAvailable):
		return apiError{http.StatusBadRequest, "question_not_answerable", "the widget cannot answer that kind of question on this deployment"}
	// A stored credential this deployment's key cannot open. Distinct
	// from "not configured" on purpose: the row is still there, and
	// telling an operator it is missing would send them to re-enter a
	// credential that nothing is wrong with.
	case errors.Is(err, settings.ErrUndecryptable):
		return apiError{http.StatusConflict, "setting_undecryptable", "this setting is stored but cannot be decrypted — SETTINGS_ENCRYPTION_KEY has probably changed; re-enter the credential or clear the setting"}
	case errors.Is(err, settings.ErrNoEncryptionKey):
		return apiError{http.StatusNotFound, "not_configured", "the AI settings endpoints are not configured on this deployment"}
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
