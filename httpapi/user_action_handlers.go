package httpapi

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store"
)

// UserActionHandlers answers the admin user surface's write half: the
// account actions an operator takes on somebody else's account.
//
// user_handlers.go's doc explains what that surface deliberately did not
// have: no lock, no unlock, nothing that changes an account, on the
// position that an operator who needs one "has the engine's own admin
// path, not an HTTP endpoint this repo invented". The console is now the
// reason that position no longer holds. The engine's own admin path is
// the CLI reaching into the database directly (csax users unlock clears
// a lockout with ResetFailedAttempts, csax oauth unlink runs bare SQL
// against oauth_identities), and a console that cannot reach the
// database has no path at all. Rather than send an operator to a SQL
// prompt, these endpoints are the same operations behind the admin gate,
// each one audited, each one answered with the state the account is in
// afterwards. What is still deliberately absent is unchanged: no
// password reset, no delete, nothing that reads PasswordHash.
type UserActionHandlers struct {
	// Engine is used for exactly one call: cryden.SignUp, the engine's
	// own public path for creating an account, so the password policy,
	// the breach check and the rate limiter all run as they would for a
	// signup that arrived at POST /v1/signup.
	Engine *cryden.Engine

	// Users, Sessions, Audit, OAuth and TOTP are the same store
	// instances main.go handed cryden, for the reason httpapi.Deps
	// gives: an action against a second store object is a change to
	// different data than the engine would act on.
	Users    store.UserStore
	Sessions store.SessionStore
	Audit    store.AuditStore
	OAuth    store.OAuthStore
	TOTP     store.TOTPStore
}

// The audit event types this surface records for its own actions. The
// engine's vocabulary (store.EventAccountLocked and friends) names what
// the engine did to an account during a login; these name what an
// operator did to it. They live here rather than in cryden because the
// engine has no operator concept to attach them to, and the audit table
// holds any type a host writes (see AuditStore.CountByType), so a host
// defining its own event types is a supported shape, not a special case.
const (
	EventAdminUserCreated     store.AuditEventType = "admin_user_created"
	EventAdminAccountUnlocked store.AuditEventType = "admin_account_unlocked"
	EventAdminUserSuspended   store.AuditEventType = "admin_user_suspended"
	EventAdminUserUnsuspended store.AuditEventType = "admin_user_unsuspended"
	EventAdminSessionsRevoked store.AuditEventType = "admin_sessions_revoked"
	EventAdminTOTPDisabled    store.AuditEventType = "admin_totp_disabled"
	EventAdminOAuthUnlinked   store.AuditEventType = "admin_oauth_unlinked"
)

// opUserID reads the operator's own id out of the context RequireAdmin
// put there. It is the audit trail's answer to "who did this", and it is
// read from the verified token's subject rather than from the body, so
// a caller cannot name somebody else as the reviewer.
func opUserID(r *http.Request) string {
	id, _ := r.Context().Value(userIDContextKey).(string)
	return id
}

// adminActionDTO is the answer every action here returns: the account as
// it stands after the action. The console re-renders the detail view
// from it rather than issuing a second GET, and the fields are the same
// adminUserDTO the list and detail views carry, so one shape is all the
// client ever parses.
type adminActionDTO struct {
	User   adminUserDTO `json:"user"`
	Detail string       `json:"detail,omitempty"`
}

// requireUser is the read every action starts from: the account has to
// exist, and a path segment that cannot be a user id is answered 404 the
// same as one that is simply not a user (see Detail for the full reason
// a malformed id never reaches Postgres).
func (h *UserActionHandlers) requireUser(w http.ResponseWriter, r *http.Request, userID string) (store.User, bool) {
	if !looksLikeUUID(userID) {
		writeErr(w, store.ErrNotFound)
		return store.User{}, false
	}
	if h.Users == nil || h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return store.User{}, false
	}
	user, err := h.Users.GetByID(r.Context(), userID)
	if err != nil {
		writeErr(w, err)
		return store.User{}, false
	}
	return user, true
}

// record writes one audit event for an operator action. The operator id
// rides in Metadata rather than UserID: the audit row's UserID is the
// account the event happened to, and an event that named the operator
// there would file an action taken on account B under account A.
func (h *UserActionHandlers) record(r *http.Request, eventType store.AuditEventType, target store.User, detail string, operatorID string) {
	metadata := map[string]string{"by": operatorID}
	if detail != "" {
		metadata["detail"] = detail
	}
	if err := h.Audit.Record(r.Context(), store.AuditEvent{
		Type:     eventType,
		UserID:   target.ID,
		IP:       CallerIP(r),
		Metadata: metadata,
	}); err != nil {
		// The action succeeded and is being reported as succeeded. An
		// audit write that failed is logged and answered anyway: failing
		// the request now would leave the account changed while the
		// client saw an error, which is the one outcome worse than an
		// unrecorded event. The same trade the engine's own login path
		// makes (auth/login.go logs a failed audit write and continues).
		log.Printf("admin user action: audit record error (%s for %s): %v", eventType, target.ID, err)
	}
}

// Create registers a new account: POST /v1/admin/users.
//
// It is cryden.SignUp, the engine's own public path, with the caller IP
// labelled "operator" rather than spoofed: the engine requires a caller
// IP and uses it for rate limiting and audit, and the honest label is
// the API's own convention (the CLI uses "cli" the same way). The rate
// limiter that SignUp consults is the engine's per-IP limiter keyed on
// that label, so a console signing up many accounts in one window
// shares one limiter bucket; that is the cost of reusing the engine's
// path rather than reaching for Users.Create directly, and it is the
// safe direction to be wrong in.
func (h *UserActionHandlers) Create(w http.ResponseWriter, r *http.Request) {
	if h.Engine == nil || h.Users == nil || h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeBadRequest(w, "a JSON body with email and password is required")
		return
	}
	if body.Email == "" || body.Password == "" {
		writeBadRequest(w, "email and password are both required")
		return
	}

	user, err := cryden.SignUp(r.Context(), h.Engine, body.Email, body.Password, "operator")
	if err != nil {
		writeErr(w, err)
		return
	}

	// SignUp records its own EventSignupSuccess as any signup would. This
	// event is the second sentence in the audit trail: the same account,
	// naming the operator who created it. Two events, because they answer
	// two different questions ("was this account signed up" and "who put
	// it here"), and collapsing them would make an operator-created
	// account indistinguishable from a self-registered one in the history
	// the console's detail view reads.
	h.record(r, EventAdminUserCreated, user, "", opUserID(r))

	writeData(w, http.StatusCreated, adminActionDTO{User: newAdminUserDTO(user, time.Now())})
}

// Unlock clears a lockout and its failed-attempt counter:
// POST /v1/admin/users/{userID}/unlock.
//
// ResetFailedAttempts is the operation the CLI's `csax users unlock`
// runs, unchanged: it clears both the counter and LockedUntil together,
// which is the engine's own definition of an unlock. An account that is
// not locked is unlocked anyway rather than refused, because the goal
// is an account that can sign in, not a report about a lock.
func (h *UserActionHandlers) Unlock(w http.ResponseWriter, r *http.Request, userID string) {
	target, ok := h.requireUser(w, r, userID)
	if !ok {
		return
	}

	if err := h.Users.ResetFailedAttempts(r.Context(), target.ID); err != nil {
		writeErr(w, err)
		return
	}

	h.record(r, EventAdminAccountUnlocked, target, "", opUserID(r))

	user, err := h.Users.GetByID(r.Context(), target.ID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, adminActionDTO{User: newAdminUserDTO(user, time.Now())})
}

// Suspend sets an account's lockout with no expiry:
// POST /v1/admin/users/{userID}/suspend.
//
// The engine has no suspend of its own; LockAccount with a far-future
// time is what the CLI would hold in a WHERE clause, and it keeps the
// engine's own semantics: a login against a locked account is refused
// by the engine's normal path, the audit history records the action,
// and sessions are revoked below so a live session cannot outlive the
// lock it was granted under.
func (h *UserActionHandlers) Suspend(w http.ResponseWriter, r *http.Request, userID string) {
	target, ok := h.requireUser(w, r, userID)
	if !ok {
		return
	}

	// A century out: long enough that no operator will be asked to renew
	// it, short enough to stay inside what every date column and every
	// client parses. Far-future sentinel dates have burned people before
	// (the year-2038 overflow, Excel's 9999-12-31); 2126 keeps the same
	// shape as an ordinary expiry while never arriving.
	until := time.Now().AddDate(100, 0, 0)
	if err := h.Users.LockAccount(r.Context(), target.ID, until); err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Sessions.RevokeAllForUser(r.Context(), target.ID); err != nil {
		writeErr(w, err)
		return
	}

	h.record(r, EventAdminUserSuspended, target, "indefinite", opUserID(r))

	user, err := h.Users.GetByID(r.Context(), target.ID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, adminActionDTO{User: newAdminUserDTO(user, time.Now())})
}

// Unsuspend clears a lockout outright:
// POST /v1/admin/users/{userID}/unsuspend.
//
// ResetFailedAttempts already clears LockedUntil (see the CLI's unlock,
// which is the behaviour this reuses), so unlock and unsuspend are one
// engine operation with two names. The distinction the console keeps is
// the audit record: lifting a suspension an operator imposed is a
// different sentence in an audit trail than clearing a lockout the
// engine itself imposed, and the account's history should say which
// happened.
func (h *UserActionHandlers) Unsuspend(w http.ResponseWriter, r *http.Request, userID string) {
	target, ok := h.requireUser(w, r, userID)
	if !ok {
		return
	}

	if err := h.Users.ResetFailedAttempts(r.Context(), target.ID); err != nil {
		writeErr(w, err)
		return
	}

	h.record(r, EventAdminUserUnsuspended, target, "", opUserID(r))

	user, err := h.Users.GetByID(r.Context(), target.ID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, adminActionDTO{User: newAdminUserDTO(user, time.Now())})
}

// RevokeSessions revokes every session an account holds:
// POST /v1/admin/users/{userID}/revoke-sessions.
//
// The engine's own RevokeAllForUser is the operation; the handler
// exists because the CLI reaches the same store directly and a console
// has no other road to it. The response reports how many sessions were
// live when the call landed, which is the number an operator reads
// rather than a count they would have to derive from a before-and-after
// diff.
func (h *UserActionHandlers) RevokeSessions(w http.ResponseWriter, r *http.Request, userID string) {
	target, ok := h.requireUser(w, r, userID)
	if !ok {
		return
	}
	if h.Sessions == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	sessions, err := h.Sessions.ListByUser(r.Context(), target.ID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := h.Sessions.RevokeAllForUser(r.Context(), target.ID); err != nil {
		writeErr(w, err)
		return
	}

	h.record(r, EventAdminSessionsRevoked, target, "", opUserID(r))

	writeData(w, http.StatusOK, adminActionDTO{
		User:   newAdminUserDTO(target, time.Now()),
		Detail: fmt.Sprintf("%d live session(s) revoked", len(sessions)),
	})
}

// DisableTOTP removes an account's second factor without the account
// holder's password: POST /v1/admin/users/{userID}/mfa/disable.
//
// The engine's own DisableTOTP requires the account holder's password,
// because it exists for the account holder changing their own settings,
// and an operator acting on somebody else's account has no password to
// give. The CLI reaches the TOTP store directly for the same reason.
// The compromise here is narrow: the operator's action is gated behind
// RequireAdmin, recorded in the audit trail with their id alongside the
// engine's own EventTOTPDisabled shape (the store.Delete plus an
// audited event, so the account's history reads the same either way),
// and the account's sessions are revoked with the enrolment, so whoever
// held the device the secret was on cannot keep the access it was
// protecting. A fresh login after that needs the password again.
func (h *UserActionHandlers) DisableTOTP(w http.ResponseWriter, r *http.Request, userID string) {
	target, ok := h.requireUser(w, r, userID)
	if !ok {
		return
	}
	if h.TOTP == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	if err := h.TOTP.Delete(r.Context(), target.ID); err != nil {
		writeErr(w, err)
		return
	}
	if h.Sessions != nil {
		if err := h.Sessions.RevokeAllForUser(r.Context(), target.ID); err != nil {
			writeErr(w, err)
			return
		}
	}

	h.record(r, EventAdminTOTPDisabled, target, "", opUserID(r))

	user, err := h.Users.GetByID(r.Context(), target.ID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, adminActionDTO{User: newAdminUserDTO(user, time.Now())})
}

// Unlink removes one OAuth identity from an account without the user's
// consent or participation: DELETE /v1/admin/users/{userID}/oauth/{provider}.
//
// The CLI's oauth unlink reaches the table directly; this is the same
// operation behind the admin gate and an audit event. The identity is
// found by listing the account's identities and matching provider, so
// a provider the account never linked is a 404 rather than a silent
// success, and the identity id (not the provider name) is what Unlink
// takes, which keeps the delete pinned to one row.
func (h *UserActionHandlers) UnlinkOAuth(w http.ResponseWriter, r *http.Request, userID, provider string) {
	target, ok := h.requireUser(w, r, userID)
	if !ok {
		return
	}
	if h.OAuth == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	identities, err := h.OAuth.ListByUser(r.Context(), target.ID)
	if err != nil {
		writeErr(w, err)
		return
	}
	var identity *store.OAuthIdentity
	for i := range identities {
		if identities[i].Provider == provider {
			identity = &identities[i]
			break
		}
	}
	if identity == nil {
		writeErr(w, store.ErrNotFound)
		return
	}

	if err := h.OAuth.Unlink(r.Context(), identity.ID); err != nil {
		writeErr(w, err)
		return
	}

	h.record(r, EventAdminOAuthUnlinked, target, provider, opUserID(r))

	writeData(w, http.StatusOK, adminActionDTO{User: newAdminUserDTO(target, time.Now()), Detail: "unlinked " + provider})
}
