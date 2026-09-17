package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store"
)

// UserHandlers answers the admin user surface: finding an account, and
// reading the state of one.
//
// This is the one place in this API where an operator can see an account
// that is not their own, so what is *not* here matters as much as what is.
// Two things are deliberately absent:
//
//   - PasswordHash. It is on the store.User every handler here receives —
//     this repo does not get to choose what cryden's struct carries — so
//     it is left out at the DTO boundary and never reaches a response.
//     TestAdminUserResponsesNeverCarryAPasswordHash asserts that against
//     the raw body, because a struct tag is not a guarantee.
//   - Anything that changes an account. There is no lock, no unlock, no
//     password reset and no delete on this surface. cryden exposes
//     LockAccount on the store, and wiring it to a button would make this
//     repo the thing that can lock somebody out of their account; an
//     operator who needs that has the engine's own admin path, not an
//     HTTP endpoint this repo invented. The detail view reports lockout
//     state so it can be diagnosed, and stops there.
type UserHandlers struct {
	// Engine is used for exactly one call: cryden.GetUser, the engine's
	// own public facade for an exact-email lookup. Reaching for
	// h.Users.GetByEmail directly would work and would be the wrong
	// choice — the facade is the engine's stated interface for this, and
	// it is the one that keeps working if the lookup grows a step.
	Engine *cryden.Engine

	// Users, Sessions and Audit are the same store instances main.go
	// handed cryden, for the reason httpapi.Deps gives: a report over a
	// second store object is a report over different data.
	Users    store.UserStore
	Sessions store.SessionStore
	Audit    store.AuditStore
}

// userActivityLimit is how much of an account's audit history the detail
// view returns. A console detail pane, not an export: the full history is
// paginated by nothing here, and returning "everything that ever happened
// to this account" is a response whose size is chosen by whoever attacked
// it hardest.
const userActivityLimit = 20

// adminUserDTO is one account as the console sees it.
//
// Locked is computed rather than mirrored from LockedUntil, and that is
// the one subtle thing here: cryden clears a lockout by time passing, not
// by writing a null, so a row can carry a locked_until that is already in
// the past. Reporting `locked: true` for a non-nil locked_until would tell
// an operator an account is locked out when it is not — and the ones that
// look like that are exactly the ones somebody just waited out.
type adminUserDTO struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	FailedAttempts int        `json:"failed_attempts"`
	Locked         bool       `json:"locked"`
	LockedUntil    *time.Time `json:"locked_until"`
}

func newAdminUserDTO(u store.User, now time.Time) adminUserDTO {
	return adminUserDTO{
		ID:             u.ID,
		Email:          u.Email,
		CreatedAt:      u.CreatedAt,
		UpdatedAt:      u.UpdatedAt,
		FailedAttempts: u.FailedAttempts,
		Locked:         u.LockedUntil != nil && u.LockedUntil.After(now),
		LockedUntil:    u.LockedUntil,
	}
}

// auditEventDTO is one recorded event, as an operator reads it.
//
// Metadata is passed through as the engine stored it rather than
// reshaped: its keys are cryden's ("signals", "distinct_accounts",
// "from"/"to"), they differ per event type, and a host that renamed them
// would be inventing a second vocabulary for the engine's own records.
type auditEventDTO struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	IP        string            `json:"ip,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

func newAuditEventDTO(e store.AuditEvent) auditEventDTO {
	return auditEventDTO{
		ID:        e.ID,
		Type:      string(e.Type),
		IP:        e.IP,
		Metadata:  e.Metadata,
		CreatedAt: e.CreatedAt,
	}
}

// The two ways a list can have been produced, echoed in the response so a
// console can label the result honestly.
const (
	// userMatchExactEmail means the list is the single account whose
	// email equals the query, byte for byte.
	userMatchExactEmail = "exact_email"
	// userMatchBrowse means no query was given and the list is a page of
	// every account, newest first.
	userMatchBrowse = "browse"
)

type adminUserListDTO struct {
	Users  []adminUserDTO `json:"users"`
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`

	// Match is "exact_email" or "browse" — see above. It is in the
	// response because the difference is otherwise invisible and the
	// surprising half of it is worth stating: the email match is exact
	// AND case-sensitive, because cryden stores addresses as typed and
	// compares them with SQL's `=`, so "Alice@example.com" does not find
	// an account created as "alice@example.com". A console that shows
	// "exact email match" beside the result tells an operator why their
	// search found nothing instead of leaving them to conclude the
	// account is gone.
	Match string `json:"match"`

	// Query is the search that produced this page, empty when browsing.
	Query string `json:"query"`
}

// List — admin required. Two modes, chosen by whether `q` is present:
// an exact-email lookup, or a page of every account newest-first.
//
// The exact-email mode calls cryden.GetUser rather than searching. There
// is no partial or case-insensitive search here, and that is a decision
// rather than a gap: partial search would mean SQL against cryden's own
// users table, which crosses the ownership boundary this repo has kept
// everywhere else (see CLAUDE.md) — the engine owns that table, and a
// query this repo wrote against it would be a second, silent definition
// of what a user is. If partial search is wanted later it is its own
// deliberate piece of work.
func (h *UserHandlers) List(w http.ResponseWriter, r *http.Request) {
	if h.Users == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	limit, err := queryLimit(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	offset, err := queryOffset(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	// An absent `q` and an empty one are the same thing, matching how
	// queryInt treats an empty numeric parameter: `?q=` is not a search
	// for the empty string, it is a search nobody filled in.
	query := queryString(r, "q")
	if query == "" {
		h.browse(w, r, limit, offset)
		return
	}
	h.exactEmail(w, r, query, limit, offset)
}

func (h *UserHandlers) browse(w http.ResponseWriter, r *http.Request, limit, offset int) {
	ctx := r.Context()

	total, err := h.Users.Count(ctx)
	if err != nil {
		writeErr(w, err)
		return
	}
	users, err := h.Users.ListAll(ctx, limit, offset)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, h.listDTO(users, total, limit, offset, userMatchBrowse, ""))
}

func (h *UserHandlers) exactEmail(w http.ResponseWriter, r *http.Request, query string, limit, offset int) {
	if h.Engine == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	// An exact match is one account or none, so `limit` and `offset` are
	// echoed rather than obeyed — there is nothing to page. They are not
	// rejected either: a console that keeps its page size fixed while
	// switching between searching and browsing is doing nothing wrong.
	user, err := cryden.GetUser(r.Context(), h.Engine, query)
	if err != nil {
		// No such account is an empty result, not a 404. A search that
		// found nothing succeeded; answering 404 would make a console
		// render "error" for the most ordinary outcome a search has.
		if errors.Is(err, store.ErrNotFound) {
			writeData(w, http.StatusOK, h.listDTO(nil, 0, limit, offset, userMatchExactEmail, query))
			return
		}
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, h.listDTO([]store.User{user}, 1, limit, offset, userMatchExactEmail, query))
}

func (h *UserHandlers) listDTO(users []store.User, total, limit, offset int, match, query string) adminUserListDTO {
	now := time.Now()
	// Non-nil even for no results, so a console ranges over an empty list
	// and the JSON renders [] rather than null.
	out := make([]adminUserDTO, 0, len(users))
	for _, u := range users {
		out = append(out, newAdminUserDTO(u, now))
	}
	return adminUserListDTO{
		Users:  out,
		Total:  total,
		Limit:  limit,
		Offset: offset,
		Match:  match,
		Query:  query,
	}
}

type adminUserDetailDTO struct {
	User adminUserDTO `json:"user"`

	// ActiveSessions is a count, not a list, and that restraint is the
	// point. cryden's SessionStore.ListByUser returns only live sessions
	// (revoked_at IS NULL), so the count is honest; listing them would
	// publish every IP and user agent an account has signed in from to
	// anyone holding an operator token. The support assistant reports
	// aggregates for the same reason. An operator who needs the devices
	// themselves needs a deliberate endpoint that says so in its name.
	ActiveSessions int `json:"active_sessions"`

	// RecentActivity is the account's own audit history, newest first,
	// capped at userActivityLimit.
	RecentActivity []auditEventDTO `json:"recent_activity"`
}

// Detail — admin required. One account's state, its live session count,
// and the most recent events recorded against it.
//
// Read-only, like everything else on this surface that is not an explicit
// operator write: it reports a lockout and cannot clear one.
func (h *UserHandlers) Detail(w http.ResponseWriter, r *http.Request, userID string) {
	// A path segment that cannot be a user id is answered 404, the same
	// as one that is simply not a user — see MetadataHandlers.ready for
	// the full reason (a malformed id reaching Postgres is a driver
	// error, which mapError turns into a 500 an operator reads as a bug).
	if !looksLikeUUID(userID) {
		writeErr(w, store.ErrNotFound)
		return
	}
	if h.Users == nil || h.Sessions == nil || h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	ctx := r.Context()

	user, err := h.Users.GetByID(ctx, userID)
	if err != nil {
		writeErr(w, err)
		return
	}

	sessions, err := h.Sessions.ListByUser(ctx, userID)
	if err != nil {
		writeErr(w, err)
		return
	}

	events, err := h.Audit.ListByUser(ctx, userID, userActivityLimit)
	if err != nil {
		writeErr(w, err)
		return
	}
	activity := make([]auditEventDTO, 0, len(events))
	for _, e := range events {
		activity = append(activity, newAuditEventDTO(e))
	}

	writeData(w, http.StatusOK, adminUserDetailDTO{
		User:           newAdminUserDTO(user, time.Now()),
		ActiveSessions: len(sessions),
		RecentActivity: activity,
	})
}
