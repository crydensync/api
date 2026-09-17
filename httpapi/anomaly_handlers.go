package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2/store"

	"github.com/crydensync/api/anomalyreview"
)

// AnomalyHandlers answers the flagged-event review queue: what the engine
// flagged, and what a human decided about it.
//
// This is the third write on the admin surface, next to the per-user
// metadata block and the settings block, and it is the same shape as the
// first: an explicit operator action on a named thing, taken by hand.
// CLAUDE.md's read-only rule is about the AI-assisted tools — which are
// read-only because the interfaces they are built from carry no method
// that can act — and nothing here is reachable from one of them. A review
// is a console action or it does not happen.
//
// What "review" means here is deliberately narrow. Confirming an event
// records that a person judged it real and does nothing else: no account
// is locked, no session is revoked, no rule is tuned. This repo has no
// machinery that acts on an account beyond what an operator does by hand,
// and inventing one behind a "confirm" button is exactly the automatic
// action the rule forbids.
type AnomalyHandlers struct {
	// Audit is the engine's own audit store, the same instance main.go
	// handed cryden. cryden has no "flagged events" list — it records the
	// events and moves on — so the queue is built from the two event
	// types it writes when something trips.
	Audit store.AuditStore

	// Reviews is this repo's own table (migrations/014), keyed on the
	// audit event id. cryden has no concept of a person having read one
	// of its events; see anomalyreview's package doc.
	Reviews anomalyreview.Store
}

// anomalyEventTypes is the queue, in one place: the two event types cryden
// writes when a login looks wrong rather than merely failing.
//
// Both carry a "signals" key naming what tripped, which is what makes them
// reviewable — an operator can read the event and form a judgement. Widening
// this to the failure events around them (login_failed, token_reuse_detected)
// would not make a bigger queue, it would make the audit table the queue,
// and a review surface that asks about everything asks about nothing.
var anomalyEventTypes = []store.AuditEventType{
	store.EventAnomalyDetected,
	store.EventCredentialStuffingDetected,
}

// anomalyReviewDTO is the human half of a queue row.
//
// An event with no row in reviewed_anomalies reads as unreviewed rather
// than as absent, and the two are the same thing by design: the store
// keeps an unreviewed row when a judgement is withdrawn, and this endpoint
// reports the same status whether that row exists or the event has simply
// never been looked at. ReviewerID and UpdatedAt are therefore omitted for
// an event nobody has called — there is no reviewer and no decision time
// to report, and a zero timestamp would be a date an operator could read
// as a very old decision.
type anomalyReviewDTO struct {
	// Status is "unreviewed", "confirmed" or "dismissed" — see
	// anomalyreview.Status. Always present.
	Status string `json:"status"`

	// Note is the reviewer's remark. Always present, empty when there is
	// none, so a console has one field to render.
	Note string `json:"note"`

	ReviewerID string     `json:"reviewer_id,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

func newAnomalyReviewDTO(r anomalyreview.Review, ok bool) anomalyReviewDTO {
	if !ok {
		return anomalyReviewDTO{Status: string(anomalyreview.StatusUnreviewed)}
	}
	updated := r.UpdatedAt
	return anomalyReviewDTO{
		Status:     string(r.Status),
		Note:       r.Note,
		ReviewerID: r.ReviewerID,
		UpdatedAt:  &updated,
	}
}

// anomalyDTO is one queue row: the engine's event, plus what a human said
// about it.
//
// The event's own fields are the audit event's, unchanged — including
// Metadata, which carries cryden's "signals" vocabulary. The review is
// nested rather than flattened so the two halves stay visibly separate: a
// console reading this row can tell which parts cryden wrote and which
// parts this deployment did, and the distinction survives somebody adding
// a field to the top level later.
type anomalyDTO struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	UserID    string            `json:"user_id,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`

	Review anomalyReviewDTO `json:"review"`
}

// anomalyListDTO is the queue page.
type anomalyListDTO struct {
	Anomalies []anomalyDTO `json:"anomalies"`
	Limit     int          `json:"limit"`
	Offset    int          `json:"offset"`

	// Status is the filter that was applied, or "" for the whole queue.
	Status string `json:"status,omitempty"`

	// HasMore says this page came back full, so there MAY be more — a
	// console should ask again rather than assume the queue ends here.
	//
	// It is deliberately not "there IS more". Deciding that exactly would
	// mean knowing the union's total size, and the two fetches below give
	// a window per type rather than a total. A page that comes back short
	// of limit IS the end — the merged window is an exact prefix of the
	// union, not a sample of it, so nothing was left behind — but a full
	// page can be the last one, and saying so would be a claim this
	// endpoint cannot support.
	HasMore bool `json:"has_more"`
}

// List — admin required. A page of flagged events, newest first, each with
// its review status, optionally filtered to one status.
//
// Read-only: it calls SearchByType and StatusesFor and writes nothing.
func (h *AnomalyHandlers) List(w http.ResponseWriter, r *http.Request) {
	if h.Audit == nil || h.Reviews == nil {
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

	// An absent status and an empty one are the same thing, matching how
	// the user list treats `q`: `?status=` is a filter nobody filled in,
	// not a filter for the empty status.
	status := anomalyreview.Status(queryString(r, "status"))
	if status != "" {
		if err := anomalyreview.ValidateStatus(status); err != nil {
			writeBadRequest(w, fmt.Sprintf("status must be one of %s", statusList()))
			return
		}
	}

	// SearchByType takes a limit and no offset, so paging a merged list
	// means over-fetching the window and slicing it here: every row of the
	// union's first limit+offset is inside its own type's first
	// limit+offset, so this prefix is exact rather than approximate.
	//
	// The window is bounded by maxListLimit and a larger one is refused
	// rather than clamped — the repo's usual rule, and it bites harder
	// here: clamping would silently return a page from further up the
	// queue than the caller asked for, which on a review queue means
	// showing an operator events they have already dealt with.
	window := limit + offset
	if window > maxListLimit {
		writeBadRequest(w, fmt.Sprintf(
			"limit + offset must be at most %d: this queue is merged from %d event types, so it cannot page past what it can fetch",
			maxListLimit, len(anomalyEventTypes)))
		return
	}

	ctx := r.Context()

	merged := make([]store.AuditEvent, 0, window*len(anomalyEventTypes))
	for _, eventType := range anomalyEventTypes {
		events, err := h.Audit.SearchByType(ctx, eventType, window)
		if err != nil {
			writeErr(w, err)
			return
		}
		merged = append(merged, events...)
	}

	sortAnomalies(merged)

	page := slicePage(merged, offset, limit)

	// One batch lookup rather than one per row: a page is up to
	// maxListLimit events and a query each would make the queue's cost
	// track its page size for no reason.
	ids := make([]string, 0, len(page))
	for _, e := range page {
		ids = append(ids, e.ID)
	}
	reviews, err := h.Reviews.StatusesFor(ctx, ids)
	if err != nil {
		writeErr(w, err)
		return
	}

	// A status filter is applied after the lookup rather than in the
	// query, because the status lives in this repo's table and the events
	// live in cryden's — there is no join to push it into without writing
	// SQL across the boundary. So a filtered page can come back short
	// while HasMore is still true: the page was full before the filter
	// ran, and the caller asks again with a larger offset. HasMore is
	// measured on the unfiltered page for exactly that reason — a filtered
	// short page must not read as the end of the queue.
	rows := make([]anomalyDTO, 0, len(page))
	for _, e := range page {
		review, found := reviews[e.ID]

		// An event with no row is unreviewed, so the filter has to compare
		// against the same default the response reports rather than
		// against what the store happened to return. Filtering on
		// "the store has a row with this status" would make the
		// status=unreviewed tab empty — which is the one tab an operator
		// opens first.
		effective := anomalyreview.StatusUnreviewed
		if found {
			effective = review.Status
		}
		if status != "" && effective != status {
			continue
		}

		rows = append(rows, anomalyDTO{
			ID:        e.ID,
			Type:      string(e.Type),
			UserID:    e.UserID,
			IP:        e.IP,
			Metadata:  e.Metadata,
			CreatedAt: e.CreatedAt,
			Review:    newAnomalyReviewDTO(review, found),
		})
	}

	writeData(w, http.StatusOK, anomalyListDTO{
		Anomalies: rows,
		Limit:     limit,
		Offset:    offset,
		Status:    string(status),
		HasMore:   len(page) == limit,
	})
}

// Review — admin required. Records what the calling operator decided about
// one flagged event.
//
// Keyed on the audit event id, which is what a console has in hand and
// what the engine's own record is filed under. The body is
// {"status": ..., "note": ...}; the note is optional and the status is
// not, because a review whose decision is missing is not a review.
//
// There is no DELETE. "Actually, never mind" is status=unreviewed, which
// keeps the row and the attribution — the record that somebody looked and
// then thought better of it is worth more than the tidier table a delete
// would leave. See anomalyreview.StatusUnreviewed.
func (h *AnomalyHandlers) Review(w http.ResponseWriter, r *http.Request, eventID string) {
	if h.Reviews == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	// A path segment that cannot be an event id is answered 404, the same
	// as one that simply is not an event — and for the second reason the
	// metadata routes give as well: a malformed id handed to Postgres is a
	// driver error that mapError would turn into a 500 an operator reads
	// as a bug. The sentinel is the anomaly one rather than store.ErrNotFound
	// so the body names what was missing: an audit event, not a user.
	if !looksLikeUUID(eventID) {
		writeErr(w, anomalyreview.ErrNoSuchEvent)
		return
	}

	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}
	if req.Status == "" {
		writeBadRequest(w, fmt.Sprintf(`status is required — send {"status": "confirmed"} or one of %s`, statusList()))
		return
	}

	// The reviewer is the authenticated operator, taken from the verified
	// token and never from the body: a caller does not get to say who
	// decided this, the same way they do not get to say who they are.
	review, err := h.Reviews.Set(r.Context(), eventID, anomalyreview.Status(req.Status), req.Note, UserIDFromContext(r))
	if err != nil {
		writeErr(w, err)
		return
	}

	// The review alone, not the whole queue row. Re-reading the event
	// would mean a lookup by event id, and the engine has none — the event
	// is fetched by type, so the only way to find this one again would be
	// to page the queue until it turned up. So a save returns the decision
	// rather than pretending to return the row it belongs to, and a console
	// refreshes the list it already has.
	writeData(w, http.StatusOK, newAnomalyReviewDTO(review, true))
}

// sortAnomalies orders the merged queue newest first.
//
// The id tie-break is not a second ordering anybody wants — it is there
// because two events recorded in the same instant (a stuffing burst writes
// several in one transaction) would otherwise come back in whichever order
// the database happened to return them, and a queue that reshuffles itself
// between two identical requests is one an operator cannot page through.
func sortAnomalies(events []store.AuditEvent) {
	sort.Slice(events, func(i, j int) bool {
		if !events[i].CreatedAt.Equal(events[j].CreatedAt) {
			return events[i].CreatedAt.After(events[j].CreatedAt)
		}
		return events[i].ID < events[j].ID
	})
}

// slicePage applies offset and limit to an already-ordered list, with an
// offset past the end reading as an empty page rather than a panic.
func slicePage(events []store.AuditEvent, offset, limit int) []store.AuditEvent {
	if offset >= len(events) {
		return nil
	}
	events = events[offset:]
	if len(events) > limit {
		events = events[:limit]
	}
	return events
}

// statusList renders the defined statuses for an error message, so the
// message cannot drift from the set the store accepts.
func statusList() string {
	statuses := anomalyreview.Statuses()
	names := make([]string, 0, len(statuses))
	for _, s := range statuses {
		names = append(names, string(s))
	}
	return strings.Join(names, ", ")
}
