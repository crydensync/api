package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"

	"github.com/crydensync/api/anomalyreview"
	"github.com/crydensync/api/config"
	"github.com/crydensync/api/usermeta"
)

// anomalyFixture is the user fixture with the review store wired in and a
// router rebuilt to carry it, so the queue endpoints are reachable. It
// reuses the user fixture rather than building a second engine because the
// audit store is the point: this surface reads the events that fixture
// already records, through the same id-assigning double the user detail
// view needs.
type anomalyFixture struct {
	userFixture
	reviews *anomalyreview.MemoryStore
}

func newAnomalyFixture(t *testing.T) anomalyFixture {
	t.Helper()
	f := newUserFixture(t)
	reviews := anomalyreview.NewMemoryStore()
	f.router = NewRouter(Deps{
		Engine:   f.engine,
		Config:   config.Config{},
		Users:    f.users,
		Sessions: f.sessions,
		Audit:    f.audit,
		Meta:     usermeta.NewMemoryStore(),
		Reviews:  reviews,
	})
	return anomalyFixture{userFixture: f, reviews: reviews}
}

// recordFlagged records one flagged event and returns its audit id.
//
// The id is read back out of the audit store rather than predicted,
// because the fixture's double assigns them from a counter that cryden's
// own signup and login calls also advance — a test that hard-coded "the
// next one is 5" would break the moment the fixture's setup changed, and
// break by reviewing a different event rather than by failing outright.
func (f anomalyFixture) recordFlagged(t *testing.T, eventType store.AuditEventType, metadata map[string]string) string {
	t.Helper()
	ctx := context.Background()

	if err := f.audit.Record(ctx, store.AuditEvent{
		Type:     eventType,
		UserID:   f.userID,
		IP:       "203.0.113.9",
		Metadata: metadata,
	}); err != nil {
		t.Fatalf("recording %s: %v", eventType, err)
	}

	// Newest of that type, which is the one just recorded.
	events, err := f.audit.SearchByType(ctx, eventType, 1)
	if err != nil {
		t.Fatalf("reading back %s: %v", eventType, err)
	}
	if len(events) != 1 {
		t.Fatalf("reading back %s: got %d events, want the one just recorded", eventType, len(events))
	}
	return events[0].ID
}

// declare makes the review store accept a review of this event, standing
// in for the foreign key Postgres enforces against audit_events. See
// anomalyreview.MemoryStore.RegisterEvents.
func (f anomalyFixture) declare(eventID string) {
	f.reviews.RegisterEvents(eventID)
}

// get and put hang off userFixture rather than anomalyFixture because the
// "router built without these stores" test needs them on a fixture that has
// no review store at all. anomalyFixture embeds userFixture, so both work
// from either.
func (f userFixture) get(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	return f.call(t, http.MethodGet, path, token)
}

func (f userFixture) put(t *testing.T, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

type anomalyListResponse struct {
	Data struct {
		Anomalies []struct {
			ID        string            `json:"id"`
			Type      string            `json:"type"`
			UserID    string            `json:"user_id"`
			IP        string            `json:"ip"`
			Metadata  map[string]string `json:"metadata"`
			CreatedAt time.Time         `json:"created_at"`
			Review    struct {
				Status     string     `json:"status"`
				Note       string     `json:"note"`
				ReviewerID string     `json:"reviewer_id"`
				UpdatedAt  *time.Time `json:"updated_at"`
			} `json:"review"`
		} `json:"anomalies"`
		Limit   int    `json:"limit"`
		Offset  int    `json:"offset"`
		Status  string `json:"status"`
		HasMore bool   `json:"has_more"`
	} `json:"data"`
}

type anomalyReviewResponse struct {
	Data struct {
		Status     string     `json:"status"`
		Note       string     `json:"note"`
		ReviewerID string     `json:"reviewer_id"`
		UpdatedAt  *time.Time `json:"updated_at"`
	} `json:"data"`
}

func decodeAnomalyList(t *testing.T, rec *httptest.ResponseRecorder) anomalyListResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp anomalyListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// The queue is both flagged types merged, newest first — not one type, and
// not two concatenated lists. A console that showed anomalies and stuffing
// separately would make an operator check two places for one incident.
func TestAnomalyListMergesBothFlaggedTypesNewestFirst(t *testing.T) {
	f := newAnomalyFixture(t)

	oldest := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_ip"})
	middle := f.recordFlagged(t, store.EventCredentialStuffingDetected, map[string]string{"signals": "account_spray"})
	newest := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "token_reuse"})

	got := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies", f.opToken))

	if len(got.Data.Anomalies) != 3 {
		t.Fatalf("got %d anomalies, want 3: %+v", len(got.Data.Anomalies), got.Data.Anomalies)
	}
	want := []string{newest, middle, oldest}
	for i, id := range want {
		if got.Data.Anomalies[i].ID != id {
			t.Errorf("anomalies[%d].id = %s, want %s (newest first)", i, got.Data.Anomalies[i].ID, id)
		}
	}
	if got.Data.Anomalies[1].Type != string(store.EventCredentialStuffingDetected) {
		t.Errorf("anomalies[1].type = %s, want the stuffing event between the two anomalies", got.Data.Anomalies[1].Type)
	}
}

// An event nobody has looked at reads as unreviewed and carries no reviewer
// and no decision time. A zero timestamp here would be a date an operator
// could read as a very old decision.
func TestAnomalyListReportsAnUnreviewedEventAsUnreviewed(t *testing.T) {
	f := newAnomalyFixture(t)
	f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_device"})

	got := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies", f.opToken))

	review := got.Data.Anomalies[0].Review
	if review.Status != string(anomalyreview.StatusUnreviewed) {
		t.Errorf("status = %q, want unreviewed", review.Status)
	}
	if review.ReviewerID != "" {
		t.Errorf("reviewer_id = %q, want it omitted for an event nobody has called", review.ReviewerID)
	}
	if review.UpdatedAt != nil {
		t.Errorf("updated_at = %v, want it omitted", review.UpdatedAt)
	}
}

// The engine's own metadata is passed through untouched — "signals" is
// cryden's key and this repo has no second vocabulary for it.
func TestAnomalyListPassesTheEnginesMetadataThrough(t *testing.T) {
	f := newAnomalyFixture(t)
	f.recordFlagged(t, store.EventCredentialStuffingDetected, map[string]string{
		"signals":           "account_spray",
		"distinct_accounts": "17",
		"unknown_targets":   "3",
	})

	got := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies", f.opToken))

	metadata := got.Data.Anomalies[0].Metadata
	for key, want := range map[string]string{"signals": "account_spray", "distinct_accounts": "17", "unknown_targets": "3"} {
		if metadata[key] != want {
			t.Errorf("metadata[%q] = %q, want %q", key, metadata[key], want)
		}
	}
}

// A review is attached to the event it was made about, and reads back on
// the queue without the event itself changing.
func TestReviewingAnEventShowsUpOnTheQueue(t *testing.T) {
	f := newAnomalyFixture(t)
	eventID := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_ip"})
	f.declare(eventID)

	rec := f.put(t, "/v1/admin/anomalies/"+eventID, f.opToken, `{"status":"confirmed","note":"real, from the office VPN"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("review status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var reviewed anomalyReviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &reviewed); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	if reviewed.Data.Status != "confirmed" {
		t.Errorf("status = %q, want confirmed", reviewed.Data.Status)
	}
	if reviewed.Data.Note != "real, from the office VPN" {
		t.Errorf("note = %q, want the note that was sent", reviewed.Data.Note)
	}
	// The reviewer is the authenticated operator, taken from the token
	// rather than the body — a caller does not get to say who decided.
	if reviewed.Data.ReviewerID != f.opID {
		t.Errorf("reviewer_id = %q, want the calling operator %q", reviewed.Data.ReviewerID, f.opID)
	}
	if reviewed.Data.UpdatedAt == nil {
		t.Error("updated_at missing on a recorded review")
	}

	got := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies", f.opToken))
	if got.Data.Anomalies[0].Review.Status != "confirmed" {
		t.Errorf("queue status = %q, want confirmed", got.Data.Anomalies[0].Review.Status)
	}
	if got.Data.Anomalies[0].Review.Note != "real, from the office VPN" {
		t.Errorf("queue note = %q, want the note that was sent", got.Data.Anomalies[0].Review.Note)
	}
}

// Dismissing keeps the row. The decision is a status, not a delete, and
// withdrawing it is a third status rather than an absence — so the record
// that an operator looked, and who they were, survives the change of mind.
func TestDismissingAndWithdrawingBothKeepTheRow(t *testing.T) {
	f := newAnomalyFixture(t)
	eventID := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_ip"})
	f.declare(eventID)

	if rec := f.put(t, "/v1/admin/anomalies/"+eventID, f.opToken, `{"status":"dismissed"}`); rec.Code != http.StatusOK {
		t.Fatalf("dismiss status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if status, ok := f.reviews.Status(eventID); !ok || status != anomalyreview.StatusDismissed {
		t.Fatalf("stored status = %q (present %v), want dismissed", status, ok)
	}

	// Withdrawing the judgement stores unreviewed rather than removing
	// the row.
	if rec := f.put(t, "/v1/admin/anomalies/"+eventID, f.opToken, `{"status":"unreviewed"}`); rec.Code != http.StatusOK {
		t.Fatalf("withdraw status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if f.reviews.Len() != 1 {
		t.Fatalf("review rows = %d, want 1 — withdrawing a judgement keeps the row", f.reviews.Len())
	}
	if status, ok := f.reviews.Status(eventID); !ok || status != anomalyreview.StatusUnreviewed {
		t.Errorf("stored status = %q (present %v), want unreviewed", status, ok)
	}

	got := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies", f.opToken))
	if got.Data.Anomalies[0].Review.Status != "unreviewed" {
		t.Errorf("queue status = %q, want unreviewed", got.Data.Anomalies[0].Review.Status)
	}
}

// The event cryden recorded is not touched by a review. Nothing in this api
// rewrites the engine's audit history — that is the evidence the review is
// about.
func TestReviewingAnEventDoesNotChangeTheEvent(t *testing.T) {
	f := newAnomalyFixture(t)
	eventID := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_ip"})
	f.declare(eventID)

	before, err := f.audit.SearchByType(context.Background(), store.EventAnomalyDetected, 1)
	if err != nil {
		t.Fatalf("reading the event: %v", err)
	}
	beforeCount := countAnomalies(t, f)

	if rec := f.put(t, "/v1/admin/anomalies/"+eventID, f.opToken, `{"status":"dismissed","note":"scanner"}`); rec.Code != http.StatusOK {
		t.Fatalf("review status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	after, err := f.audit.SearchByType(context.Background(), store.EventAnomalyDetected, 1)
	if err != nil {
		t.Fatalf("re-reading the event: %v", err)
	}
	if after[0].ID != before[0].ID || !after[0].CreatedAt.Equal(before[0].CreatedAt) {
		t.Error("the audit event changed; a review must not rewrite the engine's own record")
	}
	if after[0].Metadata["signals"] != "new_ip" {
		t.Errorf("metadata = %v, want it untouched", after[0].Metadata)
	}
	// A review is not an audit event: reviewing must not add one, or the
	// queue would grow every time somebody worked through it.
	if got := countAnomalies(t, f); got != beforeCount {
		t.Errorf("flagged events = %d after a review, want %d — a review is not an audit event", got, beforeCount)
	}
}

func countAnomalies(t *testing.T, f anomalyFixture) int {
	t.Helper()
	total := 0
	for _, eventType := range anomalyEventTypes {
		events, err := f.audit.SearchByType(context.Background(), eventType, 1000)
		if err != nil {
			t.Fatalf("counting %s: %v", eventType, err)
		}
		total += len(events)
	}
	return total
}

// A review of an event that does not exist is refused, not stored. The
// check comes from the store — in Postgres, from the foreign key against
// audit_events — so a console acting on a stale list is told.
func TestReviewingAnEventThatDoesNotExistIs404(t *testing.T) {
	f := newAnomalyFixture(t)

	// A well-formed id that names nothing.
	rec := f.put(t, "/v1/admin/anomalies/01a0a4ce-5453-78d3-9126-0000000000ff", f.opToken, `{"status":"dismissed"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "audit_event_not_found") {
		t.Errorf("body = %s, want audit_event_not_found", rec.Body.String())
	}
	if f.reviews.Len() != 0 {
		t.Errorf("review rows = %d, want 0 — a refused review stores nothing", f.reviews.Len())
	}
}

// A path segment that cannot be an event id is a 404, not the 500 a
// malformed uuid handed to Postgres would produce.
func TestReviewingAMalformedEventIDIs404(t *testing.T) {
	f := newAnomalyFixture(t)

	rec := f.put(t, "/v1/admin/anomalies/not-a-uuid", f.opToken, `{"status":"dismissed"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	// The body names what was missing: an audit event, not a user.
	if !strings.Contains(rec.Body.String(), "audit_event_not_found") {
		t.Errorf("body = %s, want audit_event_not_found rather than a user-shaped 404", rec.Body.String())
	}
}

func TestReviewRejectsABadBody(t *testing.T) {
	f := newAnomalyFixture(t)
	eventID := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_ip"})
	f.declare(eventID)

	path := "/v1/admin/anomalies/" + eventID
	for name, body := range map[string]string{
		"unknown status":  `{"status":"maybe"}`,
		"empty status":    `{"status":""}`,
		"no status":       `{"note":"looks fine"}`,
		"malformed json":  `{"status":`,
		"status not text": `{"status":42}`,
	} {
		rec := f.put(t, path, f.opToken, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", name, rec.Code, rec.Body.String())
		}
	}
	if f.reviews.Len() != 0 {
		t.Errorf("review rows = %d, want 0 after every request was refused", f.reviews.Len())
	}
}

// A note longer than the limit is refused with a code a console can branch
// on rather than a generic bad request.
func TestReviewRejectsAnOverlongNote(t *testing.T) {
	f := newAnomalyFixture(t)
	eventID := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_ip"})
	f.declare(eventID)

	body, err := json.Marshal(map[string]string{"status": "dismissed", "note": strings.Repeat("x", 501)})
	if err != nil {
		t.Fatalf("building the body: %v", err)
	}
	rec := f.put(t, "/v1/admin/anomalies/"+eventID, f.opToken, string(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_review_note") {
		t.Errorf("body = %s, want invalid_review_note", rec.Body.String())
	}
}

// The status filter narrows to one decision, and an unreviewed event is
// matched by status=unreviewed even though it has no row — which is the
// case a console's "needs attention" tab is built on.
func TestAnomalyListFiltersByStatus(t *testing.T) {
	f := newAnomalyFixture(t)

	confirmed := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_ip"})
	f.declare(confirmed)
	unreviewed := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_device"})
	f.declare(unreviewed)

	if rec := f.put(t, "/v1/admin/anomalies/"+confirmed, f.opToken, `{"status":"confirmed"}`); rec.Code != http.StatusOK {
		t.Fatalf("review status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	got := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies?status=confirmed", f.opToken))
	if len(got.Data.Anomalies) != 1 || got.Data.Anomalies[0].ID != confirmed {
		t.Fatalf("confirmed filter = %+v, want only the confirmed event", got.Data.Anomalies)
	}
	if got.Data.Status != "confirmed" {
		t.Errorf("status = %q, want the filter echoed", got.Data.Status)
	}

	// The event with no row at all is unreviewed.
	got = decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies?status=unreviewed", f.opToken))
	if len(got.Data.Anomalies) != 1 || got.Data.Anomalies[0].ID != unreviewed {
		t.Fatalf("unreviewed filter = %+v, want the event with no review row", got.Data.Anomalies)
	}

	// A status that is not one of the three is a 400, not an empty list —
	// an operator who mistyped should be told, not shown "nothing here".
	rec := f.get(t, "/v1/admin/anomalies?status=maybe", f.opToken)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad status: status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

// Paging walks the merged queue without repeating or dropping a row, which
// is the property the over-fetch-and-slice exists to provide: each type is
// fetched to limit+offset, so the merged window is an exact prefix.
func TestAnomalyListPagesTheMergedQueue(t *testing.T) {
	f := newAnomalyFixture(t)

	// Interleaved types, so a page boundary falls between two of them.
	var want []string
	for i := range 6 {
		eventType := store.EventAnomalyDetected
		if i%2 == 1 {
			eventType = store.EventCredentialStuffingDetected
		}
		want = append(want, f.recordFlagged(t, eventType, map[string]string{"signals": "new_ip"}))
	}
	// Newest first.
	for i, j := 0, len(want)-1; i < j; i, j = i+1, j-1 {
		want[i], want[j] = want[j], want[i]
	}

	var got []string
	for offset := 0; offset < len(want); offset += 2 {
		page := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies?limit=2&offset="+strconv.Itoa(offset), f.opToken))
		for _, a := range page.Data.Anomalies {
			got = append(got, a.ID)
		}
		if page.Data.Offset != offset || page.Data.Limit != 2 {
			t.Errorf("offset %d: echoed limit/offset = %d/%d, want 2/%d", offset, page.Data.Limit, page.Data.Offset, offset)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("paged %d events over three pages, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("paged[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

// Paging past what the merge can fetch is refused rather than clamped: a
// silently clamped offset would return a page from further up the queue
// than the caller asked for, which on a review queue means showing events
// they have already dealt with.
func TestAnomalyListRefusesAnOffsetBeyondWhatItCanFetch(t *testing.T) {
	f := newAnomalyFixture(t)

	rec := f.get(t, "/v1/admin/anomalies?limit=500&offset=1", f.opToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "limit + offset") {
		t.Errorf("body = %s, want the reason the window was refused", rec.Body.String())
	}
}

// A page that comes back short is the end of the queue; a full one is not
// a promise of more, only a reason to ask again.
func TestAnomalyListReportsWhetherToAskAgain(t *testing.T) {
	f := newAnomalyFixture(t)
	f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_ip"})

	full := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies?limit=1", f.opToken))
	if !full.Data.HasMore {
		t.Error("has_more = false on a full page, want true so a console asks again")
	}

	short := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies?limit=10", f.opToken))
	if short.Data.HasMore {
		t.Error("has_more = true on a short page, want false — the merged window is an exact prefix, so a short page is the end")
	}
}

// The queue is the two flagged types and nothing else. Widening it to the
// failure events around them would make the audit table the queue.
func TestAnomalyListExcludesOrdinaryFailureEvents(t *testing.T) {
	f := newAnomalyFixture(t)

	f.recordFlagged(t, store.EventLoginFailed, nil)
	f.recordFlagged(t, store.EventTokenReuseDetected, nil)
	flagged := f.recordFlagged(t, store.EventAnomalyDetected, map[string]string{"signals": "new_ip"})

	got := decodeAnomalyList(t, f.get(t, "/v1/admin/anomalies", f.opToken))
	if len(got.Data.Anomalies) != 1 || got.Data.Anomalies[0].ID != flagged {
		t.Fatalf("queue = %+v, want only the flagged event", got.Data.Anomalies)
	}
}

func TestAnomalyRoutesAreGatedByRequireAdmin(t *testing.T) {
	f := newAnomalyFixture(t)

	// The detail path is PUT-only — a single flagged event is read as part
	// of the queue, not on its own, because the engine has no lookup by
	// event id to serve one from.
	if rec := f.put(t, "/v1/admin/anomalies/01a0a4ce-5453-78d3-9126-0000000000ff", "", `{"status":"dismissed"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("PUT with no token: status = %d, want 401", rec.Code)
	}
	if rec := f.put(t, "/v1/admin/anomalies/01a0a4ce-5453-78d3-9126-0000000000ff", f.userToken, `{"status":"dismissed"}`); rec.Code != http.StatusForbidden {
		t.Errorf("PUT with an ordinary user's token: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
}

// A router built without the review store answers 404 — the feature is
// unavailable, not broken.
func TestAnomalyRoutesWithoutStoresAre404(t *testing.T) {
	f := newUserFixture(t)

	if rec := f.call(t, http.MethodGet, "/v1/admin/anomalies", f.opToken); rec.Code != http.StatusNotFound {
		t.Errorf("GET: status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	rec := f.put(t, "/v1/admin/anomalies/01a0a4ce-5453-78d3-9126-0000000000ff", f.opToken, `{"status":"dismissed"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("PUT: status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_configured") {
		t.Errorf("body = %s, want not_configured", rec.Body.String())
	}
}

// The merged order must be total, not merely newest-first: two events
// recorded in the same instant — a stuffing burst writes several in one
// transaction — would otherwise come back in whichever order the database
// happened to return them, and a queue that reshuffles between two
// identical requests cannot be paged through.
func TestSortAnomaliesBreaksTiesDeterministically(t *testing.T) {
	same := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	events := []store.AuditEvent{
		{ID: "01a0a4ce-5453-78d3-9126-00000000000c", CreatedAt: same},
		{ID: "01a0a4ce-5453-78d3-9126-00000000000a", CreatedAt: same},
		{ID: "01a0a4ce-5453-78d3-9126-00000000000b", CreatedAt: same},
	}

	sortAnomalies(events)

	for i, want := range []string{
		"01a0a4ce-5453-78d3-9126-00000000000a",
		"01a0a4ce-5453-78d3-9126-00000000000b",
		"01a0a4ce-5453-78d3-9126-00000000000c",
	} {
		if events[i].ID != want {
			t.Errorf("events[%d].id = %s, want %s", i, events[i].ID, want)
		}
	}

	// And a genuinely newer event still wins on time, so the tie-break is
	// a tie-break rather than the ordering.
	events = append(events, store.AuditEvent{
		ID:        "01a0a4ce-5453-78d3-9126-000000000000",
		CreatedAt: same.Add(time.Second),
	})
	sortAnomalies(events)
	if events[0].ID != "01a0a4ce-5453-78d3-9126-000000000000" {
		t.Errorf("events[0].id = %s, want the newest event first", events[0].ID)
	}
}
