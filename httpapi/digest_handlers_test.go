package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/admin"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/digest"
)

// digestResponse and digestHistoryResponse mirror the endpoints' DTOs
// field by field, so a renamed or dropped field fails here rather than
// silently changing the contract an operator's console reads.
type digestResponse struct {
	Data struct {
		Since      time.Time `json:"since"`
		Until      time.Time `json:"until"`
		WindowDays int       `json:"window_days"`
		Text       string    `json:"text"`
	} `json:"data"`
}

type digestHistoryResponse struct {
	Data struct {
		Runs []struct {
			ID          int64     `json:"id"`
			WindowStart time.Time `json:"window_start"`
			WindowEnd   time.Time `json:"window_end"`
			GeneratedAt time.Time `json:"generated_at"`
			Text        string    `json:"text"`
		} `json:"runs"`
		Count int `json:"count"`
		Limit int `json:"limit"`
	} `json:"data"`
}

type digestFixture struct {
	engine *cryden.Engine
	audit  *memory.AuditStore
	store  *digest.MemoryStore
	router http.Handler

	adminToken string
	userToken  string
}

// newDigestFixture builds the engine on in-memory stores, with the audit
// store held directly — the digest is a report on exactly that store, so
// the fixture is the only thing that can seed it and check what came back.
func newDigestFixture(t *testing.T) digestFixture {
	t.Helper()
	ctx := context.Background()

	audit := memory.NewAuditStore()
	store := digest.NewMemoryStore()
	var adminID string
	engine, err := cryden.New(cryden.Config{
		JWTSecret:       "test-secret",
		Users:           memory.NewUserStore(),
		Sessions:        memory.NewSessionStore(),
		Audit:           audit,
		Verifications:   memory.NewVerificationStore(),
		EmailSender:     stubMailSender{},
		MagicLinkSender: stubMailSender{},
		AccessTokenClaims: token.ClaimsFunc(func(_ context.Context, userID string) (map[string]any, error) {
			if userID == adminID {
				return map[string]any{"role": "admin"}, nil
			}
			return nil, nil
		}),
	})
	if err != nil {
		t.Fatalf("cryden.New on the in-memory stores: %v", err)
	}

	admin, err := cryden.SignUp(ctx, engine, "operator@example.com", testPassword, "203.0.113.1")
	if err != nil {
		t.Fatalf("signup (operator): %v", err)
	}
	adminID = admin.ID
	adminTokens, err := cryden.Login(ctx, engine, "operator@example.com", testPassword, "203.0.113.1", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (operator): %v", err)
	}

	const userEmail = "dana@example.com"
	if _, err := cryden.SignUp(ctx, engine, userEmail, testPassword, "203.0.113.2"); err != nil {
		t.Fatalf("signup (user): %v", err)
	}
	userTokens, err := cryden.Login(ctx, engine, userEmail, testPassword, "203.0.113.2", chromeOnMacOS)
	if err != nil {
		t.Fatalf("login (user): %v", err)
	}

	return digestFixture{
		engine:     engine,
		audit:      audit,
		store:      store,
		router:     NewRouter(Deps{Engine: engine, Audit: audit, Digests: store, Config: config.Config{}}),
		adminToken: adminTokens.AccessToken,
		userToken:  userTokens.AccessToken,
	}
}

func (f digestFixture) get(t *testing.T, path, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f digestFixture) digest(t *testing.T, token, query string) digestResponse {
	t.Helper()
	rec := f.get(t, "/v1/admin/digest", token, query)
	if rec.Code != http.StatusOK {
		t.Fatalf("digest: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp digestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

func (f digestFixture) history(t *testing.T, token, query string) digestHistoryResponse {
	t.Helper()
	rec := f.get(t, "/v1/admin/digest/history", token, query)
	if rec.Code != http.StatusOK {
		t.Fatalf("history: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp digestHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// record plants audit events of a type cryden does not define. That is
// what makes the assertions below exact: a host-specific type cannot
// collide with anything the engine records during signup and login, so
// the count in the report is this test's and nothing else's.
func (f digestFixture) record(t *testing.T, eventType store.AuditEventType, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := f.audit.Record(context.Background(), store.AuditEvent{Type: eventType}); err != nil {
			t.Fatalf("recording a %s event: %v", eventType, err)
		}
	}
}

// schedule runs the real Scheduler — the same object, on the same
// composition main.go builds — until it has recorded at least n digests,
// then stops it. Going through the scheduler rather than inserting rows by
// hand is the point: what these tests list is what the scheduled job
// produced.
func (f digestFixture) schedule(t *testing.T, n int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scheduler := &digest.Scheduler{
		Store:    f.store,
		Interval: 5 * time.Millisecond,
		Build: func(ctx context.Context) (digest.Entry, error) {
			since := time.Now().Add(-admin.DefaultDigestWindow)
			text, err := cryden.DigestSince(ctx, f.engine, since)
			if err != nil {
				return digest.Entry{}, err
			}
			return digest.Entry{
				WindowStart: since.UTC(),
				WindowEnd:   time.Now().UTC(),
				Text:        text,
			}, nil
		},
	}
	go scheduler.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for f.store.Count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("the scheduler recorded %d digests in five seconds, want %d", f.store.Count(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// The window is this repo's arithmetic, not the engine's: cryden's
// WeeklyDigest fixes seven days internally, so the only way to offer a
// configurable window is to compute it here and pass it to DigestSince.
// Both halves of that are asserted — the number echoed back, and the
// instant it was counted from.
func TestDigestCoversTheRequestedWindow(t *testing.T) {
	f := newDigestFixture(t)
	before := time.Now()

	resp := f.digest(t, f.adminToken, "")
	if resp.Data.WindowDays != digestDefaultWindowDays {
		t.Errorf("window_days = %d, want the default %d", resp.Data.WindowDays, digestDefaultWindowDays)
	}
	wantSince := before.AddDate(0, 0, -digestDefaultWindowDays)
	if delta := resp.Data.Since.Sub(wantSince); delta > time.Minute || delta < -time.Minute {
		t.Errorf("since = %v, want about %v (%v away)", resp.Data.Since, wantSince, delta)
	}
	// The window ends now, which is a reading only this repo can supply —
	// the engine returns the text and nothing else.
	if resp.Data.Until.Before(resp.Data.Since) {
		t.Errorf("until = %v is before since = %v", resp.Data.Until, resp.Data.Since)
	}
	if resp.Data.Until.Before(before) {
		t.Errorf("until = %v, want an instant at or after the request", resp.Data.Until)
	}
	if !strings.HasPrefix(resp.Data.Text, "Security digest") {
		t.Errorf("text = %q, want the engine's report passed through verbatim", resp.Data.Text)
	}

	wider := f.digest(t, f.adminToken, "?window_days=30")
	if wider.Data.WindowDays != 30 {
		t.Errorf("window_days = %d with window_days=30, want 30", wider.Data.WindowDays)
	}
	if !wider.Data.Since.Before(resp.Data.Since) {
		t.Errorf("a thirty-day window starts at %v, want earlier than the seven-day window's %v",
			wider.Data.Since, resp.Data.Since)
	}
}

// The report is built from the audit table the engine writes to, and this
// asserts it against a store the test holds and seeded itself. The type is
// one cryden does not define, which is also the proof that the report is
// the engine's own — a handler that reimplemented the digest would have no
// reason to know about a type it has never heard of.
func TestDigestCountsWhatTheAuditTableHolds(t *testing.T) {
	f := newDigestFixture(t)
	f.record(t, "host_specific_thing", 3)

	resp := f.digest(t, f.adminToken, "")
	if !strings.Contains(resp.Data.Text, "types this engine does not define") {
		t.Errorf("text = %q, want the section for types the engine does not define", resp.Data.Text)
	}
	if !strings.Contains(resp.Data.Text, "3 host_specific_thing") {
		t.Errorf("text = %q, want the three events this test recorded", resp.Data.Text)
	}

	// A window that reaches back further sees the same three, because they
	// happened within the last seven days — the count is the store's answer
	// to the window asked for, not a number the handler carries.
	if got := f.digest(t, f.adminToken, "?window_days=1").Data.Text; !strings.Contains(got, "3 host_specific_thing") {
		t.Errorf("text over one day = %q, want the events recorded moments ago", got)
	}
}

// window_days is bounded and rejected rather than clamped: a caller that
// asked for 5000 days and got 365 back has no way to tell that from a
// window that happens to hold the same history.
func TestDigestWindowIsBounded(t *testing.T) {
	f := newDigestFixture(t)

	for _, query := range []string{"?window_days=0", "?window_days=366", "?window_days=week", "?window_days=-7"} {
		rec := f.get(t, "/v1/admin/digest", f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
		}
	}
}

// The read-only property the whole feature rests on, asserted rather than
// promised: asking for a digest does not record one. Two requests, no
// rows. If this ever fails, an operator reading the history can no longer
// tell what the schedule produced from what somebody happened to open.
func TestDigestRecordsNothing(t *testing.T) {
	f := newDigestFixture(t)
	f.record(t, "host_specific_thing", 1)

	for i := 0; i < 2; i++ {
		if text := f.digest(t, f.adminToken, "").Data.Text; text == "" {
			t.Fatal("the digest came back empty")
		}
	}
	if n := f.store.Count(); n != 0 {
		t.Errorf("asking for a digest recorded %d runs, want 0", n)
	}
}

// The history shows what the schedule produced. The assertion on the
// planted count is what makes this a test of the whole path — scheduler,
// builder, store, endpoint — rather than of a handler reading rows a test
// inserted for it.
func TestDigestHistoryShowsWhatTheScheduleRecorded(t *testing.T) {
	f := newDigestFixture(t)
	f.record(t, "host_specific_thing", 3)

	f.schedule(t, 1)

	resp := f.history(t, f.adminToken, "")
	if resp.Data.Count == 0 {
		t.Fatalf("history is empty after the scheduler ran (count %d)", resp.Data.Count)
	}
	newest := resp.Data.Runs[0]
	if !strings.Contains(newest.Text, "3 host_specific_thing") {
		t.Errorf("the recorded digest does not hold the audit history it covered: %q", newest.Text)
	}
	if newest.ID == 0 || newest.GeneratedAt.IsZero() {
		t.Errorf("run %+v was recorded without an id or a timestamp", newest)
	}
	if newest.WindowEnd.IsZero() || newest.WindowStart.IsZero() {
		t.Errorf("run %+v was recorded without its window", newest)
	}
}

// A wired store with no runs answers an empty listing, not a 404: the
// schedule is configured and simply has not fired yet, which is a
// different thing from a deployment that has no history table at all.
// runs is [] rather than null, so a console can iterate it without a
// special case.
func TestDigestHistoryIsEmptyBeforeTheFirstRun(t *testing.T) {
	f := newDigestFixture(t)

	rec := f.get(t, "/v1/admin/digest/history", f.adminToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"runs":[]`) {
		t.Errorf("body = %s, want an empty runs array rather than null", rec.Body.String())
	}

	resp := f.history(t, f.adminToken, "")
	if resp.Data.Count != 0 {
		t.Errorf("count = %d with nothing scheduled yet, want 0", resp.Data.Count)
	}
	if resp.Data.Limit != digest.DefaultHistoryLimit {
		t.Errorf("limit = %d, want the default %d", resp.Data.Limit, digest.DefaultHistoryLimit)
	}
}

// Ordering, the limit, and its bounds. The rows are inserted directly here
// because this is about the listing rather than about the schedule: the
// clock is controlled so newest-first is a fact and not a hope.
func TestDigestHistoryOrdersAndBoundsTheListing(t *testing.T) {
	f := newDigestFixture(t)
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		if _, err := f.store.Insert(context.Background(), digest.Entry{
			WindowStart: base.Add(time.Duration(i) * time.Hour),
			WindowEnd:   base.Add(time.Duration(i+1) * time.Hour),
			GeneratedAt: base.Add(time.Duration(i) * time.Hour),
			Text:        "report " + string(rune('a'+i)),
		}); err != nil {
			t.Fatalf("inserting run %d: %v", i, err)
		}
	}

	resp := f.history(t, f.adminToken, "")
	if resp.Data.Count != 5 {
		t.Fatalf("count = %d, want 5", resp.Data.Count)
	}
	if resp.Data.Runs[0].Text != "report e" {
		t.Errorf("first row = %q, want the newest", resp.Data.Runs[0].Text)
	}
	if resp.Data.Runs[4].Text != "report a" {
		t.Errorf("last row = %q, want the oldest", resp.Data.Runs[4].Text)
	}

	limited := f.history(t, f.adminToken, "?limit=2")
	if limited.Data.Count != 2 || limited.Data.Limit != 2 {
		t.Errorf("count = %d limit = %d with limit=2, want 2 and 2", limited.Data.Count, limited.Data.Limit)
	}
	if limited.Data.Runs[0].Text != "report e" {
		t.Errorf("first row = %q, want the newest of the bounded set", limited.Data.Runs[0].Text)
	}

	// Bounded, not clamped — the same rule the logging endpoint's limit
	// follows, so one word does not mean two things across the admin
	// surface.
	for _, query := range []string{"?limit=0", "?limit=201", "?limit=-1", "?limit=lots"} {
		rec := f.get(t, "/v1/admin/digest/history", f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
		}
	}
}

// A router built without the history store answers 404 rather than 500 —
// a wiring fact, not a server fault, and the same shape every unconfigured
// feature in this API uses. Called through a router with no Digests, which
// is the state a deployment without DIGEST_INTERVAL_HOURS is in.
func TestDigestHistoryWithoutAStoreIsNotFound(t *testing.T) {
	f := newDigestFixture(t)
	router := NewRouter(Deps{Engine: f.engine, Audit: f.audit, Config: config.Config{}})

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/digest/history", nil)
	req.Header.Set("Authorization", "Bearer "+f.adminToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_configured") {
		t.Errorf("body = %s, want the not_configured code", rec.Body.String())
	}
}

// Both routes sit behind the same gate as every other admin report. A
// digest names accounts and failures, and read-only is not a reason to
// widen who can read it.
func TestDigestRoutesAreGatedByRequireAdmin(t *testing.T) {
	f := newDigestFixture(t)

	for _, path := range []string{"/v1/admin/digest", "/v1/admin/digest/history"} {
		if rec := f.get(t, path, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: no token gave %d, want 401", path, rec.Code)
		}
		if rec := f.get(t, path, "not-a-real-token", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: garbage token gave %d, want 401", path, rec.Code)
		}
		if rec := f.get(t, path, f.userToken, ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s: ordinary user gave %d, want 403 (body %s)", path, rec.Code, rec.Body.String())
		}
		if rec := f.get(t, path, f.adminToken, ""); rec.Code != http.StatusOK {
			t.Errorf("%s: operator gave %d, want 200 (body %s)", path, rec.Code, rec.Body.String())
		}
	}
}
