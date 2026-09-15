package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/webhook"
)

// webhookClock is a clock a test moves by hand, so a listing's ordering is
// something the test decides rather than something it hopes the wall clock
// separated by enough microseconds to be reproducible.
type webhookClock struct {
	mu sync.Mutex
	t  time.Time
}

func newWebhookClock() *webhookClock {
	return &webhookClock{t: time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)}
}

func (c *webhookClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *webhookClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// deliveriesResponse mirrors the endpoint's DTO field by field, so a
// renamed or dropped field fails here rather than silently changing the
// contract an operator's console reads.
type deliveriesResponse struct {
	Data struct {
		Deliveries []struct {
			ID           int64           `json:"id"`
			EventID      string          `json:"event_id"`
			EventType    string          `json:"event_type"`
			UserID       string          `json:"user_id"`
			IP           string          `json:"ip"`
			Payload      json.RawMessage `json:"payload"`
			Status       string          `json:"status"`
			Attempts     int             `json:"attempts"`
			ResponseCode int             `json:"response_code"`
			Error        string          `json:"error"`
			DurationMS   int             `json:"duration_ms"`
			CreatedAt    time.Time       `json:"created_at"`
			DeliveredAt  *time.Time      `json:"delivered_at"`
		} `json:"deliveries"`
		Count    int      `json:"count"`
		Status   string   `json:"status"`
		Statuses []string `json:"statuses"`
	} `json:"data"`
}

// deliveryOutcome is what a test reads off one raw row, with presence
// recorded separately from value: an omitted response_code and a
// response_code of 0 decode to the same int, and the endpoint's whole
// reason for omitting it is that those two are different things.
type deliveryOutcome struct {
	status       string
	responseCode int
	errText      string
	hasDelivered bool
	hasCode      bool
}

type webhookFixture struct {
	store  *webhook.MemoryStore
	clock  *webhookClock
	router http.Handler

	adminToken string
	userToken  string
}

// newWebhookFixture builds an engine whose operator carries the admin
// claim, a router holding the delivery log, and both tokens. The store is
// filled through webhook.Sender rather than by hand, so what these tests
// list is the body the sender actually produced — the same bytes the
// worker would POST, which is the whole point of the log.
func newWebhookFixture(t *testing.T) webhookFixture {
	t.Helper()
	ctx := context.Background()

	store := webhook.NewMemoryStore()
	clock := newWebhookClock()
	store.Clock = clock.now

	var adminID string
	engine, err := cryden.New(cryden.Config{
		JWTSecret:       "test-secret",
		Users:           memory.NewUserStore(),
		Sessions:        memory.NewSessionStore(),
		Audit:           memory.NewAuditStore(),
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

	return webhookFixture{
		store:      store,
		clock:      clock,
		router:     NewRouter(Deps{Engine: engine, Config: config.Config{}, Hooks: store}),
		adminToken: adminTokens.AccessToken,
		userToken:  userTokens.AccessToken,
	}
}

// seed records an event through the real sender and returns its row id.
func (f webhookFixture) seed(t *testing.T, eventType, reason string) int64 {
	t.Helper()
	sender := &webhook.Sender{Store: f.store}
	err := sender.SendWebhook(context.Background(), notify.WebhookEvent{
		ID:         "evt_" + eventType,
		Type:       eventType,
		UserID:     "01a0a4ce-5453-78d3-9126-52268da8da5c",
		IP:         "203.0.113.9",
		Metadata:   map[string]string{"reason": reason},
		OccurredAt: f.clock.now(),
	})
	if err != nil {
		t.Fatalf("enqueueing %s: %v", eventType, err)
	}
	rows, err := f.store.List(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return rows[0].ID
}

// resolve drives a seeded row to a terminal state the way the worker
// would, so the listing's status filter has something real to filter on.
func (f webhookFixture) resolve(t *testing.T, id int64, delivered bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.store.ClaimDue(ctx, f.clock.now(), 10, 5, time.Minute); err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if delivered {
		if err := f.store.MarkDelivered(ctx, id, webhook.Result{Code: http.StatusOK, Duration: 42 * time.Millisecond}); err != nil {
			t.Fatalf("MarkDelivered: %v", err)
		}
		return
	}
	if err := f.store.MarkFailed(ctx, id, webhook.Result{Code: http.StatusInternalServerError, Duration: 7 * time.Millisecond, Err: "receiver answered 500"}, nil); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
}

func (f webhookFixture) list(t *testing.T, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/webhooks/deliveries"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func decodeDeliveries(t *testing.T, rec *httptest.ResponseRecorder) deliveriesResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp deliveriesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

func TestWebhookDeliveriesListsNewestFirst(t *testing.T) {
	f := newWebhookFixture(t)

	first := f.seed(t, "account_locked", "too many attempts")
	f.clock.advance(time.Minute)
	second := f.seed(t, "password_reset", "requested by the user")

	resp := decodeDeliveries(t, f.list(t, f.adminToken, ""))
	if resp.Data.Count != 2 {
		t.Fatalf("count = %d, want 2", resp.Data.Count)
	}
	if len(resp.Data.Deliveries) != 2 {
		t.Fatalf("listed %d rows, want 2", len(resp.Data.Deliveries))
	}
	if resp.Data.Deliveries[0].ID != second || resp.Data.Deliveries[1].ID != first {
		t.Errorf("order = %d, %d, want the newest (%d) first", resp.Data.Deliveries[0].ID, resp.Data.Deliveries[1].ID, second)
	}

	// The filter values are reported rather than hardcoded, so a console
	// can offer the filter without a second source of truth for it.
	want := []string{"pending", "in_flight", "delivered", "failed"}
	if strings.Join(resp.Data.Statuses, ",") != strings.Join(want, ",") {
		t.Errorf("statuses = %v, want %v", resp.Data.Statuses, want)
	}
	// No filter in force, so nothing is echoed back.
	if resp.Data.Status != "" {
		t.Errorf("status = %q on an unfiltered listing, want empty", resp.Data.Status)
	}
}

// The log's reason for existing: what was sent is readable after the fact,
// for a retry as much as a first attempt. The payload is emitted as raw
// JSON rather than a re-encoding — or worse, a base64 string — which is
// the property a console displaying "what we signed" depends on.
func TestWebhookDeliveriesServesTheBodyThatWasSent(t *testing.T) {
	f := newWebhookFixture(t)
	f.seed(t, "account_locked", "too many attempts")

	rec := f.list(t, f.adminToken, "")
	resp := decodeDeliveries(t, rec)
	d := resp.Data.Deliveries[0]

	var body struct {
		ID       string            `json:"id"`
		Type     string            `json:"type"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(d.Payload, &body); err != nil {
		t.Fatalf("payload is not a JSON object: %v (%s)", err, d.Payload)
	}
	if body.ID != "evt_account_locked" || body.Type != "account_locked" {
		t.Errorf("payload id/type = %q/%q", body.ID, body.Type)
	}
	if body.Metadata["reason"] != "too many attempts" {
		t.Errorf("payload metadata = %v, want the event's own", body.Metadata)
	}

	// The raw body, not the decoded DTO: json.RawMessage is inlined
	// verbatim and []byte would have become a base64 string, so this is
	// the assertion that distinguishes the two.
	if !strings.Contains(rec.Body.String(), `"payload":{`) {
		t.Errorf("payload was not emitted as a JSON object: %s", rec.Body.String())
	}
}

// A row that reached a terminal state is readable with the evidence that
// decided it, and the two failure shapes stay distinguishable: a receiver
// that answered 500 and an endpoint that never answered at all are fixed
// in different places.
func TestWebhookDeliveriesCarryTheirOutcome(t *testing.T) {
	f := newWebhookFixture(t)

	delivered := f.seed(t, "account_locked", "one")
	f.clock.advance(time.Minute)
	failed := f.seed(t, "account_locked", "two")
	f.clock.advance(time.Minute)
	unreachable := f.seed(t, "account_locked", "three")

	f.resolve(t, delivered, true)
	f.resolve(t, failed, false)
	// A connection that never answered: code 0, with the transport's own
	// error and nothing that looks like an HTTP status.
	if _, err := f.store.ClaimDue(context.Background(), f.clock.now(), 10, 5, time.Minute); err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if err := f.store.MarkFailed(context.Background(), unreachable, webhook.Result{
		Code: 0, Duration: 2 * time.Second, Err: "dial tcp 203.0.113.9:443: connect: connection refused",
	}, nil); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	// Read off the raw response rather than the DTO, because the two
	// assertions that matter most here are about fields being ABSENT —
	// response_code on a connection that never answered, delivered_at on a
	// row that failed — and an absent field is invisible once decoded.
	rec := f.list(t, f.adminToken, "")
	var raw struct {
		Data struct {
			Deliveries []map[string]json.RawMessage `json:"deliveries"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	byID := map[int64]deliveryOutcome{}
	for _, row := range raw.Data.Deliveries {
		var id int64
		if err := json.Unmarshal(row["id"], &id); err != nil {
			t.Fatalf("decoding id: %v", err)
		}
		got := deliveryOutcome{hasDelivered: row["delivered_at"] != nil, hasCode: row["response_code"] != nil}
		if err := json.Unmarshal(row["status"], &got.status); err != nil {
			t.Fatalf("decoding status: %v", err)
		}
		if got.hasCode {
			if err := json.Unmarshal(row["response_code"], &got.responseCode); err != nil {
				t.Fatalf("decoding response_code: %v", err)
			}
		}
		if raw, ok := row["error"]; ok {
			if err := json.Unmarshal(raw, &got.errText); err != nil {
				t.Fatalf("decoding error: %v", err)
			}
		}
		byID[id] = got
	}

	if got := byID[delivered]; got.status != "delivered" || got.responseCode != http.StatusOK || !got.hasDelivered {
		t.Errorf("delivered row = %+v, want delivered with a 200 and delivered_at set", got)
	}
	if got := byID[failed]; got.status != "failed" || got.responseCode != http.StatusInternalServerError {
		t.Errorf("failed row = %+v, want failed with a 500", got)
	}
	// The important half: no response code at all, not a zero an operator
	// would read as a status.
	if got := byID[unreachable]; got.status != "failed" || got.hasCode {
		t.Errorf("unreachable row = %+v, want failed with response_code absent", got)
	}
	if got := byID[unreachable]; !strings.Contains(got.errText, "connection refused") {
		t.Errorf("unreachable row error = %q, want the transport's own words", got.errText)
	}
}

func TestWebhookDeliveriesFiltersByStatus(t *testing.T) {
	f := newWebhookFixture(t)

	// Resolved while it is the only row, deliberately: ClaimDue sweeps
	// every due row in one pass, so seeding both first and then resolving
	// one would leave the other claimed and in_flight — real worker
	// behaviour, but not the state this test is about.
	ok := f.seed(t, "account_locked", "one")
	f.resolve(t, ok, true)

	f.clock.advance(time.Minute)
	f.seed(t, "password_reset", "two")

	pending := decodeDeliveries(t, f.list(t, f.adminToken, "?status=pending"))
	if pending.Data.Count != 1 {
		t.Fatalf("pending count = %d, want 1", pending.Data.Count)
	}
	if pending.Data.Status != "pending" {
		t.Errorf("status = %q, want the filter echoed back", pending.Data.Status)
	}

	delivered := decodeDeliveries(t, f.list(t, f.adminToken, "?status=delivered"))
	if delivered.Data.Count != 1 {
		t.Fatalf("delivered count = %d, want 1", delivered.Data.Count)
	}
	if delivered.Data.Deliveries[0].ID != ok {
		t.Errorf("delivered row = %d, want %d", delivered.Data.Deliveries[0].ID, ok)
	}
}

// An unrecognized status is a 400 that names the four real values. It must
// not be an empty list, which is indistinguishable from "no deliveries" —
// the one thing a filter must never be able to look like.
func TestWebhookDeliveriesRejectsAnUnknownStatus(t *testing.T) {
	f := newWebhookFixture(t)
	f.seed(t, "account_locked", "one")

	for _, query := range []string{"?status=done", "?status=PENDING", "?status=all"} {
		rec := f.list(t, f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
			continue
		}
		body := rec.Body.String()
		for _, want := range []string{"pending", "in_flight", "delivered", "failed"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: body = %s, want the valid values including %q", query, body, want)
			}
		}
	}
}

func TestWebhookDeliveriesBoundsTheLimit(t *testing.T) {
	f := newWebhookFixture(t)
	for i := 0; i < 3; i++ {
		f.seed(t, "account_locked", "x")
		f.clock.advance(time.Minute)
	}

	limited := decodeDeliveries(t, f.list(t, f.adminToken, "?limit=2"))
	if limited.Data.Count != 2 {
		t.Errorf("count = %d with limit=2, want 2", limited.Data.Count)
	}

	// Bounded, not clamped: a caller that asked for 100000 and got 500 back
	// has no way to tell that from a table holding 500 rows.
	for _, query := range []string{"?limit=0", "?limit=501", "?limit=lots"} {
		rec := f.list(t, f.adminToken, query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", query, rec.Code, rec.Body.String())
		}
	}
}

// A router built without a delivery log answers 404 rather than 500 — a
// wiring fact, not a server fault, and the same shape every unconfigured
// feature in this API uses.
//
// The handler is called directly rather than through a router because this
// repo has no engine without the stores either: the deployment this covers
// is one where WEBHOOK_URL is unset, which leaves Deps.Hooks genuinely nil
// while everything else is wired. That guard is a single branch, and this
// is the only way to reach it.
func TestWebhookDeliveriesWithoutAStoreIsNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/webhooks/deliveries", nil)
	rec := httptest.NewRecorder()

	h := &WebhookHandlers{}
	h.Deliveries(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_configured") {
		t.Errorf("body = %s, want the not_configured code", rec.Body.String())
	}
}

// The delivery log is evidence about accounts and about a third party's
// responses, so it sits behind the same gate as every other admin report.
func TestWebhookDeliveriesRouteIsGatedByRequireAdmin(t *testing.T) {
	f := newWebhookFixture(t)
	f.seed(t, "account_locked", "one")

	if rec := f.list(t, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := f.list(t, "not-a-real-token", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: status = %d, want 401", rec.Code)
	}
	if rec := f.list(t, f.userToken, ""); rec.Code != http.StatusForbidden {
		t.Errorf("ordinary user: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := f.list(t, f.adminToken, ""); rec.Code != http.StatusOK {
		t.Errorf("operator: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}
