package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/notify"
)

// testClock is a clock a test moves by hand, so a retry schedule can be
// exercised in microseconds instead of in real backoff delays.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// receiver is a stand-in for whatever an operator points WEBHOOK_URL at. It
// records what it was sent so a test can assert on the body and headers a
// real endpoint would see, and answers with a status the test chooses.
type receiver struct {
	mu       sync.Mutex
	requests []received
	status   int
	body     string
}

type received struct {
	header http.Header
	body   []byte
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := req.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	r.mu.Lock()
	r.requests = append(r.requests, received{header: req.Header.Clone(), body: body})
	status, respBody := r.status, r.body
	r.mu.Unlock()

	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(respBody))
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

func (r *receiver) last(t *testing.T) received {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) == 0 {
		t.Fatal("the receiver was never called")
	}
	return r.requests[len(r.requests)-1]
}

// newReceiver starts a real HTTP server. The worker's HTTP path is the
// production one down to the socket, which is the strongest thing available
// here without a live third party.
func newReceiver(t *testing.T, status int, body string) (*receiver, string) {
	t.Helper()
	r := &receiver{status: status, body: body}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return r, srv.URL
}

func testEvent() notify.WebhookEvent {
	return notify.WebhookEvent{
		ID:         "evt_01",
		Type:       "account_locked",
		UserID:     "01a0a4ce-5453-78d3-9126-52268da8da5c",
		IP:         "203.0.113.9",
		Metadata:   map[string]string{"reason": "too many failed attempts"},
		OccurredAt: time.Date(2026, time.September, 15, 11, 59, 0, 0, time.UTC),
	}
}

// The whole design in one assertion: the sender records the event and does
// NOT call the endpoint. cryden calls this on the login request path, so an
// HTTP call here would be a third party's downtime becoming login latency.
func TestSendWebhookEnqueuesWithoutCallingTheEndpoint(t *testing.T) {
	rec, _ := newReceiver(t, http.StatusOK, "")
	store := NewMemoryStore()

	sender := &Sender{Store: store}
	if err := sender.SendWebhook(context.Background(), testEvent()); err != nil {
		t.Fatalf("SendWebhook: %v", err)
	}

	if rec.count() != 0 {
		t.Errorf("the endpoint was called %d times, want 0 — the sender must only enqueue", rec.count())
	}
	if n := store.Count(StatusPending); n != 1 {
		t.Fatalf("pending rows = %d, want 1", n)
	}

	rows, err := store.List(context.Background(), StatusPending, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	d := rows[0]
	if d.EventID != "evt_01" || d.EventType != "account_locked" {
		t.Errorf("recorded %q/%q, want evt_01/account_locked", d.EventID, d.EventType)
	}
	if d.UserID == "" || d.IP == "" {
		t.Errorf("recorded user/ip %q/%q, want both present", d.UserID, d.IP)
	}
	if d.Attempts != 0 {
		t.Errorf("attempts = %d before any delivery, want 0", d.Attempts)
	}
}

// The body is built once, at enqueue, and is what the receiver gets. That is
// what lets the delivery log answer "what did we send?" for a retry as well
// as a first attempt.
func TestSendWebhookRecordsTheBodyItWillSend(t *testing.T) {
	store := NewMemoryStore()
	sender := &Sender{Store: store}
	if err := sender.SendWebhook(context.Background(), testEvent()); err != nil {
		t.Fatalf("SendWebhook: %v", err)
	}

	rows, _ := store.List(context.Background(), "", 10)
	var got payload
	if err := json.Unmarshal(rows[0].Payload, &got); err != nil {
		t.Fatalf("the stored payload is not the JSON body: %v (%s)", err, rows[0].Payload)
	}

	if got.ID != "evt_01" || got.Type != "account_locked" {
		t.Errorf("payload id/type = %q/%q", got.ID, got.Type)
	}
	if got.Metadata["reason"] != "too many failed attempts" {
		t.Errorf("payload metadata = %v, want the event's own", got.Metadata)
	}
	if !got.OccurredAt.Equal(testEvent().OccurredAt) {
		t.Errorf("occurred_at = %v, want %v", got.OccurredAt, testEvent().OccurredAt)
	}
}

// ctx on the request path may already be cancelled by the time a slow sender
// gets to it — cryden's own doc comment says so. An insert that honoured
// that cancellation would drop the event exactly when the request went away,
// and this row is the only record it ever happened.
func TestSendWebhookIgnoresACancelledRequestContext(t *testing.T) {
	store := NewMemoryStore()
	sender := &Sender{Store: store}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := sender.SendWebhook(ctx, testEvent()); err != nil {
		t.Fatalf("SendWebhook with a cancelled ctx: %v", err)
	}
	if n := store.Count(StatusPending); n != 1 {
		t.Errorf("pending rows = %d, want 1 — the event outlives the connection it arrived on", n)
	}
}

// The nudge is a hint, never a guarantee: it must not be able to block the
// request path, whatever state the channel is in.
func TestSendWebhookNeverBlocksOnTheWakeupChannel(t *testing.T) {
	full := make(chan struct{}, 1)
	full <- struct{}{}

	for name, wake := range map[string]chan<- struct{}{
		"already full": full,
		"nil":          nil,
		"unbuffered":   make(chan struct{}),
	} {
		t.Run(name, func(t *testing.T) {
			sender := &Sender{Store: NewMemoryStore(), Wake: wake}

			done := make(chan error, 1)
			go func() { done <- sender.SendWebhook(context.Background(), testEvent()) }()

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("SendWebhook: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("SendWebhook blocked on the wakeup channel — that is a login hanging")
			}
		})
	}
}

// cryden logs a send error and lets the login succeed regardless. So the
// error has to actually reach it rather than being swallowed here, or a
// delivery pipeline that is broken reports nothing at all.
func TestSendWebhookReportsAnEnqueueFailure(t *testing.T) {
	wantErr := errors.New("database is down")
	sender := &Sender{Store: failingStore{err: wantErr}}

	if err := sender.SendWebhook(context.Background(), testEvent()); !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want %v", err, wantErr)
	}
}

// An event with no user behind it — a failed login naming an email nobody
// registered — is a real case, and its empty fields must not become a
// problem for the store.
func TestSendWebhookAcceptsAnEventWithNoUser(t *testing.T) {
	store := NewMemoryStore()
	sender := &Sender{Store: store}

	event := testEvent()
	event.UserID = ""
	event.IP = ""
	event.Metadata = nil

	if err := sender.SendWebhook(context.Background(), event); err != nil {
		t.Fatalf("SendWebhook: %v", err)
	}
	rows, _ := store.List(context.Background(), "", 10)
	if rows[0].UserID != "" {
		t.Errorf("user id = %q, want empty", rows[0].UserID)
	}

	// And the body omits the fields rather than sending empty strings, so a
	// receiver can tell "no user" from "the empty user".
	var body map[string]any
	if err := json.Unmarshal(rows[0].Payload, &body); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if _, present := body["user_id"]; present {
		t.Errorf("payload = %s, want user_id omitted when there is no user", rows[0].Payload)
	}
	if body["id"] != "evt_01" {
		t.Errorf("payload id = %v, want the event id present even when other fields are empty", body["id"])
	}
}

// failingStore is a Store whose writes always fail, for the error paths.
type failingStore struct{ err error }

func (s failingStore) Enqueue(context.Context, Delivery) error { return s.err }
func (s failingStore) ClaimDue(context.Context, time.Time, int, int, time.Duration) ([]Delivery, error) {
	return nil, s.err
}
func (s failingStore) MarkDelivered(context.Context, int64, Result) error { return s.err }
func (s failingStore) MarkFailed(context.Context, int64, Result, *time.Time) error {
	return s.err
}
func (s failingStore) List(context.Context, Status, int) ([]Delivery, error) { return nil, s.err }
