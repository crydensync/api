package webhook

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newTestWorker wires a worker to an in-memory store and a clock a test
// controls, pointed at a real HTTP endpoint.
func newTestWorker(t *testing.T, store Store, url, secret string) (*Worker, *testClock) {
	t.Helper()
	clock := newTestClock()
	store.(*MemoryStore).Clock = clock.now

	w := NewWorker(store, url, secret)
	w.Now = clock.now
	w.BatchSize = 10
	return w, clock
}

// enqueue is the sender's job, done directly so a worker test is about the
// worker.
func enqueue(t *testing.T, store Store, eventType string) int64 {
	t.Helper()
	sender := &Sender{Store: store}
	event := testEvent()
	event.Type = eventType
	if err := sender.SendWebhook(context.Background(), event); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	rows, err := store.List(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return rows[0].ID
}

func TestWorkerDeliversAndRecordsTheAttempt(t *testing.T) {
	rec, url := newReceiver(t, http.StatusOK, "")
	store := NewMemoryStore()
	w, _ := newTestWorker(t, store, url, "")

	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Errorf("claimed %d rows from an empty store, want 0", n)
	}

	id := enqueue(t, store, "account_locked")
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if rec.count() != 1 {
		t.Fatalf("the endpoint was called %d times, want 1", rec.count())
	}
	d, _ := store.Get(id)
	if d.Status != StatusDelivered {
		t.Errorf("status = %q, want delivered (%s)", d.Status, d.Error)
	}
	if d.ResponseCode != http.StatusOK {
		t.Errorf("response code = %d, want 200", d.ResponseCode)
	}
	if d.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", d.Attempts)
	}
	if d.DeliveredAt == nil {
		t.Error("delivered_at is not set on a delivered row")
	}
	if d.ClaimedAt != nil {
		t.Error("claimed_at is still set after the row was resolved")
	}
	if d.Error != "" {
		t.Errorf("error = %q, want empty on a delivered row", d.Error)
	}
}

// A receiver that keeps failing gets exactly MaxAttempts attempts and then
// stops. Retrying forever is a load generator pointed at a third party;
// giving up silently is half a feature. The row stays readable either way.
func TestWorkerRetriesThenGivesUpAtTheAttemptLimit(t *testing.T) {
	rec, url := newReceiver(t, http.StatusInternalServerError, "upstream exploded")
	store := NewMemoryStore()
	w, clock := newTestWorker(t, store, url, "")
	w.MaxAttempts = 3

	id := enqueue(t, store, "account_locked")

	for attempt := 1; attempt <= w.MaxAttempts; attempt++ {
		if _, err := w.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce (attempt %d): %v", attempt, err)
		}
		d, _ := store.Get(id)
		if d.Attempts != attempt {
			t.Fatalf("after attempt %d, attempts = %d", attempt, d.Attempts)
		}

		if attempt < w.MaxAttempts {
			if d.Status != StatusPending {
				t.Fatalf("after attempt %d, status = %q, want pending for a retry", attempt, d.Status)
			}
			// Nothing is due yet, so a pass made now must find no work.
			if n, _ := w.RunOnce(context.Background()); n != 0 {
				t.Fatalf("attempt %d was retried immediately, without waiting out its backoff", attempt)
			}
			clock.advance(backoff(attempt) + time.Second)
		}
	}

	d, _ := store.Get(id)
	if d.Status != StatusFailed {
		t.Errorf("status = %q, want failed once the attempts ran out", d.Status)
	}
	if d.Attempts != w.MaxAttempts {
		t.Errorf("attempts = %d, want exactly the budget of %d", d.Attempts, w.MaxAttempts)
	}
	if rec.count() != w.MaxAttempts {
		t.Errorf("the endpoint was called %d times, want %d", rec.count(), w.MaxAttempts)
	}
	// The receiver's own words are what makes the row actionable.
	if !strings.Contains(d.Error, "500") || !strings.Contains(d.Error, "upstream exploded") {
		t.Errorf("error = %q, want the status and the receiver's message", d.Error)
	}

	// And a failed row is not picked up again.
	clock.advance(24 * time.Hour)
	if n, _ := w.RunOnce(context.Background()); n != 0 {
		t.Errorf("claimed %d rows, want 0 — a failed delivery is terminal", n)
	}
}

// Doubling, capped, and never negative.
func TestBackoffDoublesAndIsBounded(t *testing.T) {
	if got := backoff(1); got != backoffBase {
		t.Errorf("backoff(1) = %v, want %v", got, backoffBase)
	}
	for attempt := 2; attempt <= 6; attempt++ {
		if got, want := backoff(attempt), backoffBase<<(attempt-1); got != want {
			t.Errorf("backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
	// Well past the cap, including values where an uncapped shift would
	// overflow into a negative duration — which would schedule a retry in
	// the past and spin.
	for _, attempt := range []int{0, -1, 7, 20, 64, 1 << 20} {
		if got := backoff(attempt); got <= 0 || got > backoffMax {
			t.Errorf("backoff(%d) = %v, want a positive duration no greater than %v", attempt, got, backoffMax)
		}
	}
}

// The signature is the receiver's whole basis for believing a delivery came
// from here, so the test verifies it with Verify — the function a receiver
// would use — rather than comparing against a string this test built.
func TestWorkerSignsTheBodyWhenASecretIsSet(t *testing.T) {
	rec, url := newReceiver(t, http.StatusOK, "")
	store := NewMemoryStore()
	w, _ := newTestWorker(t, store, url, "s3cret-shared-with-the-receiver")

	id := enqueue(t, store, "account_locked")
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	got := rec.last(t)
	signature := got.header.Get(SignatureHeader)
	if signature == "" {
		t.Fatalf("no %s header on a signed delivery", SignatureHeader)
	}
	if !Verify("s3cret-shared-with-the-receiver", got.body, signature) {
		t.Errorf("signature %q does not verify against the body sent", signature)
	}
	// A different secret must not verify, or the test above would pass for
	// the wrong reason.
	if Verify("some-other-secret", got.body, signature) {
		t.Error("the signature verified under a secret it was not computed with")
	}

	// The body is byte-for-byte what the log recorded, which is what makes
	// "show me what we signed" answerable.
	d, _ := store.Get(id)
	if string(d.Payload) != string(got.body) {
		t.Errorf("the endpoint received %s but the log records %s", got.body, d.Payload)
	}
	if got.header.Get("X-Cryden-Event-Type") != "account_locked" {
		t.Errorf("event type header = %q", got.header.Get("X-Cryden-Event-Type"))
	}
	if got.header.Get("X-Cryden-Event-Id") != "evt_01" {
		t.Errorf("event id header = %q", got.header.Get("X-Cryden-Event-Id"))
	}
	if got.header.Get("Content-Type") != "application/json" {
		t.Errorf("content type = %q", got.header.Get("Content-Type"))
	}
}

// No secret means no signature header at all — not one computed over an
// empty key, which a receiver might accept as a real signature.
func TestWorkerSendsNoSignatureWithoutASecret(t *testing.T) {
	rec, url := newReceiver(t, http.StatusOK, "")
	store := NewMemoryStore()
	w, _ := newTestWorker(t, store, url, "")

	enqueue(t, store, "account_locked")
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if got := rec.last(t).header.Get(SignatureHeader); got != "" {
		t.Errorf("%s = %q on an unsigned worker, want the header absent", SignatureHeader, got)
	}
}

// Anything outside 2xx is a failure, including the redirects and 4xx a
// receiver might answer with. 204 is a success — the body is the request's,
// not the response's.
func TestWorkerTreatsOnlyTwoHundredsAsDelivered(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   Status
	}{
		{http.StatusOK, StatusDelivered},
		{http.StatusCreated, StatusDelivered},
		{http.StatusNoContent, StatusDelivered},
		{http.StatusMovedPermanently, StatusPending},
		{http.StatusBadRequest, StatusPending},
		{http.StatusNotFound, StatusPending},
		{http.StatusTooManyRequests, StatusPending},
		{http.StatusInternalServerError, StatusPending},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			_, url := newReceiver(t, tc.status, "")
			store := NewMemoryStore()
			w, _ := newTestWorker(t, store, url, "")
			w.MaxAttempts = 5

			id := enqueue(t, store, "account_locked")
			if _, err := w.RunOnce(context.Background()); err != nil {
				t.Fatalf("RunOnce: %v", err)
			}
			if d, _ := store.Get(id); d.Status != tc.want {
				t.Errorf("status after %d = %q, want %q", tc.status, d.Status, tc.want)
			}
		})
	}
}

// A connection that never completes is a failure with no response code at
// all — 0, which is never a real HTTP status, so "nothing came back" is
// distinguishable from "it said 500".
func TestWorkerRecordsAnUnreachableEndpointAsNoResponse(t *testing.T) {
	store := NewMemoryStore()
	w, _ := newTestWorker(t, store, "http://127.0.0.1:1/hooks", "")
	w.Client = &http.Client{Timeout: 2 * time.Second}

	id := enqueue(t, store, "account_locked")
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	d, _ := store.Get(id)
	if d.Status != StatusPending {
		t.Errorf("status = %q, want pending for a retry", d.Status)
	}
	if d.ResponseCode != 0 {
		t.Errorf("response code = %d, want 0 for a connection that never answered", d.ResponseCode)
	}
	if d.Error == "" {
		t.Error("no error was recorded for an unreachable endpoint")
	}
}

// A row claimed by a worker that then went away is retried rather than
// stranded. This is the branch of ClaimDue that ignores the attempt budget,
// and without it a crash mid-delivery would leave a row in_flight forever
// with nothing to finish it.
func TestWorkerReclaimsAStaleInFlightRow(t *testing.T) {
	rec, url := newReceiver(t, http.StatusOK, "")
	store := NewMemoryStore()
	w, clock := newTestWorker(t, store, url, "")
	w.MaxAttempts = 5

	id := enqueue(t, store, "account_locked")

	// A worker claims the row and dies before resolving it.
	claimed, err := store.ClaimDue(context.Background(), clock.now(), 10, w.MaxAttempts, w.StaleAfter)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed %d rows, want 1", len(claimed))
	}
	if d, _ := store.Get(id); d.Status != StatusInFlight {
		t.Fatalf("status = %q, want in_flight", d.Status)
	}

	// Not yet stale: nothing may claim it, because the first worker might
	// still be making the call.
	if n, _ := w.RunOnce(context.Background()); n != 0 {
		t.Fatal("a freshly claimed row was claimed again — the receiver would see the event twice")
	}

	// Past the staleness bound, and the replacement worker delivers it.
	clock.advance(w.StaleAfter + time.Second)
	if n, _ := w.RunOnce(context.Background()); n != 1 {
		t.Fatalf("claimed %d rows after the claim went stale, want 1", n)
	}
	if d, _ := store.Get(id); d.Status != StatusDelivered {
		t.Errorf("status = %q, want delivered", d.Status)
	}
	if rec.count() != 1 {
		t.Errorf("the endpoint was called %d times, want 1", rec.count())
	}
}

// The other half of the same property: a row that goes stale AFTER its
// attempts have run out must still reach a terminal state, rather than being
// reclaimed forever by a worker that keeps dying. It gets one more real
// attempt — ClaimDue's stale branch ignores the budget on purpose — and that
// attempt is what decides it: delivered if it works, failed if it does not.
// Either way it stops there, never rescheduled.
func TestWorkerResolvesAStaleRowThatIsOutOfAttempts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		wantStatus Status
	}{
		{"the last attempt succeeds", http.StatusOK, StatusDelivered},
		{"the last attempt fails too", http.StatusInternalServerError, StatusFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, url := newReceiver(t, tc.status, "")
			store := NewMemoryStore()
			w, clock := newTestWorker(t, store, url, "")
			w.MaxAttempts = 2

			id := enqueue(t, store, "account_locked")

			// Two claims, neither resolved: a worker that died
			// mid-delivery twice, which spends the whole budget.
			for i := 0; i < w.MaxAttempts; i++ {
				clock.advance(w.StaleAfter + time.Second)
				if _, err := store.ClaimDue(context.Background(), clock.now(), 10, w.MaxAttempts, w.StaleAfter); err != nil {
					t.Fatalf("ClaimDue: %v", err)
				}
			}
			if d, _ := store.Get(id); d.Attempts != w.MaxAttempts {
				t.Fatalf("attempts = %d, want the budget spent", d.Attempts)
			}

			// Freshly claimed, so not yet reclaimable.
			if n, _ := w.RunOnce(context.Background()); n != 0 {
				t.Fatal("a freshly claimed row was claimed again")
			}

			clock.advance(w.StaleAfter + time.Second)
			if n, _ := w.RunOnce(context.Background()); n != 1 {
				t.Fatalf("claimed %d stale rows, want 1", n)
			}

			d, _ := store.Get(id)
			if d.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", d.Status, tc.wantStatus)
			}
			if rec.count() != 1 {
				t.Errorf("the endpoint was called %d times, want the one last attempt", rec.count())
			}
			// The bound that makes this safe: exactly one attempt past the
			// budget, never a scheduled retry, so no crash can turn into a
			// loop.
			if d.Attempts != w.MaxAttempts+1 {
				t.Errorf("attempts = %d, want exactly one past the budget of %d", d.Attempts, w.MaxAttempts)
			}
			if d.Status == StatusPending {
				t.Error("a stranded row was rescheduled for another retry")
			}
		})
	}
}

// BatchSize bounds one pass, so a backlog is worked through a batch at a
// time rather than claimed in one go.
func TestClaimDueHonoursTheBatchSize(t *testing.T) {
	store := NewMemoryStore()
	clock := newTestClock()
	store.Clock = clock.now

	for i := 0; i < 5; i++ {
		enqueue(t, store, "account_locked")
	}

	first, err := store.ClaimDue(context.Background(), clock.now(), 2, 5, time.Minute)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("claimed %d rows with a batch size of 2, want 2", len(first))
	}
	// Claimed rows are in_flight and not yet stale, so the next pass takes
	// the NEXT two rather than the same ones again.
	second, _ := store.ClaimDue(context.Background(), clock.now(), 2, 5, time.Minute)
	if len(second) != 2 {
		t.Fatalf("second pass claimed %d rows, want 2", len(second))
	}
	seen := map[int64]bool{}
	for _, d := range append(first, second...) {
		if seen[d.ID] {
			t.Fatalf("delivery %d was claimed twice without being resolved", d.ID)
		}
		seen[d.ID] = true
	}
	if n := store.Count(StatusInFlight); n != 4 {
		t.Errorf("in-flight rows = %d, want 4", n)
	}
}

// A panic in the delivery path must not take the auth API down with it. It
// is recorded as a failure and retried like any other.
func TestWorkerContainsAPanicInTheDeliveryPath(t *testing.T) {
	store := NewMemoryStore()
	w, _ := newTestWorker(t, store, "http://example.invalid/hooks", "")
	w.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		panic("the http transport blew up")
	})}

	id := enqueue(t, store, "account_locked")
	n, err := w.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("claimed %d rows, want 1", n)
	}

	d, _ := store.Get(id)
	if d.Status != StatusPending {
		t.Errorf("status = %q, want pending so the delivery is retried", d.Status)
	}
	if !strings.Contains(d.Error, "panic") {
		t.Errorf("error = %q, want the panic recorded", d.Error)
	}
}

// The configured URL is where the operator wants their events to go.
// Following a redirect to a different host would deliver the body, and the
// signature over it, wherever that host said.
func TestWorkerRefusesARedirectToAnotherHost(t *testing.T) {
	check := defaultClient().CheckRedirect

	original := &http.Request{URL: mustURL(t, "https://hooks.example.com/v1")}
	sameHost := &http.Request{URL: mustURL(t, "https://hooks.example.com/v1/")}
	otherHost := &http.Request{URL: mustURL(t, "https://attacker.example.net/collect")}

	if err := check(sameHost, []*http.Request{original}); err != nil {
		t.Errorf("a same-host redirect was refused: %v", err)
	}
	if err := check(otherHost, []*http.Request{original}); err == nil {
		t.Error("a cross-host redirect was followed")
	}
}

// A malformed WEBHOOK_URL is retried rather than lost: the row would
// otherwise be thrown away for a typo an operator is about to fix.
func TestWorkerRetriesAMalformedURL(t *testing.T) {
	store := NewMemoryStore()
	w, _ := newTestWorker(t, store, "://not-a-url", "")

	id := enqueue(t, store, "account_locked")
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if d, _ := store.Get(id); d.Status != StatusPending {
		t.Errorf("status = %q, want pending", d.Status)
	}
}

// List is what the admin endpoint is built on: newest first, filtered, and
// bounded.
func TestMemoryStoreListOrdersAndFilters(t *testing.T) {
	store := NewMemoryStore()
	clock := newTestClock()
	store.Clock = clock.now

	for _, eventType := range []string{"first", "second", "third"} {
		enqueue(t, store, eventType)
		clock.advance(time.Minute)
	}

	all, err := store.List(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("listed %d rows, want 3", len(all))
	}
	if all[0].EventType != "third" {
		t.Errorf("first row = %q, want the newest", all[0].EventType)
	}
	if all[2].EventType != "first" {
		t.Errorf("last row = %q, want the oldest", all[2].EventType)
	}

	limited, _ := store.List(context.Background(), "", 2)
	if len(limited) != 2 {
		t.Errorf("listed %d rows with limit 2", len(limited))
	}
	if limited[0].EventType != "third" || limited[1].EventType != "second" {
		t.Errorf("limited rows = %q, %q, want the two newest", limited[0].EventType, limited[1].EventType)
	}

	if pending, _ := store.List(context.Background(), StatusPending, 10); len(pending) != 3 {
		t.Errorf("pending rows = %d, want 3", len(pending))
	}
	if delivered, _ := store.List(context.Background(), StatusDelivered, 10); len(delivered) != 0 {
		t.Errorf("delivered rows = %d, want 0", len(delivered))
	}
}

func TestParseStatusRejectsAnythingElse(t *testing.T) {
	if got, err := ParseStatus("failed"); err != nil || got != StatusFailed {
		t.Errorf("ParseStatus(failed) = %q, %v", got, err)
	}
	for _, bad := range []string{"", "done", "PENDING", "pending "} {
		if _, err := ParseStatus(bad); !errors.Is(err, ErrInvalidStatus) {
			t.Errorf("ParseStatus(%q) error = %v, want ErrInvalidStatus", bad, err)
		}
	}
}

// A returned row is a copy, so a caller cannot resolve a delivery by editing
// a struct — the same thing a scanned row cannot do to a database.
func TestMemoryStoreHandsOutCopies(t *testing.T) {
	store := NewMemoryStore()
	id := enqueue(t, store, "account_locked")

	rows, _ := store.List(context.Background(), "", 10)
	rows[0].Status = StatusDelivered
	rows[0].Payload[0] = 'X'

	got, _ := store.Get(id)
	if got.Status != StatusPending {
		t.Errorf("status = %q after a caller edited its copy, want pending", got.Status)
	}
	if got.Payload[0] == 'X' {
		t.Error("a caller's edit to its payload buffer reached the stored row")
	}
}

// roundTripFunc is an http.RoundTripper that is a plain function, so a test
// can make the HTTP layer do something a real server cannot.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}
