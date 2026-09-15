package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Defaults for every knob. A zero field means "use this", so a Worker built
// by hand cannot end up with a budget of zero attempts or a poll interval
// that spins the CPU.
const (
	DefaultPollInterval = 15 * time.Second
	DefaultBatchSize    = 20
	DefaultMaxAttempts  = 5

	// DefaultStaleAfter is how long a claimed row may sit in_flight before
	// another pass treats its worker as gone. It has to be comfortably
	// longer than the HTTP timeout below, or a merely slow delivery would
	// be claimed out from under the worker still making it — and the
	// receiver would get the event twice.
	DefaultStaleAfter = 5 * time.Minute

	// defaultHTTPTimeout bounds one delivery attempt. The worker is
	// single-goroutine and serial, so this is also the worst case added to
	// every other delivery's latency in the same batch.
	defaultHTTPTimeout = 10 * time.Second

	// backoffBase and backoffMax bound the exponential retry schedule:
	// 30s, 1m, 2m, 4m, 8m ... out to 30m. At the default five attempts that
	// is a delivery resolved or given up on inside about eight minutes,
	// which is short enough that an operator watching the console sees the
	// outcome of a change they just made.
	backoffBase = 30 * time.Second
	backoffMax  = 30 * time.Minute

	// maxResponseSnippet bounds how much of a failing receiver's response
	// body is kept. The point is to keep "your endpoint said: database is
	// down" in the log, not to archive a third party's error pages.
	maxResponseSnippet = 512

	// userAgent identifies this worker to a receiver's access log.
	userAgent = "cryden-webhook/1.0"

	// SignatureHeader carries Sign's output. Exported knowledge rather than
	// an internal detail: it is the header a receiver implements against.
	SignatureHeader = "X-Cryden-Signature"
)

// Worker makes the deliveries. One goroutine is enough by design — SKIP
// LOCKED in the Postgres claim means raising the count later is safe and
// needs no change here, and the default event set is deliberately
// low-volume (see cryden.DefaultWebhookEvents).
type Worker struct {
	Store Store

	// URL is where deliveries are POSTed. Required: a Worker with no URL
	// does nothing rather than guessing.
	URL string

	// Secret is the HMAC key for the signature header. Empty means the
	// deliveries go out UNSIGNED and no signature header is sent — not a
	// header computed over an empty key, which a receiver might mistake for
	// a real one. A trusted endpoint on a private network is a legitimate
	// configuration; the worker says so once at startup.
	Secret string

	// MaxAttempts is the total number of attempts a delivery gets,
	// including the first. Zero means DefaultMaxAttempts.
	MaxAttempts int

	// Client makes the calls. Zero means a client with a 10s timeout that
	// refuses to follow a redirect to a different host.
	Client *http.Client

	// Log receives operational lines — a failed attempt, a panic, a batch
	// error. Nil means silent, which is what a test wants.
	Log *log.Logger

	// Now is the clock, for the retry schedule and for claim cutoffs. Zero
	// means time.Now.
	Now func() time.Time

	// PollInterval is how often the worker looks for work even when nothing
	// has nudged it — the safety net for a nudge lost to a full buffer or a
	// row due in the future whose backoff has just elapsed. Zero means
	// DefaultPollInterval.
	PollInterval time.Duration

	// BatchSize is the most rows claimed per pass. Zero means
	// DefaultBatchSize.
	BatchSize int

	// StaleAfter is how long an in_flight row may sit before it is
	// reclaimed. Zero means DefaultStaleAfter.
	StaleAfter time.Duration

	// Wake is the channel Sender nudges. Nil is fine: the worker then runs
	// on its poll interval alone.
	Wake <-chan struct{}
}

// NewWorker builds a worker with every default filled in, so no exported
// field on the result is ever a zero that means something other than zero.
// Only the two arguments without a sensible default are required; the rest
// are set by the caller afterwards.
func NewWorker(store Store, url, secret string) *Worker {
	w := &Worker{Store: store, URL: url, Secret: secret}
	w.applyDefaults()
	return w
}

// Sign computes the value of SignatureHeader for a body: HMAC-SHA256 over
// the raw bytes, hex-encoded, prefixed with the algorithm so a receiver can
// tell which scheme it is looking at without having to guess.
//
// Exported, along with Verify, so a receiver written in Go can use this
// rather than reimplementing it — and so a test can assert a real signature
// rather than a string it produced itself.
//
// A receiver in another language needs this much: HMAC-SHA256, key = the
// shared secret as UTF-8 bytes, message = the request body byte for byte,
// lowercase hex, "sha256=" in front.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether header is a valid signature for body under secret.
// Comparison is constant-time, so a receiver using this does not leak the
// expected digest through timing.
func Verify(secret string, body []byte, header string) bool {
	return hmac.Equal([]byte(Sign(secret, body)), []byte(header))
}

// Run delivers until ctx is cancelled. It is meant to be started once, in
// its own goroutine; main.go passes context.Background() because this repo
// has no graceful shutdown anywhere yet (see PROGRESS.md — introducing one
// touches every component and is its own change, not a passenger on this
// one).
func (w *Worker) Run(ctx context.Context) {
	w.applyDefaults()
	if w.Secret == "" {
		w.logf("webhook worker: WEBHOOK_SECRET is not set — deliveries are unsigned")
	}

	ticker := time.NewTicker(w.PollInterval)
	defer ticker.Stop()

	for {
		// Drain before sleeping: a batch that came back full almost
		// certainly means there is more waiting, and waiting a whole poll
		// interval to find that out would put a backlog behind the
		// interval for no reason.
		for {
			n, err := w.RunOnce(ctx)
			if err != nil {
				// A database error is not retried in a tight loop — the
				// poll interval is the backoff, which keeps a broken
				// connection from becoming a busy loop.
				if ctx.Err() == nil {
					w.logf("webhook worker: %v", err)
				}
				break
			}
			if n < w.BatchSize || ctx.Err() != nil {
				break
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-w.Wake:
		case <-ticker.C:
		}
	}
}

// RunOnce claims and delivers one batch, returning how many rows it claimed.
// It is the whole of the worker's behaviour without the loop, so tests drive
// it directly and deterministically instead of racing a goroutine.
//
// A cancelled ctx can leave claimed rows in_flight and un-attempted; the
// stale reclaim picks them up. That is why Attempts counts attempts
// STARTED rather than attempts that reached an endpoint.
func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	w.applyDefaults()

	claimed, err := w.Store.ClaimDue(ctx, w.Now(), w.BatchSize, w.MaxAttempts, w.StaleAfter)
	if err != nil {
		return 0, err
	}

	for _, d := range claimed {
		if ctx.Err() != nil {
			break
		}
		w.deliver(ctx, d)
	}
	return len(claimed), nil
}

// deliver makes one attempt and resolves the row.
func (w *Worker) deliver(ctx context.Context, d Delivery) {
	// A panic here would otherwise take the process with it. That is worth
	// diverging from the engine's own "a panicking sender should fail
	// loudly" advice for: cryden's reasoning is about the REQUEST path,
	// where failing loudly is cheap and is seen on the first request. This
	// runs in a background goroutine, so the same bug would turn a webhook
	// problem into "nobody can log in" — a far worse outcome than a
	// retried delivery and a loud log line.
	defer func() {
		if r := recover(); r != nil {
			w.logf("webhook worker: panic delivering %d (%s): %v", d.ID, d.EventType, r)
			w.resolve(ctx, d, Result{Err: fmt.Sprintf("panic while delivering: %v", r)})
		}
	}()

	w.resolve(ctx, d, w.post(ctx, d))
}

// resolve records the outcome of an attempt: delivered, retried, or given
// up on.
//
// Note the ordering in the caller: the attempt is always made first, and
// this only decides what to do with the result. So a row reclaimed from a
// crashed worker — whose Attempts is already at the budget — gets one more
// real attempt rather than being written off unvisited. That is deliberate,
// and it is bounded: ClaimDue only ignores the budget on its stale branch,
// and this method then resolves the row either way, so a crash costs at most
// one attempt beyond MaxAttempts and can never become a loop. Delivering an
// event the receiver may never have got is worth more than a row that says
// "failed" without anyone having tried.
func (w *Worker) resolve(ctx context.Context, d Delivery, result Result) {
	if result.Code >= 200 && result.Code < 300 {
		if err := w.Store.MarkDelivered(ctx, d.ID, result); err != nil {
			w.logf("webhook worker: recording delivery %d as delivered: %v", d.ID, err)
		}
		return
	}

	if result.Err == "" {
		result.Err = fmt.Sprintf("receiver answered %d", result.Code)
	}

	// d.Attempts is the count ClaimDue returned, which is already
	// incremented for the attempt just made — so this is "attempt 5 of 5"
	// on the fifth. Comparing before scheduling the retry is what makes
	// MaxAttempts mean exactly that, rather than one attempt more.
	if d.Attempts >= w.MaxAttempts {
		w.logf("webhook worker: giving up on delivery %d (%s) after %d attempts: %s",
			d.ID, d.EventType, d.Attempts, result.Err)
		if err := w.Store.MarkFailed(ctx, d.ID, result, nil); err != nil {
			w.logf("webhook worker: recording delivery %d as failed: %v", d.ID, err)
		}
		return
	}

	retryAt := w.Now().Add(backoff(d.Attempts))
	if err := w.Store.MarkFailed(ctx, d.ID, result, &retryAt); err != nil {
		w.logf("webhook worker: rescheduling delivery %d: %v", d.ID, err)
	}
}

// post makes the HTTP call and reports what happened. It never returns an
// error: a delivery failure is data to be recorded, not a Go error to be
// propagated, and every path here ends in a Result.
func (w *Worker) post(ctx context.Context, d Delivery) Result {
	start := w.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(d.Payload))
	if err != nil {
		// A malformed WEBHOOK_URL. Retried rather than terminal, because
		// the row would otherwise be lost to a typo an operator is about
		// to fix — and the error is in the log either way.
		return Result{Duration: w.Now().Sub(start), Err: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Cryden-Event-Type", d.EventType)

	// The headers below are informational and deliberately NOT covered by
	// the signature, which is over the body alone. A receiver must not make
	// a decision on them; it can use the attempt number for its own logs.
	if d.EventID != "" {
		req.Header.Set("X-Cryden-Event-Id", d.EventID)
	}
	req.Header.Set("X-Cryden-Delivery-Attempt", strconv.Itoa(d.Attempts))

	if w.Secret != "" {
		req.Header.Set(SignatureHeader, Sign(w.Secret, d.Payload))
	}

	resp, err := w.Client.Do(req)
	if err != nil {
		return Result{Duration: w.Now().Sub(start), Err: err.Error()}
	}
	defer resp.Body.Close()

	// Read a bounded snippet, which both keeps the connection reusable for
	// the next delivery and gives a failing receiver's own words a place in
	// the log — "your endpoint said: database is down" is the difference
	// between a delivery log an operator can act on and a row that only
	// says 500.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSnippet))
	result := Result{Code: resp.StatusCode, Duration: w.Now().Sub(start)}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Err = fmt.Sprintf("receiver answered %d: %s", resp.StatusCode, snippetText(snippet))
	}
	return result
}

// snippetText renders a response body for the log: whitespace collapsed so
// it stays one line, and bounded again because a body full of no-break
// spaces would otherwise be a small wall of text in a console.
func snippetText(raw []byte) string {
	text := strings.Join(strings.Fields(string(raw)), " ")
	if len(text) > 200 {
		text = text[:200] + "…"
	}
	if text == "" {
		return "(no body)"
	}
	return text
}

// backoff is the retry delay after attempt n (1-based). Doubling with a
// cap, no jitter: one worker claims rows in batches, so a set of deliveries
// failing together is already spread across passes rather than hammering a
// receiver in the same instant. Running several workers would want jitter
// here — noted rather than pre-built.
func backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	// Capped before shifting so a large value shifts into a negative
	// duration rather than being caught by the comparison below.
	if attempt > 20 {
		return backoffMax
	}
	d := backoffBase << (attempt - 1)
	if d <= 0 || d > backoffMax {
		return backoffMax
	}
	return d
}

func (w *Worker) applyDefaults() {
	if w.MaxAttempts <= 0 {
		w.MaxAttempts = DefaultMaxAttempts
	}
	if w.Now == nil {
		w.Now = func() time.Time { return time.Now().UTC() }
	}
	if w.PollInterval <= 0 {
		w.PollInterval = DefaultPollInterval
	}
	if w.BatchSize <= 0 {
		w.BatchSize = DefaultBatchSize
	}
	if w.StaleAfter <= 0 {
		w.StaleAfter = DefaultStaleAfter
	}
	if w.Client == nil {
		w.Client = defaultClient()
	}
}

// defaultClient bounds one attempt and refuses a redirect to another host.
//
// The timeout is the obvious half. The redirect rule is the less obvious
// one: the configured URL is where the operator wants their events to go,
// and following a redirect to a different host would deliver the body, and
// the signature over it, wherever that host said. A same-host redirect —
// http to https, a missing trailing slash — still works, which is the
// common legitimate case.
func defaultClient() *http.Client {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("refusing to follow a redirect from %s to %s", via[0].URL.Host, req.URL.Host)
			}
			return nil
		},
	}
}

func (w *Worker) logf(format string, args ...any) {
	if w.Log != nil {
		w.Log.Printf(format, args...)
	}
}
