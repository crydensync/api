package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/crydensync/cryden/v2/notify"
)

// Sender is the notify.WebhookSender this repo hands the engine.
//
// SendWebhook records a delivery and returns. It makes NO HTTP call — that
// is the entire reason it exists in this shape. cryden calls it
// synchronously, in the same goroutine as the login that triggered it (see
// notify.WebhookSender's own doc comment), so an http.Client.Do in here is
// a third party's downtime becoming this deployment's login latency.
//
// The queue is the database row, and that choice is deliberate rather than
// incidental: a channel would be faster and would lose everything on
// restart — and a crash between the audit write and the delivery is
// precisely the case this log exists to make visible. The channel here is
// only a nudge telling the worker there is likely to be work.
type Sender struct {
	// Store is where the delivery row goes. Enqueue is the only method this
	// type calls.
	Store Store

	// Wake is nudged, non-blockingly, after a successful enqueue. It is a
	// hint and never a guarantee: a full buffer, a nil channel or a worker
	// that is not running all simply mean the worker finds the row on its
	// next poll instead. Nothing about correctness depends on it.
	Wake chan<- struct{}

	// EnqueueTimeout bounds the insert. Zero means DefaultEnqueueTimeout.
	//
	// A bound exists because the insert runs on the request path: without
	// one, a wedged database would hold a login open indefinitely. Five
	// seconds is long enough that a merely slow insert still makes it and
	// short enough that a broken one fails while the user is still waiting.
	EnqueueTimeout time.Duration
}

// DefaultEnqueueTimeout bounds the insert SendWebhook performs.
const DefaultEnqueueTimeout = 5 * time.Second

var _ notify.WebhookSender = (*Sender)(nil)

// payload is the body a receiver gets. It is a struct rather than a
// map[string]any so the wire format is a decision made here and visible in
// one place, and so adding a field cannot silently change the order of the
// existing ones.
type payload struct {
	// ID is the engine's idempotency key for this occurrence, and the same
	// value as the X-Cryden-Event-Id header. Always present, possibly
	// empty: cryden generates it with crypto/rand and deliberately
	// delivers an event without one rather than not at all, so an empty
	// string here is information ("the generator failed") rather than a
	// bug.
	ID string `json:"id"`

	// Type is the recorded audit event type, e.g. "account_locked". A
	// receiver should treat an unrecognised value as a reason to ignore the
	// event, not to fail: the engine adds types, and this repo must not
	// need a deploy to learn about one.
	Type string `json:"type"`

	// UserID is whose account the event concerns, empty for the events that
	// genuinely have no user behind them — a failed login naming an email
	// nobody registered, for one.
	UserID string `json:"user_id,omitempty"`
	IP     string `json:"ip,omitempty"`

	// OccurredAt is when the engine recorded the event, in UTC.
	OccurredAt time.Time `json:"occurred_at"`

	// Metadata is the audit event's own metadata, unchanged — its keys are
	// documented per event type on cryden's constants.
	//
	// Note what is NOT here: the attempt number. The body is built once, at
	// enqueue, and every retry sends these same bytes, which is what lets
	// the delivery log answer "what did we send?" for a retry as well as a
	// first attempt. Per-attempt information travels in the
	// X-Cryden-Delivery-Attempt header instead.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SendWebhook implements notify.WebhookSender. It returns an error only when
// the delivery could not be recorded; cryden logs that and lets the login
// succeed regardless, which is the contract (a webhook is a notification,
// not a gate).
//
// A panic is not reported as an error — it propagates, exactly as the
// interface documents. Nothing here can panic on a plausible input, and
// swallowing one would hide a real bug behind a log line.
func (s *Sender) SendWebhook(ctx context.Context, event notify.WebhookEvent) error {
	body, err := json.Marshal(payload{
		ID:         event.ID,
		Type:       event.Type,
		UserID:     event.UserID,
		IP:         event.IP,
		OccurredAt: event.OccurredAt.UTC(),
		Metadata:   event.Metadata,
	})
	if err != nil {
		return fmt.Errorf("encoding webhook payload: %w", err)
	}

	// context.WithoutCancel, deliberately, and this is the one place the
	// obvious implementation is wrong. ctx is the triggering request's, and
	// the engine's own doc comment warns that it may already be cancelled
	// by the time a slow sender gets to use it. An insert that honoured
	// that would drop the event precisely when the request went away —
	// and this row is the only record that it ever happened. The event is
	// worth more than the connection it arrived on, the same reasoning
	// cryden applies to a failed id generation.
	//
	// The timeout is what stops that from becoming "a wedged database holds
	// a login open forever": cancellation is dropped, the deadline is not.
	timeout := s.EnqueueTimeout
	if timeout <= 0 {
		timeout = DefaultEnqueueTimeout
	}
	enqueueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	if err := s.Store.Enqueue(enqueueCtx, Delivery{
		EventID:   event.ID,
		EventType: event.Type,
		UserID:    event.UserID,
		IP:        event.IP,
		Payload:   body,
	}); err != nil {
		return err
	}

	// Non-blocking, and nil-safe: a send on a nil channel would block
	// forever, but a nil channel in a select is simply never ready, so this
	// falls through to the worker's next poll.
	select {
	case s.Wake <- struct{}{}:
	default:
	}
	return nil
}
