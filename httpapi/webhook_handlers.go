package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crydensync/api/webhook"
)

// WebhookHandlers answers the admin webhook delivery log.
//
// Read-only, like the two reports beside it on the admin surface: it lists
// what the delivery worker has done and can take no action. Deliberately no
// "retry this delivery" endpoint here — that would be a write on a surface
// whose neighbouring feature is the AI-assisted tooling CLAUDE.md keeps
// read-only, and re-queuing a delivery is a decision an operator should make
// in the database with the evidence in front of them rather than through a
// button whose consequences are a third party's.
type WebhookHandlers struct {
	// Store is this repo's own delivery log (see the webhook package). Nil
	// when WEBHOOK_URL is unset, which is a wiring fact rather than a
	// server fault — cryden's own "not configured" convention, answered as
	// a 404.
	Store webhook.Store
}

// deliveryDTO is one row of the log. It carries the payload as raw JSON
// rather than re-encoding it, so what a console shows is the body that was
// actually POSTed — including key order, which is what a receiver's
// signature is computed over.
type deliveryDTO struct {
	ID        int64  `json:"id"`
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	UserID    string `json:"user_id,omitempty"`
	IP        string `json:"ip,omitempty"`

	Payload json.RawMessage `json:"payload"`

	Status webhook.Status `json:"status"`

	// Attempts counts attempts STARTED, which is why it is worth reporting
	// rather than hiding: a delivery at 3 of 5 tells an operator the
	// endpoint has been failing, and a row that failed outright says how
	// many tries it got.
	Attempts int `json:"attempts"`

	// ResponseCode is absent when no response arrived at all — a connection
	// failure or a timeout, which is a different problem from a receiver
	// answering 500, and one an operator fixes in a different place.
	ResponseCode int `json:"response_code,omitempty"`

	// Error is the receiver's own words where it gave any, so a failing
	// delivery can be diagnosed from this response alone.
	Error string `json:"error,omitempty"`

	DurationMS int `json:"duration_ms"`

	CreatedAt     time.Time  `json:"created_at"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
}

// deliveriesDTO is the whole response. Statuses is included so a console can
// offer the filter without hardcoding the four values, and Status echoes the
// filter in force — an operator looking at a short list needs to know
// whether it is short because of the filter or because of the traffic.
type deliveriesDTO struct {
	Deliveries []deliveryDTO    `json:"deliveries"`
	Count      int              `json:"count"`
	Status     webhook.Status   `json:"status,omitempty"`
	Statuses   []webhook.Status `json:"statuses"`
}

// Deliveries — admin required (see router.go). Lists the delivery log
// newest first, optionally filtered by status.
func (h *WebhookHandlers) Deliveries(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	limit, err := queryLimit(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	var status webhook.Status
	if raw := queryString(r, "status"); raw != "" {
		var err error
		status, err = webhook.ParseStatus(raw)
		if err != nil {
			// Reported as a 400 naming the four valid values rather than as
			// an unmapped error: an empty list would look like "no
			// deliveries", which is the one thing a filter must never be
			// able to be confused with.
			writeBadRequest(w, fmt.Sprintf("status must be one of: %s", strings.Join(statusNames(), ", ")))
			return
		}
	}

	rows, err := h.Store.List(r.Context(), status, limit)
	if err != nil {
		writeErr(w, err)
		return
	}

	out := make([]deliveryDTO, 0, len(rows))
	for _, d := range rows {
		out = append(out, deliveryDTO{
			ID:            d.ID,
			EventID:       d.EventID,
			EventType:     d.EventType,
			UserID:        d.UserID,
			IP:            d.IP,
			Payload:       d.Payload,
			Status:        d.Status,
			Attempts:      d.Attempts,
			ResponseCode:  d.ResponseCode,
			Error:         d.Error,
			DurationMS:    d.DurationMS,
			CreatedAt:     d.CreatedAt,
			NextAttemptAt: d.NextAttemptAt,
			DeliveredAt:   d.DeliveredAt,
		})
	}

	writeData(w, http.StatusOK, deliveriesDTO{
		Deliveries: out,
		Count:      len(out),
		Status:     status,
		Statuses:   webhook.Statuses(),
	})
}

func statusNames() []string {
	statuses := webhook.Statuses()
	out := make([]string, 0, len(statuses))
	for _, s := range statuses {
		out = append(out, string(s))
	}
	return out
}
