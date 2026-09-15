package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2/logger"

	"github.com/crydensync/api/shiplog"
)

// LoggingHandlers answers the admin view of the shipped-events log.
//
// Read-only, like every other endpoint on this surface (CLAUDE.md's hard
// rule): it lists records and can take no action. There is deliberately no
// endpoint that writes a record, edits LOG_LEVEL, or clears the log —
// changing what gets shipped is configuration, and configuration changes
// go through the same explicit, human-confirmed settings path every other
// one does.
type LoggingHandlers struct {
	// Store is this repo's own shipped-events table. Nil when
	// CLOUD_LOGGING is unset, which is a wiring fact rather than a server
	// fault — the same 404 not_configured shape the OAuth health and
	// hash-migration reports use for the same reason.
	Store shiplog.Store
}

// logEventDTO is one record. It is the redacted, filtered copy the cloud
// sink was handed, not the raw record on stdout — the two differ by
// design, and an operator reading this response is reading what would
// have left the building.
type logEventDTO struct {
	ID      int64             `json:"id"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
	Sink    string            `json:"sink"`

	// ShippedAt is when the sink wrote the record, which for a
	// synchronous sink is when the engine logged it. Nano-precision on
	// the wire, because one login emits many records and at second
	// precision they would arrive with identical timestamps and nothing
	// downstream could order them.
	ShippedAt time.Time `json:"shipped_at"`
}

// logEventsDTO is the whole response. Levels is included so a console can
// offer the filter without hardcoding the four names, and Level echoes the
// filter in force — an operator looking at a short list needs to know
// whether it is short because of the filter or because the engine has been
// quiet.
type logEventsDTO struct {
	Events []logEventDTO `json:"events"`
	Count  int           `json:"count"`

	// Level is the filter that was asked for, absent when none was. It is
	// the requested word rather than the resolved minimum: "warn" is what
	// an operator typed, and echoing "debug" back for an unfiltered
	// listing would suggest a filter that is not in force.
	Level  string   `json:"level,omitempty"`
	Levels []string `json:"levels"`
}

// Recent — admin required (see router.go). Lists the shipped-events log
// newest first, optionally restricted to a level and above.
func (h *LoggingHandlers) Recent(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	limit, err := queryLimit(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	// Unfiltered means everything, so the minimum starts at the least
	// severe level rather than at a zero value that happens to be the
	// same thing — the distinction matters if the constants ever move.
	minLevel := logger.LevelDebug
	var requested string
	if raw := queryString(r, "level"); raw != "" {
		minLevel, err = logger.ParseLevel(raw)
		if err != nil {
			// 400 naming the four valid values, rather than an empty list
			// a caller would read as "the engine logged nothing at this
			// level" — the same reasoning the delivery log's status
			// filter is built on.
			writeBadRequest(w, fmt.Sprintf("level must be one of: %s", strings.Join(shiplog.Levels(), ", ")))
			return
		}
		requested = strings.ToLower(raw)
	}

	entries, err := h.Store.List(r.Context(), minLevel, limit)
	if err != nil {
		writeErr(w, err)
		return
	}

	out := make([]logEventDTO, 0, len(entries))
	for _, e := range entries {
		out = append(out, logEventDTO{
			ID:        e.ID,
			Level:     e.Level.String(),
			Message:   e.Message,
			Fields:    e.Fields,
			Sink:      e.Sink,
			ShippedAt: e.ShippedAt,
		})
	}

	writeData(w, http.StatusOK, logEventsDTO{
		Events: out,
		Count:  len(out),
		Level:  requested,
		Levels: shiplog.Levels(),
	})
}
