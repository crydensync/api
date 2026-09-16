package httpapi

import (
	"net/http"
	"time"

	"github.com/crydensync/cryden/v2"

	"github.com/crydensync/api/digest"
)

// DigestHandlers answers the admin digest endpoints: the report itself,
// and the history of the ones the schedule produced.
type DigestHandlers struct {
	Engine *cryden.Engine

	// Store is the digest history — this repo's own table. Nil unless
	// DIGEST_INTERVAL_HOURS asked for a schedule, because the table is
	// only ever written by the scheduler: with no schedule there is no
	// history to read, and an empty list would be a lie about a
	// deployment that has never built one. The handler answers 404, the
	// same shape every other unconfigured feature in this API uses.
	Store digest.Store
}

// digestDefaultWindowDays is the reporting window used when the caller
// does not ask for another one. Seven days, matching cryden's own
// admin.DefaultDigestWindow — what makes the report a *weekly* digest —
// restated here rather than imported so this endpoint's bound and the
// engine's default are each readable where they are set, the same way
// hashMigrationDefaultWindowDays states the same week.
const digestDefaultWindowDays = 7

// digestRunDTO is one recorded run in the history listing.
type digestRunDTO struct {
	ID          int64     `json:"id"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	GeneratedAt time.Time `json:"generated_at"`

	// Text is the report exactly as the engine rendered it, stored at
	// the time and returned verbatim. It is included in a *listing*
	// rather than behind a fetch-by-id, because there is no fetch-by-id:
	// reading a past digest is the whole point of the history, and a
	// list of windows with no reports in it would be an index to
	// nothing.
	Text string `json:"text"`
}

// digestDTO is the on-demand report.
//
// Since and Until are reported alongside the text even though the text
// has the same window in its header, because a client should not have to
// parse English out of a report to learn what it covers — and because
// Until is this repo's clock reading, not something the engine returns.
type digestDTO struct {
	Since      time.Time `json:"since"`
	Until      time.Time `json:"until"`
	WindowDays int       `json:"window_days"`
	Text       string    `json:"text"`
}

// digestHistoryDTO is the whole history listing. Limit is echoed back so
// a console showing "20 of 143" knows which number it asked for without
// keeping its own copy of the default.
type digestHistoryDTO struct {
	Runs  []digestRunDTO `json:"runs"`
	Count int            `json:"count"`
	Limit int            `json:"limit"`
}

// Digest — admin required (see router.go). Builds a digest of the audit
// history and returns it. Read-only in the strongest sense available:
// cryden builds it through an interface with no way to write anything
// (admin.AuditReader has no Record), and this handler records nothing
// either — asking twice does not put two entries in the history. See
// CLAUDE.md's hard rule.
//
// An optional window_days query parameter sets the window; it defaults
// to a week and is bounded, so a caller cannot ask for a window so wide
// the report stops meaning anything.
func (h *DigestHandlers) Digest(w http.ResponseWriter, r *http.Request) {
	windowDays, err := queryInt(r, "window_days", digestDefaultWindowDays, 1, 365)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	// The window is computed here and passed to DigestSince, rather than
	// calling WeeklyDigest and describing the window afterwards. Both
	// produce the same report, but only this way is the Since reported
	// above the exact instant the engine was asked to count from — the
	// other would report a window a few microseconds out from the one
	// the text describes.
	since := time.Now().AddDate(0, 0, -windowDays)

	text, err := cryden.DigestSince(r.Context(), h.Engine, since)
	if err != nil {
		writeErr(w, err)
		return
	}

	writeData(w, http.StatusOK, digestDTO{
		Since:      since.UTC(),
		Until:      time.Now().UTC(),
		WindowDays: windowDays,
		Text:       text,
	})
}

// DigestHistory — admin required (see router.go). Lists the digests the
// schedule has recorded, newest first. Read-only: nothing here creates,
// deletes or re-runs a digest, so an operator cannot manufacture history
// through the API.
func (h *DigestHandlers) DigestHistory(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	limit, err := queryInt(r, "limit", digest.DefaultHistoryLimit, 1, digest.MaxHistoryLimit)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	runs, err := h.Store.List(r.Context(), limit)
	if err != nil {
		writeErr(w, err)
		return
	}

	out := make([]digestRunDTO, 0, len(runs))
	for _, run := range runs {
		out = append(out, digestRunDTO{
			ID:          run.ID,
			WindowStart: run.WindowStart,
			WindowEnd:   run.WindowEnd,
			GeneratedAt: run.GeneratedAt,
			Text:        run.Text,
		})
	}

	writeData(w, http.StatusOK, digestHistoryDTO{
		Runs:  out,
		Count: len(out),
		Limit: limit,
	})
}
