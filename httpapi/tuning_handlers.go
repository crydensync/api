package httpapi

import (
	"net/http"
	"time"

	"github.com/crydensync/cryden/v2/admin"
	"github.com/crydensync/cryden/v2/store"

	"github.com/crydensync/api/config"
)

// TuningHandlers answers the config tuning advisor.
type TuningHandlers struct {
	// Audit is the same store instance main.go handed cryden (see Deps).
	// It satisfies admin.AuditReader as it stands — the point of that
	// interface is that Record is not in it, so a report built through it
	// has no way to write.
	Audit store.AuditStore

	// Config is what the suggestions are judged against: the settings
	// actually in force, read back off the config this process built.
	Config config.Config
}

// tuningSuggestionDTO is one observation and the change it points at.
// The three fields are cryden's own TuningSuggestion, unchanged — the
// console renders one card per suggestion from them, which is exactly why
// this endpoint returns the structured list rather than the flattened
// prose ConfigTuningReport produces.
type tuningSuggestionDTO struct {
	// Area names the knob the suggestion concerns. cryden's names, not
	// this repo's: "Lockout", "Rate limiting", "Anomaly detection",
	// "Credential stuffing", "Password strength".
	Area       string `json:"area"`
	Finding    string `json:"finding"`
	Suggestion string `json:"suggestion"`
}

// tuningDTO is the whole report.
//
// Counts is included alongside the suggestions even though the prose
// above already quotes the numbers: it is the raw audit counts the
// suggestions were computed from, so a console can show the evidence
// behind a recommendation instead of asking an operator to trust a
// sentence. Keys are audit event types, including ones this engine does
// not define.
type tuningDTO struct {
	Since       time.Time             `json:"since"`
	Until       time.Time             `json:"until"`
	WindowDays  int                   `json:"window_days"`
	Counts      map[string]int        `json:"counts"`
	Suggestions []tuningSuggestionDTO `json:"suggestions"`
}

// ConfigTuning — admin required (see router.go). Summarises recent audit
// history against this deployment's own tuning settings and suggests
// changes worth considering.
//
// # There is no write path here, and there is not going to be one
//
// This endpoint suggests. It has no counterpart that applies a
// suggestion, and no parameter that changes a setting — the decision
// already recorded for this surface is that a suggestion PRE-FILLS the
// settings field it concerns and a human still saves that change through
// the ordinary settings path. An endpoint that wrote a suggested value
// straight into live config would be exactly the violation CLAUDE.md's
// hard rule names, and it would also mean a bad suggestion silently
// changing production with no confirmation step.
//
// cryden's side of that is structural: admin.BuildTuningReport is handed
// an AuditReader with no Record on it, so the report cannot even write an
// audit event of its own. Running this twice is exactly like running it
// once.
//
// # Why the structured report
//
// This calls admin.BuildTuningReport directly rather than
// cryden.ConfigTuningReport, which wraps it and returns that report's
// Text(). The text is the right thing for a CLI and the wrong thing for a
// console: a pre-rendered blob cannot be rendered as one card per
// suggestion, and a client would be back to parsing English to find out
// which knob a paragraph was about. The Text() rendering remains the
// engine's own, and this repo does not reimplement it.
//
// An optional window_days query parameter sets the window; it defaults to
// cryden's own 30-day tuning window, which is deliberately wider than the
// digest's week — a config knob should be judged against a month of
// traffic, not whatever happened to occur this week.
func (h *TuningHandlers) ConfigTuning(w http.ResponseWriter, r *http.Request) {
	if h.Audit == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	windowDays, err := queryInt(r, "window_days", int(admin.DefaultTuningWindow.Hours()/24), 1, 365)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	since := time.Now().AddDate(0, 0, -windowDays)

	report, err := admin.BuildTuningReport(r.Context(), h.Audit, h.inputs(), since)
	if err != nil {
		writeErr(w, err)
		return
	}

	suggestions := make([]tuningSuggestionDTO, 0, len(report.Suggestions))
	for _, s := range report.Suggestions {
		suggestions = append(suggestions, tuningSuggestionDTO{
			Area:       s.Area,
			Finding:    s.Finding,
			Suggestion: s.Suggestion,
		})
	}

	writeData(w, http.StatusOK, tuningDTO{
		Since:       report.Since,
		Until:       report.Until,
		WindowDays:  windowDays,
		Counts:      eventCounts(report.Counts),
		Suggestions: suggestions,
	})
}

// inputs assembles the snapshot of current settings the report judges
// history against. Every value comes from the config this process
// actually built the engine from — never a second reading of the
// environment, which could disagree with what the engine is running.
//
// Two of these are worth reading the reasoning for:
//
//   - UsingDefaultRateLimiter is derived from RedisURL being empty, which
//     is the same condition main.go uses to decide whether to construct a
//     Redis limiter. Derived rather than stored as its own flag, so the
//     report and the wiring cannot drift.
//   - BreachedPasswordCheckerActive is always false today, and that is
//     accurate rather than a stub: this repo has never set
//     Config.BreachedPasswordChecker, because cryden ships no checker
//     implementation and every real one calls somebody else's breach
//     corpus. So the report says the checker is not set, which is true,
//     and a deployment that wires one in changes this line and the
//     engine wiring together.
func (h *TuningHandlers) inputs() admin.TuningInputs {
	return admin.TuningInputs{
		LockoutThreshold:        h.Config.LockoutThreshold,
		LockoutDuration:         h.Config.LockoutDuration,
		RateLimitAttempts:       h.Config.RateLimitAttempts,
		RateLimitWindow:         h.Config.RateLimitWindow,
		UsingDefaultRateLimiter: h.Config.RedisURL == "",

		AnomaliesEnabled:       h.Config.AnomalyDetection,
		UserFailureVelocity:    h.Config.AnomalyThresholds.UserFailureVelocity,
		IPFailureVelocity:      h.Config.AnomalyThresholds.IPFailureVelocity,
		HistorySize:            h.Config.AnomalyThresholds.HistorySize,
		StuffingTargetAccounts: h.Config.CredentialStuffingThresholds.TargetAccounts,
		StuffingWindow:         h.Config.CredentialStuffingThresholds.Window,
		StuffingCooldown:       h.Config.CredentialStuffingThresholds.Cooldown,

		BreachedPasswordCheckerActive: false,
	}
}

// eventCounts narrows the report's typed count map to plain strings for
// JSON. Done explicitly rather than relying on the encoder: a map key of
// a defined string type marshals the same way, but only by accident of
// encoding/json, and a response shape should not depend on that.
func eventCounts(counts map[store.AuditEventType]int) map[string]int {
	out := make(map[string]int, len(counts))
	for eventType, n := range counts {
		out[string(eventType)] = n
	}
	return out
}
