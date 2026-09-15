package httpapi

import (
	"net/http"
	"time"

	"github.com/crydensync/cryden/v2/store"

	"github.com/crydensync/api/config"
)

// SecurityHandlers answers the admin security reports.
type SecurityHandlers struct {
	// Audit and Users are the same store instances main.go handed cryden
	// (see Deps). Reading them directly is what makes this report possible
	// at all: cryden exposes no bulk way to inspect stored password hashes,
	// so the migration is measured from the audit events the engine already
	// records on an upgrade, against the user total.
	//
	// Both may be nil in a router built without them (tests). That is a
	// wiring fact, not a server fault, so it answers 404 rather than 500 —
	// the same shape as every other unconfigured feature in this API.
	Audit  store.AuditStore
	Users  store.UserStore
	Config config.Config
}

// hashMigrationDefaultWindowDays is the reporting window the endpoint uses
// when the caller does not ask for another one. A week matches the cadence
// an operator actually checks a migration on, and is the same window
// cryden's own weekly digest uses.
const hashMigrationDefaultWindowDays = 7

// hasherDTO reports what this deployment writes NEW password hashes with.
// It is read from configuration, not from the users table: cryden exposes
// no bulk way to inspect the algorithm behind a stored hash, and adding one
// would be the engine's job rather than this repo's (see CLAUDE.md's
// ownership rule). So this block describes the destination of the
// migration, never its current position — the counts below are the
// position.
type hasherDTO struct {
	// Algorithm is "bcrypt" or "argon2id" — whichever PASSWORD_HASHER
	// selected. Both are always verifiable: cryden wraps whichever hasher it
	// is given in a MultiHasher that picks the verifier from each stored
	// hash's own format, so old hashes keep working and are rewritten one
	// successful login at a time.
	Algorithm string `json:"algorithm"`

	// The Argon2id cost parameters, omitted entirely for bcrypt — they would
	// be meaningless there, and omitempty on a uint32 keeps them out rather
	// than reporting four zeroes a reader would have to know to ignore.
	MemoryKiB   uint32 `json:"memory_kib,omitempty"`
	Iterations  uint32 `json:"iterations,omitempty"`
	Parallelism uint8  `json:"parallelism,omitempty"`
}

// hashMigrationDTO is the whole report. The naming of the fields is
// deliberate and load-bearing:
//
//   - UpgradedEvents counts EVENTS, not users. A user whose hash is
//     rewritten twice — a second cost increase a year later — contributes
//     two, so this number can exceed TotalUsers. Calling it "upgraded_users"
//     would be reporting a figure that is right most of the time and
//     quietly wrong exactly when someone is watching it closely.
//   - EstimatedRemaining is therefore ESTIMATED, and floored at zero for
//     the same reason: TotalUsers - UpgradedEvents is only a user count if
//     every user upgraded exactly once, which is the normal case and not a
//     guarantee.
//
// Both names are the honest description of what is being computed, and the
// README and openapi/spec.yaml say the same thing in prose so the number
// does not get read as something it isn't.
//
// UpgradedEventsInWindow is the field that actually answers "is this
// draining": the all-time count only ever rises, while a windowed one falls
// to zero as the last stragglers log in.
type hashMigrationDTO struct {
	Hasher                 hasherDTO `json:"hasher"`
	TotalUsers             int       `json:"total_users"`
	UpgradedEvents         int       `json:"upgraded_events"`
	EstimatedRemaining     int       `json:"estimated_remaining"`
	WindowDays             int       `json:"window_days"`
	UpgradedEventsInWindow int       `json:"upgraded_events_in_window"`
}

// HashMigration — admin required (see router.go). Reports how far a
// password-hash migration has got, as the engine's own audit events against
// the user total. Read-only by construction: it calls two count methods and
// records nothing, the same rule every endpoint on the admin surface
// follows (see CLAUDE.md).
//
// An optional window_days query parameter sets the reporting window; it
// defaults to a week and is bounded, so a caller cannot ask for a window so
// wide the count stops meaning anything.
func (h *SecurityHandlers) HashMigration(w http.ResponseWriter, r *http.Request) {
	if h.Audit == nil || h.Users == nil {
		writeErr(w, errAdminStoresUnavailable)
		return
	}

	windowDays, err := queryInt(r, "window_days", hashMigrationDefaultWindowDays, 1, 365)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	ctx := r.Context()

	total, err := h.Users.Count(ctx)
	if err != nil {
		writeErr(w, err)
		return
	}

	// A zero time.Time as `since` is an open lower bound rather than a date
	// anyone chose: both store implementations read it as "at or after the
	// beginning of time", so this is the all-time count. CountByType returns
	// one entry per type that actually occurred and omits the rest, which is
	// why a missing key reads as zero here rather than as an error.
	allTime, err := h.Audit.CountByType(ctx, time.Time{})
	if err != nil {
		writeErr(w, err)
		return
	}
	windowed, err := h.Audit.CountByType(ctx, time.Now().AddDate(0, 0, -windowDays))
	if err != nil {
		writeErr(w, err)
		return
	}

	upgraded := allTime[store.EventPasswordHashUpgraded]
	remaining := total - upgraded
	if remaining < 0 {
		remaining = 0
	}

	writeData(w, http.StatusOK, hashMigrationDTO{
		Hasher:                 h.hasher(),
		TotalUsers:             total,
		UpgradedEvents:         upgraded,
		EstimatedRemaining:     remaining,
		WindowDays:             windowDays,
		UpgradedEventsInWindow: windowed[store.EventPasswordHashUpgraded],
	})
}

func (h *SecurityHandlers) hasher() hasherDTO {
	if h.Config.PasswordHasher != config.PasswordHasherArgon2id {
		// The engine's own default hasher. Its cost is cryden's default
		// BcryptCost, which this repo does not expose as a knob — see
		// PROGRESS.md's note on why BCRYPT_COST was left out of Tier 3.
		return hasherDTO{Algorithm: config.PasswordHasherBcrypt}
	}
	p := h.Config.Argon2idParams
	return hasherDTO{
		Algorithm:   config.PasswordHasherArgon2id,
		MemoryKiB:   p.Memory,
		Iterations:  p.Iterations,
		Parallelism: p.Parallelism,
	}
}
