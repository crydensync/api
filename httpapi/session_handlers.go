package httpapi

import (
	"net/http"

	"github.com/crydensync/cryden/v2"
)

type SessionHandlers struct {
	Engine *cryden.Engine
}

// sessionDTO deliberately excludes TokenHash and FamilyID — the
// client never needs the hashed refresh token, and there's no reason
// to expose it over the API even hashed. Built this way from the
// start here, unlike typebook's backend where this had to be caught
// and fixed after the fact — same lesson, applied proactively.
//
// Label, Device and Location are derived on read from the IP and
// User-Agent the session already carries (cryden.ListNamedSessions), so
// nothing about them is stored and every session ever recorded has a
// label the moment this is called. The structured halves travel
// alongside the label so a client can group or sort by OS, form factor
// or country without re-parsing a display string.
type sessionDTO struct {
	ID        string      `json:"id"`
	IP        string      `json:"ip"`
	UserAgent string      `json:"user_agent"`
	CreatedAt string      `json:"created_at"`
	Label     string      `json:"label"`
	Device    deviceDTO   `json:"device"`
	Location  locationDTO `json:"location"`
}

// deviceDTO is security.Device, which is what the engine recognised in
// the session's User-Agent. Every field is "" when nothing matched —
// "Unknown device" is the label's job, not this struct's.
type deviceDTO struct {
	Browser string `json:"browser"`
	OS      string `json:"os"`
	// Form is "desktop", "mobile", "tablet", "bot" or "".
	Form string `json:"form"`
}

// locationDTO is security.Location. All three fields are empty unless a
// geolocator is configured (see Config.Geolocator) — this repo wires
// none, deliberately: every implementation of that interface calls
// somebody else's internet service, which is a deployment's decision to
// make, not this repo's to make for it. Labels are device-only without
// one, which is why Label is never empty either way.
type locationDTO struct {
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
}

// List — auth required. Returns named sessions: a deliberate change to
// this endpoint's response shape (label, device and location are new
// fields; the four that were already there keep their names), recorded
// in openapi/spec.yaml and the README rather than slipped in as an
// undocumented extra.
func (h *SessionHandlers) List(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r)
	sessions, err := cryden.ListNamedSessions(r.Context(), h.Engine, userID)
	if err != nil {
		writeErr(w, err)
		return
	}

	out := make([]sessionDTO, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionDTO{
			ID:        s.ID,
			IP:        s.IP,
			UserAgent: s.UserAgent,
			CreatedAt: s.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			Label:     s.Label,
			Device: deviceDTO{
				Browser: s.Device.Browser,
				OS:      s.Device.OS,
				Form:    s.Device.Form,
			},
			Location: locationDTO{
				City:    s.Location.City,
				Region:  s.Location.Region,
				Country: s.Location.Country,
			},
		})
	}
	writeData(w, http.StatusOK, out)
}

// Revoke — auth required. sessionID comes from the URL path, wired in router.go.
func (h *SessionHandlers) Revoke(w http.ResponseWriter, r *http.Request, sessionID string) {
	userID := UserIDFromContext(r)
	if err := cryden.RevokeSession(r.Context(), h.Engine, sessionID, userID); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "session revoked"})
}
