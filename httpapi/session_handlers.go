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
type sessionDTO struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	CreatedAt string `json:"created_at"`
}

// List — auth required
func (h *SessionHandlers) List(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r)
	sessions, err := cryden.ListSessions(r.Context(), h.Engine, userID)
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
