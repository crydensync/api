package httpapi

import (
	"net/http"

	"github.com/crydensync/cryden/v2"
)

type EmailHandlers struct {
	Engine *cryden.Engine
}

// RequestChange — auth required.
func (h *EmailHandlers) RequestChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewEmail string `json:"new_email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	userID := UserIDFromContext(r)
	if err := cryden.RequestEmailChange(r.Context(), h.Engine, userID, req.NewEmail); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "verification email sent"})
}

// ConfirmChange — deliberately public, no auth middleware. The token
// itself (from the email link) is the proof of authorization — the
// user clicking it may not have an active browser session.
func (h *EmailHandlers) ConfirmChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	if err := cryden.ConfirmEmailChange(r.Context(), h.Engine, req.Token); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "email changed"})
}
