package httpapi

import (
	"net/http"

	"github.com/crydensync/cryden/v2"
)

type AccountHandlers struct {
	Engine *cryden.Engine
}

// ChangePassword — auth required. Revokes ALL sessions on success,
// including the one making this request — the client must discard
// its tokens and force a fresh login. This is real engine behavior,
// not an API-layer choice.
func (h *AccountHandlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	userID := UserIDFromContext(r)
	if err := cryden.ChangePassword(r.Context(), h.Engine, userID, req.CurrentPassword, req.NewPassword); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "password changed, please log in again"})
}

// DeleteAccount — auth required, requires current password re-confirmation.
func (h *AccountHandlers) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	userID := UserIDFromContext(r)
	if err := cryden.DeleteAccount(r.Context(), h.Engine, userID, req.CurrentPassword); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "account deleted"})
}
