package httpapi

import (
	"net/http"

	"github.com/crydensync/cryden/v2"
)

type TOTPHandlers struct {
	Engine *cryden.Engine
}

// Enroll — auth required. Starts TOTP enrollment and returns the
// otpauth:// URL for the client to render as a QR code. The secret does
// not gate login until Confirm succeeds.
func (h *TOTPHandlers) Enroll(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r)
	otpauthURL, err := cryden.EnrollTOTP(r.Context(), h.Engine, userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"otpauth_url": otpauthURL})
}

// Confirm — auth required. Activates a pending enrollment once the user
// proves they captured the secret by submitting one valid code.
func (h *TOTPHandlers) Confirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	userID := UserIDFromContext(r)
	if err := cryden.ConfirmTOTP(r.Context(), h.Engine, userID, req.Code); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "totp confirmed"})
}

// Disable — auth required. Requires the current password as
// re-confirmation, same reasoning as change-password and delete-account:
// a stolen access token alone should not be able to weaken an account's
// own auth requirements.
func (h *TOTPHandlers) Disable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	userID := UserIDFromContext(r)
	if err := cryden.DisableTOTP(r.Context(), h.Engine, userID, req.Password); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "totp disabled"})
}

// Login — no auth. Completes a login /v1/login paused with a
// second_factor_required response, using the pending token and a code
// from the user's authenticator app.
func (h *TOTPHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PendingToken string `json:"pending_token"`
		Code         string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	tokens, err := cryden.CompleteLoginWithTOTP(r.Context(), h.Engine, req.PendingToken, req.Code, CallerIP(r), UserAgent(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, toTokensDTO(tokens))
}
