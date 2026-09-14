package httpapi

import (
	"net/http"

	"github.com/crydensync/cryden/v2"
)

type RecoveryHandlers struct {
	Engine *cryden.Engine
}

// recoveryCodesNotice is echoed in the response body because the raw
// codes below exist in exactly one place — this response. cryden stores
// only their hashes and can never show them again.
const recoveryCodesNotice = "these codes are shown only once and each one works a single time — store them somewhere safe now, they cannot be retrieved later"

// Generate — auth required. Replaces any existing batch. Requires a
// confirmed TOTP secret or a registered passkey already on the account
// (there is nothing for a fallback code to fall back to otherwise).
func (h *RecoveryHandlers) Generate(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r)
	codes, err := cryden.GenerateRecoveryCodes(r.Context(), h.Engine, userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if codes == nil {
		codes = []string{}
	}
	writeData(w, http.StatusOK, map[string]any{
		"codes":  codes,
		"notice": recoveryCodesNotice,
	})
}

// Login — no auth. Completes a login that /v1/login (or a magic-link or
// OAuth login) paused with a second_factor_required response, using one
// of the account's recovery codes instead of TOTP or a passkey.
func (h *RecoveryHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PendingToken string `json:"pending_token"`
		Code         string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	tokens, err := cryden.CompleteLoginWithRecoveryCode(r.Context(), h.Engine, req.PendingToken, req.Code, CallerIP(r), UserAgent(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, toTokensDTO(tokens))
}
