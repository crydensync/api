package httpapi

import (
	"net/http"

	"github.com/crydensync/cryden/v2"
)

type MagicLinkHandlers struct {
	Engine *cryden.Engine
}

// Request — no auth, and deliberately answers the same way whether or
// not the email belongs to an account: this does not create accounts,
// and anything else would let a caller enumerate registered emails one
// request at a time. cryden returns nil for an unknown address (nothing
// was sent) and only propagates a real delivery failure for an address
// that does exist.
func (h *MagicLinkHandlers) Request(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	if err := cryden.RequestMagicLink(r.Context(), h.Engine, req.Email, CallerIP(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{})
}

// Complete — no auth. The raw token from the emailed link is the proof
// of authorization. Like password login, this can pause for a second
// factor: an account with TOTP or a passkey enrolled gets the same
// second_factor_required response here as it would after a correct
// password.
func (h *MagicLinkHandlers) Complete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	tokens, err := cryden.CompleteMagicLink(r.Context(), h.Engine, req.Token, CallerIP(r), UserAgent(r))
	if err != nil {
		if writeTokensOrPause(w, err) {
			return
		}
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, toTokensDTO(tokens))
}
