package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/crydensync/cryden/v2"
)

type PasskeyHandlers struct {
	Engine *cryden.Engine
}

// passkeyDTO keeps cryden's storage detail out of the API response and
// the field names in this repo's snake_case convention. CredentialID is
// base64url-encoded by cryden itself, matching how credential IDs travel
// in the WebAuthn spec — pass it back verbatim to delete.
type passkeyDTO struct {
	CredentialID string `json:"credential_id"`
	Nickname     string `json:"nickname"`
	CreatedAt    string `json:"created_at"`
	LastUsedAt   string `json:"last_used_at,omitempty"`
}

// RegisterBegin — auth required. Returns the ceremony options to hand to
// navigator.credentials.create() and the ceremony token that must come
// back to RegisterFinish unmodified. The options are emitted as raw JSON
// so the client receives them as an object, not a JSON-encoded string it
// would have to parse twice.
func (h *PasskeyHandlers) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r)
	optionsJSON, ceremonyToken, err := cryden.BeginRegisterPasskey(r.Context(), h.Engine, userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{
		"public_key":     json.RawMessage(optionsJSON),
		"ceremony_token": ceremonyToken,
	})
}

// RegisterFinish — auth required. `credential` is the raw JSON the
// browser produced in navigator.credentials.create(); it is passed
// through to the engine unmodified (any shape checking the engine needs
// to do, it does itself).
func (h *PasskeyHandlers) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CeremonyToken string          `json:"ceremony_token"`
		Credential    json.RawMessage `json:"credential"`
		Nickname      string          `json:"nickname"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}
	if req.CeremonyToken == "" {
		writeBadRequest(w, "ceremony_token is required")
		return
	}
	if len(req.Credential) == 0 {
		writeBadRequest(w, "credential is required")
		return
	}

	userID := UserIDFromContext(r)
	if err := cryden.FinishRegisterPasskey(r.Context(), h.Engine, userID, req.CeremonyToken, req.Credential, req.Nickname); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "passkey registered"})
}

// List — auth required.
func (h *PasskeyHandlers) List(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r)
	passkeys, err := cryden.ListPasskeys(r.Context(), h.Engine, userID)
	if err != nil {
		writeErr(w, err)
		return
	}

	out := make([]passkeyDTO, 0, len(passkeys))
	for _, p := range passkeys {
		dto := passkeyDTO{
			CredentialID: p.CredentialID,
			Nickname:     p.Nickname,
			CreatedAt:    p.CreatedAt.Format(time.RFC3339),
		}
		if p.LastUsedAt != nil {
			dto.LastUsedAt = p.LastUsedAt.Format(time.RFC3339)
		}
		out = append(out, dto)
	}
	writeData(w, http.StatusOK, out)
}

// Delete — auth required. credentialID comes from the URL path (wired in
// router.go); the current password is re-confirmation, same reasoning as
// DisableTOTP.
func (h *PasskeyHandlers) Delete(w http.ResponseWriter, r *http.Request, credentialID string) {
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	userID := UserIDFromContext(r)
	if err := cryden.DeletePasskey(r.Context(), h.Engine, userID, credentialID, req.Password); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "passkey removed"})
}

// LoginBegin — no auth. Starts the passkey half of a login that
// /v1/login paused, using the pending token from that response.
func (h *PasskeyHandlers) LoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PendingToken string `json:"pending_token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	optionsJSON, ceremonyToken, err := cryden.BeginWebAuthnLogin(r.Context(), h.Engine, req.PendingToken)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{
		"public_key":     json.RawMessage(optionsJSON),
		"ceremony_token": ceremonyToken,
	})
}

// LoginFinish — no auth. `credential` is the raw JSON the browser
// produced in navigator.credentials.get().
func (h *PasskeyHandlers) LoginFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PendingToken  string          `json:"pending_token"`
		CeremonyToken string          `json:"ceremony_token"`
		Credential    json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}
	if req.PendingToken == "" || req.CeremonyToken == "" {
		writeBadRequest(w, "pending_token and ceremony_token are required")
		return
	}
	if len(req.Credential) == 0 {
		writeBadRequest(w, "credential is required")
		return
	}

	tokens, err := cryden.CompleteLoginWithWebAuthn(r.Context(), h.Engine, req.PendingToken, req.CeremonyToken, req.Credential, CallerIP(r), UserAgent(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, toTokensDTO(tokens))
}
