package httpapi

import (
	"net/http"

	"github.com/crydensync/cryden/v2"
)

type AuthHandlers struct {
	Engine *cryden.Engine
}

func (h *AuthHandlers) SignUp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	user, err := cryden.SignUp(r.Context(), h.Engine, req.Email, req.Password, CallerIP(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusCreated, map[string]string{"user_id": user.ID, "email": user.Email})
}

// tokensDTO ensures a consistent snake_case JSON contract. Passing
// cryden.Tokens straight through would leak Go's PascalCase exported
// field names (AccessToken, RefreshToken) into the API response —
// caught by actually running this against real HTTP, not by review.
type tokensDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func toTokensDTO(t cryden.Tokens) tokensDTO {
	return tokensDTO{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken}
}

func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	tokens, err := cryden.Login(r.Context(), h.Engine, req.Email, req.Password, CallerIP(r), UserAgent(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, toTokensDTO(tokens))
}

func (h *AuthHandlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	tokens, err := cryden.RefreshToken(r.Context(), h.Engine, req.RefreshToken)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, toTokensDTO(tokens))
}

// Logout — auth required
func (h *AuthHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	userID := UserIDFromContext(r)
	if err := cryden.Logout(r.Context(), h.Engine, req.SessionID, userID); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// LogoutAll — auth required
func (h *AuthHandlers) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r)
	if err := cryden.LogoutAll(r.Context(), h.Engine, userID); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "logged out of all devices"})
}

// Verify — auth required (the middleware already did the work; if we
// got here, the token is valid). Lets a client cheaply check "am I
// still logged in" without a side-effecting call.
func (h *AuthHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	writeData(w, http.StatusOK, map[string]string{"user_id": UserIDFromContext(r)})
}
