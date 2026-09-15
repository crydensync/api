package httpapi

import (
	"net/http"

	"github.com/crydensync/cryden/v2"
)

// SupportHandlers answers the support-ticket assistant.
type SupportHandlers struct {
	Engine *cryden.Engine
}

// supportDiagnosisDTO is one diagnosis. Text is the report the engine
// built; Email is echoed back because the whole point of this endpoint is
// to answer "why can't THIS person log in", and a support agent pasting
// addresses into a console should be able to see which one was answered
// without scrolling up.
type supportDiagnosisDTO struct {
	Email string `json:"email"`
	Text  string `json:"text"`
}

// Diagnose — admin required (see router.go). Answers the support ticket
// "why can't this user log in": whether the account is locked and until
// when, its failed-attempt count, how many sessions it holds, and its
// recent failure history.
//
// Read-only structurally, not by convention. cryden builds this through
// admin.DiagnoseLogin, which is handed narrow interfaces carrying no
// Create, LockAccount, ResetFailedAttempts or Revoke — so this endpoint
// cannot unlock the very account it is reporting on, whatever the caller
// asks for. See CLAUDE.md's hard rule.
//
// An account that does not exist is not an error: it is the answer, and
// the report says so. That distinction is the engine's own, and this
// handler passes it through rather than inventing a 404 the engine did
// not mean.
func (h *SupportHandlers) Diagnose(w http.ResponseWriter, r *http.Request) {
	email := queryString(r, "email")
	if email == "" {
		writeBadRequest(w, "email is required")
		return
	}

	text, err := cryden.DiagnoseLoginIssue(r.Context(), h.Engine, email)
	if err != nil {
		writeErr(w, err)
		return
	}

	writeData(w, http.StatusOK, supportDiagnosisDTO{Email: email, Text: text})
}
