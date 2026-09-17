package httpapi

import (
	"net/http"

	"github.com/crydensync/api/askai"
)

// WidgetHandlers serves the ask-ai widget to the signed-in end user.
//
// This is the only AI-assisted surface in this repo that is not behind
// RequireAdmin, and the distinction is the point of the feature rather
// than an exception to it. Every other AI tool here answers an operator's
// question about the deployment; this one answers an ordinary user's
// question about their own account, and cryden's widget.Ask is built for
// exactly that caller — it takes the identity to scope to, and its
// package doc requires that identity to come from the host's own
// authentication of the current request.
//
// So the owner is UserIDFromContext, from the verified Bearer token, and
// the request body carries nothing but the question. It has no user id
// field to get wrong: a caller cannot ask about somebody else because
// there is nowhere to say who. Putting this behind RequireAdmin would
// make it unusable (end users are not operators) and would hand a token
// that can already read anyone's record a surface whose entire design
// assumes it reads exactly one person's.
//
// Read-only, in the sense CLAUDE.md means. widget.Ask parses, scopes and
// executes a SELECT through ai.QueryableStore, which has no method that
// can write; the connection it runs on is a role this repo verified
// refuses writes before it stored it. Nothing here can change an account.
type WidgetHandlers struct {
	// Service is this repo's own serving side — see askai. Nil unless a
	// router was built without one (tests); the handler then answers 404
	// rather than panicking on a nil dereference.
	Service *askai.Service
}

// askAIRequest is the body. One field, deliberately: see WidgetHandlers
// on why there is no owner here.
type askAIRequest struct {
	Question string `json:"question"`
}

// askAIResponse is the answer as a widget renders it.
//
// Text is cryden's RenderResult — a plain-text table — because no
// Composer is configured; see askai.Ask. It is a string and not a
// structured table so that adding a Composer later cannot change this
// response's shape: a model-written answer and a rendered one are both
// text, and a client that renders one renders the other.
type askAIResponse struct {
	Answer string `json:"answer"`
	// RowCount is how many rows the scoped query returned, which a
	// widget shows as "3 results" when the table itself is collapsed.
	RowCount int `json:"row_count"`
}

// Ask — auth required, end user. Answers a question about the calling
// user's own account.
func (h *WidgetHandlers) Ask(w http.ResponseWriter, r *http.Request) {
	if h.Service == nil {
		writeErr(w, errAskAIUnavailable)
		return
	}

	var req askAIRequest
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	answer, err := h.Service.Ask(r.Context(), askai.Request{
		OwnerUserID: UserIDFromContext(r),
		Question:    req.Question,
		Origin:      r.Header.Get("Origin"),
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	writeData(w, http.StatusOK, askAIResponse{
		Answer:   answer.Text,
		RowCount: len(answer.Result.Rows),
	})
}
