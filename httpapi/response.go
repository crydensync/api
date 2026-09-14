package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/crydensync/cryden/v2/auth"
)

func writeData(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// writeErr resolves err through mapError and writes it. Internal
// errors (unmapped, status 500) are logged server-side with the real
// error — the client only ever sees the deliberately vague message.
func writeErr(w http.ResponseWriter, err error) {
	apiErr := mapError(err)
	if apiErr.Status == http.StatusInternalServerError {
		log.Printf("internal error: %v", err)
	}
	errBody := map[string]any{"code": apiErr.Code, "message": apiErr.Message}
	// A password-policy violation carries every broken rule as stable
	// strings, deliberately so a client can render them together instead
	// of parsing prose. Read off the error rather than threaded through
	// mapError's (status, code, message) triple, which every other error
	// still fits exactly as before.
	var policy *auth.ErrPasswordPolicyViolation
	if errors.As(err, &policy) && len(policy.Violations) > 0 {
		errBody["details"] = policy.Violations
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiErr.Status)
	json.NewEncoder(w).Encode(map[string]any{"error": errBody})
}

// writeBadRequest is for request-parsing failures — these never come
// from the engine, so they don't go through mapError.
func writeBadRequest(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": "bad_request", "message": message},
	})
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
