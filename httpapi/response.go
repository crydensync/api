package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiErr.Status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": apiErr.Code, "message": apiErr.Message},
	})
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
