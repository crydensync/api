package httpapi

import (
	"errors"
	"net/http"

	"github.com/crydensync/cryden/v2/auth"
)

// secondFactorDTO is the shape returned when a correct password (or a
// magic-link token) is not on its own enough to finish a login. It is a
// 200, not an error: nothing failed, the caller just has one more step
// to complete. `pending_token` proves only "this caller already
// supplied a correct first factor" — it is not an access or refresh
// token and does nothing on any other endpoint.
type secondFactorDTO struct {
	SecondFactorRequired bool     `json:"second_factor_required"`
	PendingToken         string   `json:"pending_token"`
	Methods              []string `json:"methods"`
}

// writeTokensOrPause is the single place the paused-login case is
// resolved. Every login-shaped endpoint (password, OAuth callback,
// magic link) can pause for a second factor — cryden reports that with
// *auth.ErrSecondFactorRequired rather than by returning tokens — so
// handling it once here keeps those handlers from each inventing their
// own response shape. Returns true if it wrote a response.
func writeTokensOrPause(w http.ResponseWriter, err error) bool {
	var secondFactor *auth.ErrSecondFactorRequired
	if errors.As(err, &secondFactor) {
		methods := secondFactor.Methods
		if methods == nil {
			// Never emit `null` for a list — an empty array is what a
			// client can iterate without a nil check.
			methods = []string{}
		}
		writeData(w, http.StatusOK, secondFactorDTO{
			SecondFactorRequired: true,
			PendingToken:         secondFactor.PendingToken,
			Methods:              methods,
		})
		return true
	}
	return false
}
