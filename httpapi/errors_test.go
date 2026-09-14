package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"
)

// TestMapErrorSecondFactor covers the errors a client can actually act
// on programmatically — the codes here are the contract, so they are
// pinned rather than left to whatever the switch happens to say.
func TestMapErrorSecondFactor(t *testing.T) {
	cases := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{auth.ErrTOTPNotEnabled, http.StatusBadRequest, "totp_not_enabled"},
		{auth.ErrTOTPAlreadyEnabled, http.StatusConflict, "totp_already_enabled"},
		{auth.ErrInvalidTOTPCode, http.StatusUnauthorized, "invalid_totp_code"},
		{auth.ErrInvalidPendingLogin, http.StatusUnauthorized, "invalid_pending_login"},
		{auth.ErrNoPasskeysEnrolled, http.StatusBadRequest, "no_passkeys_enrolled"},
		{auth.ErrInvalidWebAuthnResponse, http.StatusUnauthorized, "invalid_passkey_response"},
		{auth.ErrInvalidCeremonyToken, http.StatusBadRequest, "invalid_ceremony_token"},
		{cryden.ErrTOTPNotConfigured, http.StatusNotFound, "totp_not_configured"},
		{cryden.ErrWebAuthnNotConfigured, http.StatusNotFound, "passkeys_not_configured"},
		{cryden.ErrMagicLinkNotConfigured, http.StatusNotFound, "magic_link_not_configured"},
		{cryden.ErrRecoveryCodesNotConfigured, http.StatusNotFound, "recovery_codes_not_configured"},
	}

	for _, tc := range cases {
		t.Run(tc.wantCode, func(t *testing.T) {
			got := mapError(tc.err)
			if got.Status != tc.wantStatus || got.Code != tc.wantCode {
				t.Fatalf("mapError(%v) = %d/%s, want %d/%s", tc.err, got.Status, got.Code, tc.wantStatus, tc.wantCode)
			}
		})
	}
}

// TestMapErrorWrappedStillMapped is the property that makes the single
// mapping site worth having: an error that travelled through a wrap
// still resolves to the same stable code.
func TestMapErrorWrappedStillMapped(t *testing.T) {
	wrapped := fmt.Errorf("complete login: %w", auth.ErrInvalidTOTPCode)
	if got := mapError(wrapped); got.Code != "invalid_totp_code" {
		t.Fatalf("wrapped error mapped to %q, want invalid_totp_code", got.Code)
	}
}

// TestPauseForSecondFactor pins the paused-login response shape: a 200
// (nothing failed) carrying the pending token and the enrolled methods,
// never a null array.
func TestPauseForSecondFactor(t *testing.T) {
	rec := httptest.NewRecorder()
	handled := writeTokensOrPause(rec, &auth.ErrSecondFactorRequired{PendingToken: "pending-123"})
	if !handled {
		t.Fatal("expected the second-factor error to be handled")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body struct {
		Data secondFactorDTO `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if !body.Data.SecondFactorRequired || body.Data.PendingToken != "pending-123" {
		t.Fatalf("unexpected pause body: %+v", body.Data)
	}
	if body.Data.Methods == nil {
		t.Fatal("methods must be an empty array, never null")
	}
}

// TestPauseForSecondFactorIgnoresOtherErrors makes sure an ordinary
// failure is left for writeErr rather than being swallowed as a pause.
func TestPauseForSecondFactorIgnoresOtherErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	if writeTokensOrPause(rec, errors.New("boom")) {
		t.Fatal("a non-second-factor error must not be handled as a pause")
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected no response body written, got %q", rec.Body.String())
	}
}
