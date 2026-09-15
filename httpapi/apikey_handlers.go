package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2"
)

type APIKeyHandlers struct {
	Engine *cryden.Engine
}

// apiKeyNotice is echoed in the creation response because the raw key
// below exists in exactly one place — that response. cryden stores only
// its hash (token.HashToken) and can never reproduce it, so a caller that
// loses it has to mint a new one.
const apiKeyNotice = "this key is shown only once and cannot be retrieved later — store it somewhere safe now"

// apiKeyMaxExpiryDays bounds the lifetime a caller may request. Not a
// security limit but a parsing one: expires_in_days is multiplied by
// 24h, and an unbounded int from a request body could overflow that
// multiplication into a NEGATIVE duration, which cryden would then
// reject as an invalid TTL — a confusing 400 for what looks like a valid
// request. Ten years is past any rotation policy and far from the
// overflow point.
const apiKeyMaxExpiryDays = 3650

// apiKeyMaxNameLength bounds the label. It is presentational and cryden
// does not require it to be unique or non-empty, so the only reason to
// cap it is the column it lands in and the list it is rendered in.
const apiKeyMaxNameLength = 100

// apiKeyDTO is the public shape of one key. KeyHash has no field here at
// all — cryden's cryden.APIKey never carries it (see publicAPIKey), and
// this type is the second layer of the same guarantee rather than a
// duplicate of it: a field that does not exist cannot be marshalled by
// accident later.
type apiKeyDTO struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Prefix string `json:"prefix"`

	// Scopes is always an array, never null, so a client can iterate it
	// without a nil check.
	Scopes []string `json:"scopes"`

	// ExpiresAt is null for a key that never expires, which is the default.
	ExpiresAt *string `json:"expires_at"`

	// Expired is the server's own answer to "is this still usable".
	// Deliberately sent rather than left to the client to compute from
	// ExpiresAt: it is the same comparison cryden makes when it
	// authenticates the key, so the two can never disagree.
	Expired bool `json:"expired"`

	CreatedAt string `json:"created_at"`

	// LastUsedAt is null until the key is first used. It is written at
	// most once every five minutes (see cryden's apiKeyLastUsedGranularity),
	// so it answers "is anything still using this?" and not "when exactly
	// was the last request".
	LastUsedAt *string `json:"last_used_at"`
}

func toAPIKeyDTO(k cryden.APIKey) apiKeyDTO {
	scopes := k.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return apiKeyDTO{
		ID:         k.ID,
		Name:       k.Name,
		Prefix:     k.Prefix,
		Scopes:     scopes,
		ExpiresAt:  formatTimePtr(k.ExpiresAt),
		Expired:    k.Expired(),
		CreatedAt:  formatTime(k.CreatedAt),
		LastUsedAt: formatTimePtr(k.LastUsedAt),
	}
}

// Create — auth required. Mints a machine-to-machine credential for the
// calling user and returns the raw key exactly once, alongside the stored
// record and a notice saying so. Same one-time-display contract as
// POST /v1/recovery-codes/generate, and the notice is the same device: a
// client that renders the key without it is the failure mode being
// guarded against.
//
// expires_in_days of 0 or absent means the key never expires. That is
// cryden's own default and the honest one for a credential living in a
// deploy pipeline's environment — revocation, not expiry, is what
// actually stops a key.
func (h *APIKeyHandlers) Create(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r)

	var req struct {
		Name          string   `json:"name"`
		Scopes        []string `json:"scopes"`
		ExpiresInDays int      `json:"expires_in_days"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}

	name := strings.TrimSpace(req.Name)
	if len(name) > apiKeyMaxNameLength {
		writeBadRequest(w, "name must be 100 characters or fewer")
		return
	}
	if req.ExpiresInDays < 0 || req.ExpiresInDays > apiKeyMaxExpiryDays {
		writeBadRequest(w, "expires_in_days must be between 0 (never expires) and 3650")
		return
	}

	var ttl time.Duration
	if req.ExpiresInDays > 0 {
		ttl = time.Duration(req.ExpiresInDays) * 24 * time.Hour
	}

	rawKey, key, err := cryden.GenerateAPIKey(r.Context(), h.Engine, userID, name, req.Scopes, ttl)
	if err != nil {
		writeErr(w, err)
		return
	}

	writeData(w, http.StatusCreated, map[string]any{
		"key":     rawKey,
		"notice":  apiKeyNotice,
		"api_key": toAPIKeyDTO(key),
	})
}

// List — auth required. Returns the calling user's live keys, newest
// first. Revoked keys are absent; expired-but-unrevoked ones are present
// and marked, because "your CI key expired on Tuesday" is exactly what
// someone needs to see to understand why a pipeline broke, whereas a
// revoked key has already been dealt with.
func (h *APIKeyHandlers) List(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r)
	keys, err := cryden.ListAPIKeys(r.Context(), h.Engine, userID)
	if err != nil {
		writeErr(w, err)
		return
	}

	out := make([]apiKeyDTO, 0, len(keys))
	for _, k := range keys {
		out = append(out, toAPIKeyDTO(k))
	}
	writeData(w, http.StatusOK, out)
}

// Revoke — auth required. keyID comes from the URL path, wired in
// router.go. Ownership is enforced inside the store statement cryden
// calls (auth.RevokeAPIKey → APIKeyStore.Revoke(ctx, userID, keyID)), so
// a key belonging to another account, a key that does not exist, and an
// already-revoked key all answer the same 404 api_key_not_found — a
// caller can never learn whether somebody else's key exists.
//
// Irreversible on purpose: the reason a key gets revoked is that somebody
// else may have it, so mint a new one rather than offering an un-revoke.
func (h *APIKeyHandlers) Revoke(w http.ResponseWriter, r *http.Request, keyID string) {
	userID := UserIDFromContext(r)
	if err := cryden.RevokeAPIKey(r.Context(), h.Engine, userID, keyID); err != nil {
		writeErr(w, err)
		return
	}
	// Same 200-and-a-status-body shape DELETE /v1/sessions/{id} returns,
	// rather than a 204 — this repo's DELETEs answer consistently.
	writeData(w, http.StatusOK, map[string]string{"status": "api key revoked"})
}
