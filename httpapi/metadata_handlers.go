package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/crydensync/cryden/v2/store"

	"github.com/crydensync/api/usermeta"
)

// MetadataHandlers answers the admin per-user metadata endpoints — the
// table behind JWT claim mapping.
//
// Every route is behind RequireAdmin (router.go). Unlike the two reports
// beside them on the admin surface, these three are not read-only: PUT
// and DELETE are writes, and CLAUDE.md's read-only rule is about the
// AI-assisted tooling, not about the console's own settings. What that
// rule does mean here is that a write is always an explicit operator
// action on a named key — nothing on this surface may take a suggestion
// and apply it by itself.
type MetadataHandlers struct {
	// Users is cryden's own user store, the same instance main.go handed
	// the engine. It is here only to answer "does this user exist", so an
	// unknown or malformed id is a 404 rather than a foreign-key failure
	// out of Postgres surfacing as a 500.
	Users store.UserStore

	// Meta is this repo's own store — see usermeta. It owns the rule
	// about which keys may exist, so nothing here re-checks a key.
	Meta usermeta.Store
}

// metadataDTO is the shape all three endpoints answer with, so a console
// can hold one parser: PUT and DELETE return the same body GET does
// rather than a status message, which means a save is also the refresh.
type metadataDTO struct {
	UserID   string         `json:"user_id"`
	Metadata map[string]any `json:"metadata"`

	// ReservedClaimNames is included so a claim-mapping UI can grey these
	// out rather than let an operator discover the rule by being
	// rejected. It is both halves of the rule — the seven registered JWT
	// names, and this api's own "role" (see usermeta.RoleClaim, which is
	// the one with teeth).
	ReservedClaimNames []string `json:"reserved_claim_names"`
}

// List — admin required. Returns every key set on the user.
func (h *MetadataHandlers) List(w http.ResponseWriter, r *http.Request, userID string) {
	if !h.ready(w, r, userID) {
		return
	}
	h.writeMetadata(w, r, userID)
}

// Put — admin required. Sets one key, creating it or replacing it.
//
// The body is {"value": <any JSON>}. A key is set on its own rather than
// the whole map being replaced, so two operators editing different fields
// of the same user cannot overwrite each other's work — the classic
// read-modify-write a "PUT the whole object" endpoint invites.
//
// The key is validated by the store, not here (see usermeta.ValidateKey):
// the reserved-claim rule is a property of the data, so it holds for
// every writer rather than for the writers that happen to know about it.
func (h *MetadataHandlers) Put(w http.ResponseWriter, r *http.Request, userID, key string) {
	if !h.ready(w, r, userID) {
		return
	}

	// RawMessage rather than any, because "value" absent and "value": null
	// have to be told apart: null is a legitimate value to store, and a
	// missing field is a client bug. Decoding into an `any` collapses
	// both to nil.
	var req struct {
		Value json.RawMessage `json:"value"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeBadRequest(w, "invalid request body")
		return
	}
	if len(req.Value) == 0 {
		writeBadRequest(w, `value is required — send {"value": null} to store an explicit null`)
		return
	}

	var value any
	if err := json.Unmarshal(req.Value, &value); err != nil {
		writeBadRequest(w, "value must be valid JSON")
		return
	}

	if err := h.Meta.Set(r.Context(), userID, key, value); err != nil {
		writeErr(w, err)
		return
	}
	h.writeMetadata(w, r, userID)
}

// Delete — admin required. Removes one key.
//
// A key that is not set answers 404 rather than a bare 200, matching
// DELETE /v1/api-keys/{id} and DELETE /v1/sessions/{id}: a console that
// removed the wrong field should be told, not shown a success it did not
// achieve.
func (h *MetadataHandlers) Delete(w http.ResponseWriter, r *http.Request, userID, key string) {
	if !h.ready(w, r, userID) {
		return
	}
	if err := h.Meta.Delete(r.Context(), userID, key); err != nil {
		writeErr(w, err)
		return
	}
	h.writeMetadata(w, r, userID)
}

// ready answers the two things all three handlers need first: are the
// stores wired, and is this a user at all. It reports whether the caller
// should carry on.
func (h *MetadataHandlers) ready(w http.ResponseWriter, r *http.Request, userID string) bool {
	if h.Users == nil || h.Meta == nil {
		writeErr(w, errAdminStoresUnavailable)
		return false
	}

	// A path segment that cannot be a user id is answered 404, the same
	// as one that simply is not a user. Two reasons: "no such user" is
	// the honest description of both, and a malformed id handed straight
	// to Postgres is a driver error — "invalid input syntax for type
	// uuid" — which mapError would turn into a 500 and an operator would
	// read as a bug in the API rather than as a stale bookmark.
	if !looksLikeUUID(userID) {
		writeErr(w, store.ErrNotFound)
		return false
	}

	if _, err := h.Users.GetByID(r.Context(), userID); err != nil {
		writeErr(w, err)
		return false
	}
	return true
}

// writeMetadata re-reads and returns the user's whole set. Reading it
// back rather than echoing what was just written is deliberate: it is the
// one thing that proves the value that landed is the value stored, and it
// costs one query on an endpoint an operator calls by hand.
func (h *MetadataHandlers) writeMetadata(w http.ResponseWriter, r *http.Request, userID string) {
	metadata, err := h.Meta.AllFor(r.Context(), userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, metadataDTO{
		UserID:             userID,
		Metadata:           metadata,
		ReservedClaimNames: usermeta.ReservedKeys(),
	})
}

// looksLikeUUID reports whether s has the canonical UUID shape —
// 8-4-4-4-12 hexadecimal digits. It checks the shape rather than parsing
// the value, because the only question being asked is whether the string
// can safely reach a UUID column; whether it names a row is the query's
// business, not this function's.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
