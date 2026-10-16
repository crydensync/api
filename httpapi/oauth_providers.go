package httpapi

import (
	"net/http"
)

// oauthProviderSummary is one row of the configured-provider list: the
// provider's name and whether this deployment holds credentials for it.
// The endpoint answers from configuration alone, so there is nothing
// further to report until a probe is asked for.
type oauthProviderSummary struct {
	Provider   string `json:"provider"`
	Configured bool   `json:"configured"`
}

// Providers answers the console's OAuth Providers screen: which providers
// this repo can speak to, and whether each is configured on this
// deployment. GET /v1/admin/oauth/providers.
//
// The distinction from /v1/admin/oauth/health matters. Health is about
// reachability and costs one outbound probe per configured provider every
// time it is called. This list answers from configuration alone — no
// request leaves the process — so the console renders the screen the moment
// it opens and calls the test endpoint when the operator wants to know
// whether a provider is up today.
//
// The screen this serves is read-only by design: this repo has no endpoint
// to create or edit provider credentials (they arrive by environment, which
// is where a deployment keeps them), so a console that offered to edit them
// would be offering to edit nothing.
func (h *OAuthHealthHandlers) Providers(w http.ResponseWriter, r *http.Request) {
	providers := make([]oauthProviderSummary, len(h.names))
	for i, name := range h.names {
		_, configured := h.lookup(name)
		providers[i] = oauthProviderSummary{Provider: name, Configured: configured}
	}

	writeData(w, http.StatusOK, map[string]any{"providers": providers})
}
