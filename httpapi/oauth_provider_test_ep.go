package httpapi

import (
	"net/http"
)

// TestProvider answers POST /v1/admin/oauth/{provider}/test: one
// reachability probe of one provider's authorize endpoint, on demand.
//
// The login flow never calls this; it exists because the console's OAuth
// Providers screen has a "Test" affordance per configured provider and the
// health report probes all of them at once. Testing one costs one outbound
// request rather than six, and it is the same probe the health report runs
// (h.probe), so the two endpoints cannot disagree about what "reachable"
// means: same client, same timeout, same 4xx-is-ok reading, same four-state
// vocabulary.
//
// An unconfigured provider is a 404 rather than an unreachable verdict:
// "this deployment never configured Google" and "Google is down" are
// different sentences, and only the operator's screen knows which question
// it asked. The probe is deliberately not run for an unconfigured provider
// — that is the one case where a request would leave the process on behalf
// of a provider the deployment never opted into.
func (h *OAuthHealthHandlers) TestProvider(w http.ResponseWriter, r *http.Request, providerName string) {
	p, configured := h.lookup(providerName)
	if !configured {
		writeErr(w, errOAuthProviderNotConfigured)
		return
	}

	status := h.probe(r.Context(), p.name, p.authURL)
	writeData(w, http.StatusOK, status)
}
