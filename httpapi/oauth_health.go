package httpapi

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// oauthHealthTimeout bounds a single provider probe, and is short on
// purpose: an operator asking for provider health would rather see
// "unreachable" in a few seconds than wait on a hung endpoint, and
// nothing here sits on the path of a real login.
const oauthHealthTimeout = 5 * time.Second

// oauthHealthStatus is the per-provider verdict. Deliberately four states
// rather than a bool: "not configured" and "configured but unreachable"
// are the same nothing-to-a-login but very different things to an
// operator, and a 5xx from an endpoint that is otherwise up is worth
// telling apart from a connect timeout.
type oauthHealthStatus string

const (
	// oauthHealthOK means the authorize endpoint answered. A 4xx counts:
	// see Health for why.
	oauthHealthOK oauthHealthStatus = "ok"
	// oauthHealthDegraded means the endpoint answered 5xx — reachable, but
	// saying it cannot serve anyone right now.
	oauthHealthDegraded oauthHealthStatus = "degraded"
	// oauthHealthUnreachable means no HTTP response at all: DNS, TLS,
	// connect or timeout.
	oauthHealthUnreachable oauthHealthStatus = "unreachable"
	// oauthHealthNotConfigured means this deployment has no client ID and
	// secret for the provider, so it cannot log anyone in. No request is
	// made in that case.
	oauthHealthNotConfigured oauthHealthStatus = "not_configured"
)

// oauthProviderHealth is one row of the report, and the whole of this
// repo's own vocabulary for provider health — cryden has no such concept.
type oauthProviderHealth struct {
	Provider   string            `json:"provider"`
	Configured bool              `json:"configured"`
	Status     oauthHealthStatus `json:"status"`
	// HTTPStatus and LatencyMS are omitted when no response was received,
	// which is exactly when they would be meaningless rather than zero.
	HTTPStatus int    `json:"http_status,omitempty"`
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	Error      string `json:"error,omitempty"`
}

// OAuthHealthHandlers answers GET /v1/admin/oauth/health.
type OAuthHealthHandlers struct {
	// lookup is OAuthHandlers.provider in production — the same switch the
	// login and linking flows resolve providers through, so a provider
	// this endpoint reports on cannot disagree with the provider those
	// flows would actually use. Field, not method, so tests can point it
	// at a local server.
	lookup func(string) (oauthProvider, bool)
	client *http.Client
	names  []string
}

func NewOAuthHealthHandlers(oauth *OAuthHandlers) *OAuthHealthHandlers {
	return &OAuthHealthHandlers{
		lookup: oauth.provider,
		client: &http.Client{Timeout: oauthHealthTimeout},
		names:  oauthProviderNames,
	}
}

// Health — admin required (see router.go). For every provider this repo
// knows about: whether it is configured, and whether its authorize
// endpoint answers. Probes run concurrently, each with its own timeout, so
// six providers cost one timeout rather than six.
//
// This is a reachability check, not an OAuth flow: no client ID, no state,
// no redirect, nothing that could mint a session. Providers answer a bare
// GET with a 4xx (their "missing client_id" complaint), which still proves
// the endpoint is up and serving — hence 4xx is ok and only 5xx is
// degraded. A configured Apple is probed like any other provider; the only
// difference is that its client secret is signed rather than stored, which
// this endpoint never touches.
//
// An unconfigured provider is reported without any request being made: it
// cannot log anyone in, which is the answer an operator needs, and not
// probing it keeps this endpoint from reaching out to providers the
// deployment never opted into.
func (h *OAuthHealthHandlers) Health(w http.ResponseWriter, r *http.Request) {
	results := make([]oauthProviderHealth, len(h.names))
	var wg sync.WaitGroup
	for i, name := range h.names {
		p, configured := h.lookup(name)
		if !configured {
			results[i] = oauthProviderHealth{Provider: name, Status: oauthHealthNotConfigured}
			continue
		}
		// Each goroutine writes its own index, so the slice needs no lock.
		wg.Add(1)
		go func(i int, name, authURL string) {
			defer wg.Done()
			results[i] = h.probe(r.Context(), name, authURL)
		}(i, name, p.authURL)
	}
	wg.Wait()

	writeData(w, http.StatusOK, map[string]any{"providers": results})
}

func (h *OAuthHealthHandlers) probe(ctx context.Context, name, authURL string) oauthProviderHealth {
	ctx, cancel := context.WithTimeout(ctx, oauthHealthTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return oauthProviderHealth{Provider: name, Configured: true, Status: oauthHealthUnreachable, Error: err.Error()}
	}
	req.Header.Set("User-Agent", "crydensync-api-oauth-health")

	start := time.Now()
	resp, err := h.client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		// Truncated so a transport stack (or a redirect chain) cannot make
		// one row of an admin JSON response arbitrarily long.
		return oauthProviderHealth{Provider: name, Configured: true, Status: oauthHealthUnreachable, LatencyMS: latency, Error: truncate(err.Error(), 200)}
	}
	defer resp.Body.Close()
	// Drain a bounded amount so this cannot be turned into a way to make
	// the API buffer something large, and so the connection is reusable.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	status := oauthHealthOK
	if resp.StatusCode >= 500 {
		status = oauthHealthDegraded
	}
	return oauthProviderHealth{Provider: name, Configured: true, Status: status, HTTPStatus: resp.StatusCode, LatencyMS: latency}
}

// truncate cuts s to max runes, never mid-rune, and marks that it did.
func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}
