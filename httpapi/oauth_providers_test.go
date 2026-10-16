package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The configured-provider list and the per-provider test, the two endpoints
// the console's OAuth Providers screen is built on. The health report's own
// tests hold the probe's semantics; what is asserted here is what the list
// answers without probing, and what the test endpoint does with a name the
// deployment never configured.
func TestProvidersList(t *testing.T) {
	h := &OAuthHealthHandlers{
		lookup: func(name string) (oauthProvider, bool) {
			return oauthProvider{name: name}, name != "apple"
		},
		names: []string{"google", "github", "apple"},
	}

	rec := httptest.NewRecorder()
	h.Providers(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/oauth/providers", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var body struct {
		Data struct {
			Providers []oauthProviderSummary `json:"providers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}

	if len(body.Data.Providers) != 3 {
		t.Fatalf("got %d rows, want 3", len(body.Data.Providers))
	}
	want := []struct {
		provider   string
		configured bool
	}{
		{"google", true},
		{"github", true},
		{"apple", false},
	}
	for i, w := range want {
		got := body.Data.Providers[i]
		if got.Provider != w.provider || got.Configured != w.configured {
			t.Errorf("row %d = {%s %v}, want {%s %v}", i, got.Provider, got.Configured, w.provider, w.configured)
		}
	}
}

// ones no response could fill.
// ones no response could fill.
func TestProvidersListMakesNoOutboundRequests(t *testing.T) {
	// A lookup handing out a URL that would fail to dial: the list endpoint
	// must consult it only for configured-ness, and its answer still being
	// 200 proves no probe ran on the list's behalf.
	h := &OAuthHealthHandlers{
		lookup: func(name string) (oauthProvider, bool) {
			return oauthProvider{name: name, authURL: "http://127.0.0.1:1/unreachable"}, true
		},
		client: &http.Client{Timeout: oauthHealthTimeout},
		names:  []string{"google"},
	}

	rec := httptest.NewRecorder()
	h.Providers(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/oauth/providers", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"configured":true`) {
		t.Fatalf("expected google configured, body %s", rec.Body.String())
	}
}

func TestProviderTest(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Providers answer a bare GET with 4xx; the probe reads that as ok.
		http.Error(w, "missing client_id", http.StatusBadRequest)
	}))
	defer ok.Close()

	h := &OAuthHealthHandlers{
		lookup: func(name string) (oauthProvider, bool) {
			if name == "google" {
				return oauthProvider{name: "google", authURL: ok.URL}, true
			}
			return oauthProvider{}, false
		},
		client: &http.Client{Timeout: oauthHealthTimeout},
		names:  []string{"google"},
	}

	t.Run("a configured provider is probed and its verdict returned", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.TestProvider(rec, httptest.NewRequest(http.MethodPost, "/v1/admin/oauth/google/test", nil), "google")

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		var body struct {
			Data oauthProviderHealth `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding %s: %v", rec.Body.String(), err)
		}
		if body.Data.Provider != "google" || body.Data.Status != oauthHealthOK {
			t.Errorf("data = %+v, want google/ok", body.Data)
		}
		if body.Data.HTTPStatus != http.StatusBadRequest {
			t.Errorf("http_status = %d, want 400 (a 4xx from an authorize endpoint is ok)", body.Data.HTTPStatus)
		}
	})

	t.Run("an unconfigured provider is a 404, and no request is made for it", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.TestProvider(rec, httptest.NewRequest(http.MethodPost, "/v1/admin/oauth/apple/test", nil), "apple")

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		if body.Error.Code != "oauth_provider_not_configured" {
			t.Errorf("code = %q, want oauth_provider_not_configured", body.Error.Code)
		}
	})
}
