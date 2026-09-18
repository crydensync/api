package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crydensync/api/config"
)

// specSourcePath is the hand-written spec, relative to this package's
// directory — which is where `go test` runs. The copy under docs_assets/ is
// what actually ships.
const specSourcePath = "../openapi/spec.yaml"

// TestOpenAPIAssetMatchesSource is the guard on the one way this arrangement
// can go wrong quietly.
//
// The embed directive cannot reach outside its own package directory, so the
// spec is copied into docs_assets/ by `go generate` and the copy is what the
// binary serves. An edit to openapi/spec.yaml that nobody re-copies leaves
// the deployed docs describing an older API, and nothing else in the build
// would notice: the copy is valid YAML, it compiles, and every other test
// passes.
//
// So this compares bytes rather than parsing either document. A parsed
// comparison would pass on a copy missing a description, a summary or an
// example — exactly the parts of a spec a reader is there for.
func TestOpenAPIAssetMatchesSource(t *testing.T) {
	source, err := os.ReadFile(specSourcePath)
	if err != nil {
		t.Fatalf("reading %s: %v", specSourcePath, err)
	}

	embedded, err := docsAssets.ReadFile(docsAssetDir + "/openapi.yaml")
	if err != nil {
		t.Fatalf("reading the embedded spec: %v", err)
	}

	if bytes.Equal(source, embedded) {
		return
	}

	// Failing with only "bytes differ" would leave the next person to
	// re-derive what to do about it, so the message says so.
	t.Errorf("docs_assets/openapi.yaml is not identical to %s "+
		"(%d bytes vs %d) — run `go generate ./httpapi/` to refresh the copy",
		specSourcePath, len(embedded), len(source))
}

// TestDocsPageIsServed covers the entry point a person actually opens: no
// Authorization header in the request, and a page that references the
// vendored assets rather than a CDN.
//
// The CDN assertion is the point of the test rather than a decoration. The
// failure it guards against — someone "fixing" the docs by pointing the
// script tags back at unpkg.com — produces a page that works perfectly on a
// developer's laptop and fails on any deployment without egress.
func TestDocsPageIsServed(t *testing.T) {
	rec := get(t, NewRouter(Deps{}), "/v1/docs")

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/docs = %d, want 200 — body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	body := rec.Body.String()
	for _, want := range []string{
		`src="/v1/docs/swagger-ui-bundle.js"`,
		`href="/v1/docs/swagger-ui.css"`,
		`url: "/v1/docs/openapi.yaml"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not reference %s", want)
		}
	}

	for _, cdn := range []string{"http://", "https://", "//unpkg", "cdn."} {
		if strings.Contains(body, cdn) {
			t.Errorf("the page contains %q; the assets are embedded and must be served from this host", cdn)
		}
	}
}

// TestDocsSpecIsServed pins the content type the contract names. A client
// that trusts the header would hand this body to the wrong parser if it came
// back as text/plain, and Go's own extension table is not the same on every
// machine.
func TestDocsSpecIsServed(t *testing.T) {
	rec := get(t, NewRouter(Deps{}), "/v1/docs/openapi.yaml")

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/docs/openapi.yaml = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/yaml" {
		t.Errorf("Content-Type = %q, want application/yaml", ct)
	}

	source, err := os.ReadFile(specSourcePath)
	if err != nil {
		t.Fatalf("reading %s: %v", specSourcePath, err)
	}
	if !bytes.Equal(rec.Body.Bytes(), source) {
		t.Error("the served spec differs from openapi/spec.yaml; the endpoint must serve the copy byte for byte")
	}
}

// TestDocsAssetsAreServed walks every vendored file through the route that
// serves it. The list is the assertion: it is what makes a missing or
// misnamed asset a test failure rather than a 404 in a browser console that
// nobody is watching in CI.
//
// The content types are checked here rather than in the helper because a
// stylesheet served as application/octet-stream is the specific way this
// breaks — the page loads, and has no styling.
func TestDocsAssetsAreServed(t *testing.T) {
	router := NewRouter(Deps{})

	for _, tc := range []struct{ name, wantType string }{
		{"swagger-ui.css", "text/css; charset=utf-8"},
		{"swagger-ui-bundle.js", "text/javascript; charset=utf-8"},
		{"swagger-ui-standalone-preset.js", "text/javascript; charset=utf-8"},
		{"favicon-16x16.png", "image/png"},
		{"favicon-32x32.png", "image/png"},
		{"LICENSE", "text/plain; charset=utf-8"},
		{"NOTICE", "text/plain; charset=utf-8"},
		{"swagger-ui-bundle.js.LICENSE.txt", "text/plain; charset=utf-8"},
		{"swagger-ui-standalone-preset.js.LICENSE.txt", "text/plain; charset=utf-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := get(t, router, "/v1/docs/"+tc.name)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET /v1/docs/%s = %d, want 200", tc.name, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != tc.wantType {
				t.Errorf("Content-Type = %q, want %q", ct, tc.wantType)
			}
			if rec.Body.Len() == 0 {
				t.Error("the asset served an empty body")
			}

			// The embedded bytes are the ones that must come back. A
			// handler that found the right file but truncated or
			// transformed it would still pass the checks above.
			want, err := docsAssets.ReadFile(docsAssetDir + "/" + tc.name)
			if err != nil {
				t.Fatalf("reading the embedded %s: %v", tc.name, err)
			}
			if !bytes.Equal(rec.Body.Bytes(), want) {
				t.Errorf("the served %s differs from the embedded copy", tc.name)
			}
		})
	}
}

// TestDocsServeIdenticallyOnBothBackends is the "no backend detection"
// requirement stated as a test. The admin console is the surface that
// differs by backend (501 on SQLite, see TestTier6AdminSurfaceIs501OnSQLite);
// the docs are static bytes and have no reason to, so the two responses are
// compared against each other rather than each against a literal — a change
// that made one backend special would have to change both to pass.
func TestDocsServeIdenticallyOnBothBackends(t *testing.T) {
	postgres := NewRouter(Deps{Config: config.Config{DatabaseURL: "postgres://localhost/cryden"}})
	sqlite := NewRouter(Deps{Config: config.Config{SQLitePath: "/var/lib/cryden/api.db"}})

	for _, path := range []string{"/v1/docs", "/v1/docs/openapi.yaml", "/v1/docs/swagger-ui.css"} {
		t.Run(path, func(t *testing.T) {
			onPostgres := get(t, postgres, path)
			onSQLite := get(t, sqlite, path)

			if onPostgres.Code != http.StatusOK || onSQLite.Code != http.StatusOK {
				t.Fatalf("GET %s = %d on postgres, %d on sqlite; want 200 from both",
					path, onPostgres.Code, onSQLite.Code)
			}
			if onPostgres.Header().Get("Content-Type") != onSQLite.Header().Get("Content-Type") {
				t.Errorf("Content-Type differs by backend: %q vs %q",
					onPostgres.Header().Get("Content-Type"), onSQLite.Header().Get("Content-Type"))
			}
			if !bytes.Equal(onPostgres.Body.Bytes(), onSQLite.Body.Bytes()) {
				t.Errorf("the body of %s differs by backend", path)
			}
		})
	}
}

// TestDocsUnknownAssetIsNotFound covers the two ways an asset name can miss:
// a file that is not vendored, and a path that tries to climb out of the
// directory.
//
// Every case has to answer the API's own 404 envelope rather than a plain
// text one, because a caller reaching these routes is speaking to this API
// and one response contract is the whole reason the envelope exists.
func TestDocsUnknownAssetIsNotFound(t *testing.T) {
	router := NewRouter(Deps{})

	for _, name := range []string{"nope.js", "%2e%2e", "%2e%2e%2fopenapi.yaml"} {
		t.Run(name, func(t *testing.T) {
			rec := get(t, router, "/v1/docs/"+name)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET /v1/docs/%s = %d, want 404 — body: %s", name, rec.Code, rec.Body.String())
			}
			if code := decodeError(t, rec).Code; code != "not_found" {
				t.Errorf("code = %q, want not_found", code)
			}
		})
	}
}

// TestDocsAssetGuardRefusesTraversalCandidates tests the handler's own check
// rather than the route table's.
//
// The router never hands "." or ".." to the handler — ServeMux canonicalizes
// the path first and answers 301 — so a router-level test would pass whether
// or not the guard existed, and would keep passing if someone widened the
// pattern to {asset...}. Calling the handler with the path value set
// directly is what actually exercises the two lines that carry the weight
// once that pattern changes. See Asset's doc comment.
func TestDocsAssetGuardRefusesTraversalCandidates(t *testing.T) {
	docs := NewDocsHandler()

	for _, name := range []string{"", ".", "..", "../openapi.yaml", "a/b", `a\b`} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/docs/x", nil)
			r.SetPathValue("asset", name)

			rec := httptest.NewRecorder()
			docs.Asset(rec, r)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("Asset(%q) = %d, want 404 — body: %s", name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestServeMuxCanonicalizesTraversalPaths pins what actually happens to the
// dot-segment spellings at the router, so the behaviour is recorded rather
// than assumed.
//
// Go's ServeMux cleans the path before matching, so /v1/docs/.. and
// /v1/docs/. redirect rather than reaching the handler. That is a fine
// answer — the redirect targets are /v1 and /v1/docs, both of which this API
// serves — but "a redirect happened" and "the guard refused it" are
// different claims, and only the second is this package's code. The
// assertion is therefore that neither spelling can return a file.
func TestServeMuxCanonicalizesTraversalPaths(t *testing.T) {
	router := NewRouter(Deps{})

	for _, path := range []string{"/v1/docs/..", "/v1/docs/."} {
		t.Run(path, func(t *testing.T) {
			rec := get(t, router, path)

			if rec.Code == http.StatusOK {
				t.Fatalf("GET %s = 200; a dot segment must never resolve to a served file", path)
			}
			if rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 301 (canonicalized) or 404", path, rec.Code)
			}
		})
	}
}

// TestDocsSourceExists keeps the byte-comparison test honest. If
// openapi/spec.yaml were ever moved without updating specSourcePath, every
// comparison above would fail with a read error — but only after someone
// worked out that the path was the problem. This says so directly, and it
// also pins that the source is where the copy is generated from.
func TestDocsSourceExists(t *testing.T) {
	info, err := os.Stat(filepath.Clean(specSourcePath))
	if err != nil {
		t.Fatalf("openapi/spec.yaml is not at %s, which is what the go:generate "+
			"directive in docs.go copies from: %v", specSourcePath, err)
	}
	if info.Size() == 0 {
		t.Fatal("openapi/spec.yaml is empty")
	}
}

// get issues an unauthenticated GET through the router and returns the
// recorder. No Authorization header is set anywhere in this file, so every
// passing call is also proof that the route needs no credentials.
func get(t *testing.T, router http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}
