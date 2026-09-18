package httpapi

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/crydensync/cryden/v2/store"
)

// docsAssetDir is the directory embedded below, and the prefix every lookup
// in this file is built from.
const docsAssetDir = "docs_assets"

//go:generate cp ../openapi/spec.yaml docs_assets/openapi.yaml

// docsAssets is the whole vendored docs directory — the spec copy, the
// Swagger UI bundle, and the licenses that have to travel with it.
//
// Embedding the directory rather than listing files is deliberate: a file
// added to docs_assets/ is served without touching this file, and a file
// removed from it is a compile error rather than a 404 at runtime.
//
//go:embed docs_assets
var docsAssets embed.FS

// DocsHandler serves the API's own reference documentation from the binary
// itself. Construct it with NewDocsHandler; the zero value has no assets and
// is not usable.
//
// # Why the assets are vendored
//
// Swagger UI's JS and CSS are checked into httpapi/docs_assets/ and embedded
// rather than loaded from a CDN. A self-hosted auth API that fetched its own
// docs UI from unpkg.com at runtime would reintroduce exactly the outbound
// dependency this repo avoids everywhere else — the page would fail to render
// behind an egress firewall, on an air-gapped host, or on the day a third
// party changes a URL. Vendoring costs about 2 MB of binary and removes the
// class of problem entirely.
//
// Vendored from swagger-ui-dist@5.33.0 (Apache-2.0, SmartBear Software Inc.):
//
//	swagger-ui.css, swagger-ui-bundle.js, swagger-ui-standalone-preset.js,
//	favicon-16x16.png, favicon-32x32.png, LICENSE, NOTICE, and the two
//	.LICENSE.txt files carrying the bundles' third-party attributions.
//
// To move to a newer Swagger UI, re-download those files from
// https://unpkg.com/swagger-ui-dist@<version>/ and replace them wholesale —
// do not hand-edit a minified bundle. Nothing in this file parses them.
//
// # The spec is copied, not read from the repo root
//
// The embed directive cannot reach outside its own package directory, so the
// spec is copied from openapi/spec.yaml into docs_assets/openapi.yaml by the
// generate directive above. The copy is committed, because the Docker build
// and the release builds run `go build` and never `go generate`.
//
// That arrangement has one failure mode worth naming: someone edits the spec
// and forgets to re-run `go generate`, and the binary serves stale docs. A
// test (TestOpenAPIAssetMatchesSource) compares the two files byte for byte,
// so that mistake fails CI instead of silently shipping.
//
// # Why these routes need no backend check
//
// The docs are static bytes compiled into the binary. Nothing here reads a
// store, a config value or a database handle, so the endpoints answer
// identically on Postgres and SQLite — the 501 that covers the admin console
// (see AdminOnly) has no reason to apply and deliberately does not. They are
// also unauthenticated: a reference document is the thing a caller reads
// before they have a token, and it describes nothing openapi/spec.yaml does
// not already describe.
type DocsHandler struct {
	// assets is an fs.FS rooted above docsAssetDir, so it is either the
	// embedded directory or a test's substitute.
	assets fs.FS
}

// NewDocsHandler returns the handler over the embedded assets.
func NewDocsHandler() *DocsHandler {
	return &DocsHandler{assets: docsAssets}
}

// docsPage is the Swagger UI shell. It is a const rather than a template
// because nothing in it varies: the asset URLs are absolute for the same
// reason every other route in this API is — the docs describe /v1, and a
// page mounted under some other prefix would be describing a different API.
//
// The inline script is Swagger UI's own initializer, reading the spec from
// the sibling endpoint rather than inlining it, so the raw YAML stays
// fetchable on its own (curl it, pipe it into a generator, diff it against
// openapi/spec.yaml).
//
// persistAuthorization is on because this API authenticates with a bearer
// token an operator has to paste in by hand; re-pasting it after every reload
// is the difference between a docs page someone uses and one they stop
// opening.
const docsPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>CrydenSync API reference</title>
<link rel="icon" type="image/png" sizes="32x32" href="/v1/docs/favicon-32x32.png">
<link rel="icon" type="image/png" sizes="16x16" href="/v1/docs/favicon-16x16.png">
<link rel="stylesheet" href="/v1/docs/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="/v1/docs/swagger-ui-bundle.js"></script>
<script src="/v1/docs/swagger-ui-standalone-preset.js"></script>
<script>
SwaggerUIBundle({
  url: "/v1/docs/openapi.yaml",
  dom_id: "#swagger-ui",
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
  layout: "StandaloneLayout",
  deepLinking: true,
  displayRequestDuration: true,
  persistAuthorization: true
});
</script>
</body>
</html>
`

// Page serves the Swagger UI HTML page.
func (h *DocsHandler) Page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(docsPage))
}

// Spec serves the OpenAPI document itself, byte for byte as it is embedded.
//
// The content type is set explicitly rather than inferred. Go's
// mime.TypeByExtension is not a fixed table — on Unix it also consults
// /etc/mime.types — so a deployment with an unusual system file could serve
// this as text/plain, and a client that trusts the header would then hand
// YAML to a JSON parser. Naming it here is the difference between correct on
// one machine and correct everywhere.
//
// It is read per request rather than cached in the handler because the read
// is a copy out of the binary's own data segment: microseconds, no I/O, and
// no second copy of a 116 KB document held for the life of the process.
func (h *DocsHandler) Spec(w http.ResponseWriter, r *http.Request) {
	spec, err := fs.ReadFile(h.assets, path.Join(docsAssetDir, "openapi.yaml"))
	if err != nil {
		// Unreachable in a built binary — an embed pattern that matches
		// nothing is a compile error — but a read error is still an error
		// rather than a reason to write a nil body with a 200.
		writeErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	w.Write(spec)
}

// Asset serves one vendored file: the Swagger UI bundle, its stylesheet, a
// favicon, or one of the licenses.
//
// The name is one path segment, because the route pattern is
// /v1/docs/{asset} and a wildcard segment never spans a slash. The check
// below is therefore belt and braces rather than the load-bearing guard —
// but it is written out rather than left implicit, because "the router
// pattern already prevents that" is a property of the route table, and this
// function should not become a directory traversal if the pattern is ever
// widened to {asset...}. fs.ValidPath would reject these names too; the
// point is that the refusal is visible here, next to the lookup it protects.
//
// Anything not in the embedded directory is a 404 in this API's own error
// envelope, not a bare http.NotFound. A client reaching this route is already
// speaking to this API, and one response contract is worth more than a
// conventional plain-text 404 on a static file.
func (h *DocsHandler) Asset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("asset")
	if name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\`) {
		writeErr(w, store.ErrNotFound)
		return
	}

	file, err := fs.ReadFile(h.assets, path.Join(docsAssetDir, name))
	if err != nil {
		writeErr(w, store.ErrNotFound)
		return
	}

	w.Header().Set("Content-Type", assetContentType(name))
	w.WriteHeader(http.StatusOK)
	w.Write(file)
}

// assetContentType names the type for a vendored file from its extension.
//
// A fixed table rather than mime.TypeByExtension, for the reason Spec gives:
// the standard library's answer depends on files outside this program, and a
// stylesheet served as text/plain is a page with no styling.
//
// A name with no extension at all is text/plain, which is what LICENSE and
// NOTICE are. That default is safe rather than merely convenient: text/plain
// is inert — a browser displays it and never executes it — so a file this
// code has not been taught about still cannot become a scripting vector.
// Anything with an extension the table does not list is
// application/octet-stream, which a browser downloads rather than renders,
// and is the right answer for the font or archive someone adds next.
func assetContentType(name string) string {
	switch ext := strings.ToLower(path.Ext(name)); ext {
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".png":
		return "image/png"
	case ".txt", "":
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
