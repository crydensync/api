package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Pagination and filtering bounds for the admin list endpoints. Named
// constants rather than literals at each call site so the cap is one
// decision: every one of these endpoints returns rows an operator reads
// by eye, and an unbounded limit is a way to make the API buffer a whole
// table into a JSON response.
const (
	defaultListLimit = 50
	maxListLimit     = 500
)

// queryInt reads an optional integer query parameter, falling back to def
// when it is absent or empty. A value that is not a number, or is outside
// [min, max], is an error the caller turns into a 400 — deliberately not
// clamped silently, because a caller asking for limit=100000 and getting
// 500 back has no way to tell that from a table that happens to hold 500
// rows.
func queryInt(r *http.Request, name string, def, min, max int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number", name)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d", name, min, max)
	}
	return n, nil
}

// queryLimit is queryInt with the shared list bounds, which is what every
// admin list endpoint wants.
func queryLimit(r *http.Request) (int, error) {
	return queryInt(r, "limit", defaultListLimit, 1, maxListLimit)
}

// maxListOffset bounds how far into a list a caller may page. Not a
// correctness bound — an offset costs the database the same whether it is
// 10 or 10,000 — but an unbounded one is a way to make a list endpoint
// walk a whole table one request at a time, and nothing in a console
// reads that far in.
const maxListOffset = 10000

// queryOffset reads the optional offset query parameter, defaulting to the
// first page.
func queryOffset(r *http.Request) (int, error) {
	return queryInt(r, "offset", 0, 0, maxListOffset)
}

// queryString reads an optional, trimmed string query parameter.
func queryString(r *http.Request, name string) string {
	return strings.TrimSpace(r.URL.Query().Get(name))
}
