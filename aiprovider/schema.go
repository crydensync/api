package aiprovider

import "sort"

// sortedKeys returns the keys of a string-keyed set in a stable order.
//
// The order matters and is not cosmetic. These feed JSON Schema enums
// that sit inside the request's system-prompt prefix, and prompt caching
// is a prefix match — a map iterated in Go's random order would produce a
// different schema on every request, invalidating the cache every time
// and paying full price for a prompt that never changed.
func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// enumOf wraps values as a JSON Schema enum of strings.
func enumOf(values []string) map[string]any {
	return map[string]any{
		"type": "string",
		"enum": values,
	}
}
