package main

import (
	"fmt"
	"os"
)

// version is what `api version` prints. It is empty in a plain `go
// build` and stamped at link time by the release workflow: `-X
// main.version=$GITHUB_REF_NAME` names the tag that produced the
// binary, so an installed binary can answer the question "which
// release am I running?" — the one a bug report needs first and the
// one a boot log cannot reliably give, since a rebuilt commit and a
// tagged release differ nowhere else.
//
// The fallback is not "unknown": a dev build is one whose provenance
// is the working tree rather than a tag, and `dev` says exactly that
// without pretending a tag it cannot name.
var version = "dev"

// runVersion is `api version`: print the stamped version and exit. It
// is dispatched before config.Load like migrate and env — a binary on a
// machine with no .env must still be able to say what it is.
func runVersion(args []string) {
	for _, a := range args {
		fmt.Fprintf(os.Stderr, "unknown flag %q for `version`\n\n%s\n", a, usage)
		os.Exit(2)
	}
	fmt.Printf("api %s\n", version)
}
