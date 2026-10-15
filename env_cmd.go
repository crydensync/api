package main

import (
	"embed"
	"fmt"
	"os"
)

// The example environment rides in the binary rather than being fetched
// from anywhere: `go install github.com/crydensync/csag@v1.9.0` followed by
// `csag env` then prints the variable set that exact binary reads, with no
// network, no GitHub dependency and no way for the template to drift from
// the code that consumes it. A remote fetch would hand down main's
// example to a pinned older binary; the embed cannot.
//
//go:embed .env.example
var envExampleFS embed.FS

// runEnv is `csag env`: print the embedded .env.example to stdout so an
// install that never cloned this repo can still start from the full,
// commented template (`csag env > .env`, then edit). It loads no config and
// opens no database — it is the one command that must work on a machine
// with nothing but the binary.
//
// Refusing a --init-style write is a deliberate non-feature: the shell
// redirect in `csag env > .env` already truncates the target before this
// process runs, so a guard here could not see the overwrite it was meant
// to prevent. The command is print-only and says so, and the README flow
// says to run it once.
func runEnv(args []string) {
	for _, a := range args {
		fmt.Fprintf(os.Stderr, "unknown flag %q for `env`\n\n%s\n", a, usage)
		os.Exit(2)
	}

	body, err := envExampleFS.ReadFile(".env.example")
	if err != nil {
		// Unreachable in a normal build — the embed directive above
		// fails compilation if the file is missing — but a message
		// beats an empty stdout if a future build layout changes.
		fmt.Fprintf(os.Stderr, "env: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(body)
}
