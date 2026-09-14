# api — progress log

## 2026-09-13 — Tier 0 (engine bump) and Tier 0.5 (admin foundation)

Built directly on `main`, no new branch, per explicit instruction —
every tier after this one gets its own branch as normal.

**Tier 0**: bumped `go.mod` to `cryden v2.5.0`. `go.sum` was not
regenerated — this sandbox has no route to a Go ≥1.25 toolchain or
`proxy.golang.org` (cryden's own `go-webauthn` dependency floors the
whole module at Go 1.25, confirmed by hitting the same wall building
cryden itself in an earlier session). Run `go mod tidy` on a real
machine before this builds. Nothing else was verifiable end to end for
the same reason; every new/changed file was instead checked by hand
against cryden's actual exported signatures from a local copy of the
engine source, and `gofmt -l` is clean on everything touched.

**Tier 0.5**: added `operator/` (its own importable package, not a
file in `package main`, since the standalone `cmd/grant-operator` tool
needs to use it too and Go doesn't allow importing one `package main`
from another — caught this before writing the CLI, not after a build
failure), `migrations/003_operators.*.sql`, `cmd/grant-operator/main.go`,
and wiring in `main.go`/`httpapi/middleware.go`/`httpapi/errors.go` for
a `role` claim and `RequireAdmin`.

Assumptions made, none blocking:
- Operator status is a plain string role (defaults `"admin"`), not an
  enum — matches cryden's own convention for `OAuthIdentity.Provider`,
  so a new role never needs a migration.
- No HTTP endpoint exists to grant the first operator, on purpose — a
  network-reachable admin-bootstrap route is unnecessary attack
  surface. `cmd/grant-operator` requires direct database access
  instead.
- An unknown user, a revoked operator, and someone who was never an
  operator all get the identical `403 not_operator` — that distinction
  is not something to expose to the caller.

Next: Tier 1 (auth methods), each on its own branch per `CODEX.md`.
Copying cryden's migrations `0003`-`0007` into this repo (renumbered
continuing from `003_operators`) is the first sub-step, before any
TOTP/WebAuthn/magic-link/recovery-code endpoint work starts.
