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

## 2026-09-14 — Tier 1 (auth methods) except Apple

Branch `feat/tier1-auth-methods`, per `CODEX.md`'s one-branch-per-tier
rule. First session in this repo with a working Go toolchain: Go 1.25.0
plus cryden v2.5.0 and every dependency already in the module cache,
so the caveat the Tier 0 entry left open is closed — `go mod tidy`
changed nothing, and `go build ./...`, `go vet ./...`, `go test ./...`
and `gofmt -l` are all clean on this branch. That is the whole of what
was verified: **the DB-backed smoke test was not run** (no Postgres and
no network in this sandbox) and neither were the WebAuthn ceremonies,
which need a real browser authenticator. Those still owe a first run
against a real database. Saying that plainly here rather than counting
green builds as "verified end to end", per `CODEX.md`.

Built, in commit order:

- `chore: copy cryden 0003-0007 migrations as 004-008` — verbatim below
  the header line, which keeps cryden's original number for
  traceability while the filename continues this repo's sequence.
- `feat: add TOTP, passkey, recovery-code and magic-link endpoints` —
  the whole second-factor surface, plus the shared paused-login
  response and the new error mappings. TOTP/WebAuthn/recovery-code
  stores are gated on `ENCRYPTION_KEY` in `main.go`; an unconfigured
  method answers `404`, the same shape an unconfigured OAuth provider
  already used.
- `feat: add Microsoft, Discord and GitLab OAuth providers` — one case
  each, plus the token exchange moved onto a POST form body.
- `test: cover second-factor error mapping and the paused-login
  response` — `httpapi/errors_test.go`, the first `_test.go` files in
  this repo, deliberately limited to what needs no database.

Decisions and assumptions, none blocking:

- **A paused login is a `200`, not an error.** `NEXT.md` specified the
  completion endpoints but not what `/v1/login` should answer once a
  second factor exists. cryden reports that with
  `*auth.ErrSecondFactorRequired` (a struct carrying the pending token
  and enrolled methods), and unmapped that would have been a `500`.
  Chosen: `200` with
  `{"second_factor_required": true, "pending_token": ..., "methods": [...]}`,
  written in exactly one place (`httpapi/second_factor.go`) and reused
  by the OAuth callback and `/v1/magic-link/complete`, since all three
  can pause.
- **Token exchange uses a POST form body now.** The existing code put
  the code-for-token parameters in the query string; Microsoft and
  Discord require the RFC 6749 §4.1.3 body form and would not have
  worked otherwise. Google and GitHub accept the body too, so this
  replaced the branch-free query version instead of adding a per-
  provider special case.
- **Not-configured features are `404`, matching
  `oauth_provider_not_configured`** — a client can hide the option
  rather than report a server fault.
- **Recovery codes are wired whenever TOTP/WebAuthn are** (i.e.
  whenever `ENCRYPTION_KEY` is set), because they are a fallback for
  whichever factor is enrolled and are meaningless without one.
- **Partial WebAuthn config logs a startup warning and leaves passkeys
  off** rather than half-starting. All three `WEBAUTHN_*` values are
  required, and a browser ceremony is a bad place to discover one is
  missing.
- **The console magic-link sender's clickable URL is a dev-time
  guess** (`BASE_URL + "/magic-link?token=..."`). cryden hands over only
  the raw token and owns no routing; a real deployment points this at
  its own frontend route. Logged as an assumption here rather than
  quietly pretending this repo owns that path.
- **Apple is deliberately still open** and is the only unfinished part
  of Tier 1. It is not a fourth mechanical provider: the client secret
  is a self-signed ES256 JWT (so a private key in config), the email
  arrives inside a signed `id_token` that has to be verified against
  Apple's JWKS, and it cannot be smoke-tested without real Apple
  credentials. Recorded in `NEXT.md` with what it needs.

Noticed while working, not fixed (out of scope for this tier, flagged
rather than silently patched):

- `httpapi/errors.go` has no case for `auth.ErrPasswordPolicyViolation`
  or `auth.ErrPasswordBreached`, so a signup or password change that
  violates the configured policy currently answers
  `500 internal_error` instead of a `400` the client can act on. Real
  and user-facing; worth its own small fix.
- `README.md` tells you to `cp .env.example .env`, but the tracked file
  is named `.env.exampl`. Left as-is (renaming touches tooling outside
  this session's scope), noted so it does not keep getting copied
  forward.

Next: finish Tier 1's Apple provider (its own commit, and it will need
real credentials before it can be smoke-tested), then a first DB-backed
smoke-test run of everything above, then Tier 2.
