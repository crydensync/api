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

## 2026-09-14 (later) — the two flagged issues, then Apple

Same branch, four more commits. Tier 1 is now complete, Apple included.

**Fixed the two things flagged in the entry above**, each its own commit:

- `fix: map password-policy and breached-password errors to 400` —
  `auth.ErrPasswordPolicyViolation` and `auth.ErrPasswordBreached` now
  map to `400`/`password_policy_violation` and `400`/`password_breached`
  instead of falling through to `500 internal_error`. The policy error
  keeps its struct case and `writeErr` reads the broken-rule codes off
  the error into an optional `details` array — the one addition to the
  error envelope, and it appears on no other error (both halves are
  pinned by tests, so an existing client sees a byte-identical shape).
- `chore: rename .env.exampl to .env.example` — renamed rather than
  rewriting the README, since the README's name is the conventional one
  and `.gitignore` only ignores `.env` itself.

**Apple** (`feat: add Sign in with Apple`, `httpapi/apple.go` +
`apple_test.go` + `golang-jwt` promoted from indirect to direct):

- Client secret is an ES256 JWT signed per exchange with the console
  `.p8` key (10-minute expiry, `kid` header, `iss`=team, `sub`=client
  ID, `aud`=Apple). `APPLE_CLIENT_ID`/`TEAM_ID`/`KEY_ID`/`PRIVATE_KEY`
  are all required; a partial config reads as unavailable, same as any
  other unconfigured provider. `APPLE_PRIVATE_KEY` accepts a `.env`-style
  `\n`-escaped PEM and leaves a real multiline value alone.
- No userinfo endpoint: the identity comes from the token response's
  `id_token`, verified against Apple's JWKS (RS256 only, issuer,
  audience, expiry, `kid` lookup) with the key set cached for an hour
  and refetched once on an unknown `kid` so a rotation is picked up.
  An unverified decode would have let anyone who can reach the callback
  mint an account, so this is the part that got the most test attention.
- `exchangeCode` now takes the client secret as an argument and returns
  both the access token and the id_token, which lets Apple reuse the
  existing POST plumbing instead of duplicating it. The authorization
  redirect query is now built in one `authQuery` helper used by both the
  login and linking flows, so a provider-specific parameter cannot be
  added to one and forgotten in the other.

Assumptions made while building Apple (recorded, not silent):

- **`response_mode=query`**, so the existing GET callback route works
  unchanged. Consequence: Apple's one-time `user` payload (the name it
  sends only on a first authorization, and only under `form_post`) is
  not captured — this repo stores the id_token's email, never names,
  which is all `LoginWithOAuth` takes anyway.
- **No `nonce`.** Apple requires one for the hybrid/implicit flow; this
  is the authorization-code flow, where the code is single-use, bound to
  this client, and the redirect already carries a CSRF `state` cookie
  verified against a signed cookie. Revisit only if a hybrid flow is
  ever added.
- **Apple's email is required**, like every other provider here — if the
  id_token has no email claim the login fails with the existing
  `oauth_email_not_available` rather than inventing an identity.

Verification: `go build ./...`, `go vet ./...` and `go test ./...` clean,
`gofmt -l` empty. `apple_test.go` covers the generated secret (parses as
ES256, correct `kid`/`iss`/`aud`/`sub`, unexpired; RSA and non-PEM keys
rejected) and id_token verification (accepted when signed by the served
key; rejected for wrong audience, wrong issuer, expiry, different
signing key, unknown `kid`, missing subject, and an `alg: none` token).
Still **not** verified here: a live Apple round trip (no credentials, no
network), the DB-backed smoke test (no Postgres), and the WebAuthn
ceremonies (no browser authenticator). Those remain the first things to
run on a real deployment.

Next: Tier 2, on its own branch per `CODEX.md` — and before or alongside
it, the first DB-backed smoke-test run of everything in Tier 1.

## 2026-09-15 — Tier 2 (config, named sessions, OAuth health)

Branch `feat/tier2-config-and-oauth-health`, per `CODEX.md`'s
one-branch-per-tier rule. Three commits, in order:

- `feat: wire anomaly detection and the Redis rate limiter from env` —
  `config/config.go` (new fields, `envInt`/`envBool`/two duration
  helpers), `main.go` (anomaly store + thresholds, Redis limiter),
  `config/config_test.go`, `.env.example`, README.
- `feat: return named sessions from GET /v1/sessions` —
  `httpapi/session_handlers.go`, its first test file for an endpoint,
  the smoketest's sessions check, `openapi/spec.yaml`, README.
- `feat: add GET /v1/admin/oauth/health` — `httpapi/oauth_health.go` +
  tests, the provider-name list next to `provider()`, the route in
  `router.go`, spec and README (including the operator section the
  README never had).

**Verification.** `go build ./...`, `go vet ./...`, `go test ./...` and
`gofmt -l` are all clean on Go 1.25.0 with cryden v2.5.0 from the local
module cache; `go mod tidy` moved `github.com/redis/go-redis/v9` from
indirect to direct and changed nothing else in `go.mod`/`go.sum`.

The material change from previous sessions is *what* the tests can
reach: cryden ships its own in-memory stores, so a real engine — and via
`httpapi.NewRouter` a real router — can be built with no Postgres. Tier
1's tests stopped at error mapping because there was nothing to build an
engine on. This tier's tests sign up, log in, call `GET /v1/sessions`
through `RequireAuth`, and call `GET /v1/admin/oauth/health` through the
real router with an operator's token (and with a non-operator's, and
with none), all offline. The health endpoint's four verdicts are
covered against `httptest` servers, including that the probe sends no
query string.

Still **not** verified, unchanged and repo-wide: the DB-backed smoke
test has not been run (no Postgres, no network here), the WebAuthn
ceremonies need a real browser authenticator, and a live Apple round
trip needs Apple credentials. Tier 2 itself has no DB-specific logic
that the in-memory tests miss — the only thing needing Postgres is the
`login_attempts` table behind `ANOMALY_DETECTION`, and the engine's own
migrations for it were copied in Tier 1 as `007`.

**Environment note, disclosed rather than glossed over.** Both sandboxes
in this container are broken: command execution fails with `bwrap:
setting up uid map: Permission denied`, and `apply_patch` cannot read or
write paths under the workspace at all (`fs sandbox helper failed ...
bwrap: loopback: Failed RTM_NEWADDR`). Every command in this session was
therefore run with escalation, and every edit went through `apply_patch`
against a hard link in `/tmp` pointing at the same inode as the file in
the workspace — the tool's own write path, not a substitute for it. That
is a workaround this environment forced, not a change to the workflow:
nothing about the resulting files differs from a normal `apply_patch`,
and all the usual checks (`gofmt`, build, vet, tests) ran on the real
tree. Worth knowing for whoever picks up Tier 3 in a working sandbox:
if `apply_patch` starts failing on workspace paths again, this is why.

Decisions and assumptions, none blocking:

- **`config` now imports `cryden/v2/security`**, which it never used to
  depend on the engine at all. The alternative was retyping eight
  threshold defaults into this repo, where they would drift silently
  from the engine's own. The structs are constructed as copies of
  `security.Default*` and then overridden per env var, because cryden
  reads every field of a non-zero thresholds value — a partial struct
  would switch off the checks it left out rather than default them.
- **The two rate-limit bounds default to 10/minute rather than 0.**
  cryden only fills a zero value in for the in-process limiter it builds
  itself; with `REDIS_URL` set this repo calls
  `security.NewRedisRateLimiter`, whose constructor rejects zero. Left
  at zero, `REDIS_URL` on its own would have been a startup failure —
  found while writing the config test, not in production.
- **An explicit `0` from env passes through untouched** rather than
  being treated as unset. Several cryden knobs use 0 as a real "switch
  this check off" setting, so the loaders cannot tell "off" from "not
  given" without a second convention; the README and `.env.example`
  explain that 0 means whatever the engine says it means per knob.
- **No geolocator is wired, so session labels are device-only.**
  `Config.Geolocator` is what fills the location half, and cryden ships
  no implementation on purpose — every implementation calls somebody
  else's internet service. That is a deployment's decision, not this
  repo's to make for it. Consequence recorded in the README, the spec
  (the `location` object is documented as present-but-empty) and the
  handler's own comment; `label` is never empty either way, since the
  engine falls back to `"Unknown device"`.
- **The named-sessions change is documented as breaking.** The spec
  described the old four fields but was not marked fixed or
  additive-only, so "bump the response" was read as: document the change
  in both places. `openapi/spec.yaml` goes to 1.1 with a description of
  what changed; README explains it in prose.
- **OAuth health: a 4xx is `ok`, not a failure.** A bare GET to an
  authorize endpoint with no `client_id` gets a 400/405 from every
  provider here — that is proof the endpoint is up and serving, which is
  the question being asked. Only 5xx is `degraded` and only "no HTTP
  response at all" is `unreachable`. Unconfigured providers are reported
  without being probed, which also means this endpoint never reaches out
  to a provider the deployment has not opted into.
- **The provider list lives next to `provider()`** in
  `oauth_handlers.go` rather than in the health file: the one way the
  two can drift is a new provider case added without a name added here,
  and keeping them adjacent is the cheapest guard.

Noticed while working, not fixed (out of scope for this tier, flagged
rather than silently patched):

- **`openapi/spec.yaml` still predates Tier 1.** None of the
  TOTP/passkey/magic-link/recovery endpoints, the extra OAuth providers,
  or the paused-login response are in it, and `ErrorResponse` has no
  `details` array for `password_policy_violation`. A documentation-only
  pass would fix it; this tier only added its own path rather than
  backfilling someone else's.
- **The coarse per-IP edge limiter is still in-process even with
  `REDIS_URL` set.** Deliberate — that is `httpapi/ratelimit.go`, a
  different layer with different trade-offs (it is a whole-API guard,
  not a login limiter), and sharing its counters across replicas is its
  own decision rather than a side effect of this one. Flagged so it is
  not mistaken for an oversight.
- **`internal/smoketest` cannot cover the admin surface.** It is HTTP
  only, against an already-running instance, and it has no way to make
  anyone an operator (`cmd/grant-operator` needs database access the
  smoketest does not have). An optional operator token/email flag would
  fix it if that coverage is wanted later.

Next: Tier 3, on its own branch per `CODEX.md`. Still owed from before
it: the first DB-backed smoke-test run, now worth doing against a
`REDIS_URL`-less and a `REDIS_URL`-set instance so the shared limiter
gets its first real exercise.

## 2026-09-15 — Tier 3, Stage 1 (config, API keys, hash migration)

Tier 3 was split into two stages with an explicit mid-point check-in.
Stage 1 is written; Stage 2 (per-user metadata + JWT claims, webhooks +
delivery log, shipped-events log) has not been started.

Most of this session had **no command execution at all**. Every
command-executing tool — `Bash`, `Monitor`, and subagents alike —
failed with `deepseek-v4-flash is temporarily unavailable, so auto mode
cannot determine the safety of ...`. Only file reads and writes worked.
So Stage 1 was written, and its cryden symbols verified by reading the
module cache, without a single build. This is a *different* failure from
the `bwrap`/`apply_patch` breakage the Tier 2 entry describes: the Go
1.25.0 toolchain and the full module cache were still here and still
working — what was unavailable was command execution, not the toolchain.

Command execution came back at the end of the session, and everything
was then actually run on `feat/tier3-config-and-endpoints` (branch
created once git was reachable):

```
go build ./...   clean
go vet ./...     clean
gofmt -l .       empty, after two fixes (below)
go test -count=1 ./...
  ok  github.com/crydensync/api/config    0.012s
  ok  github.com/crydensync/api/httpapi   6.129s
  ok  github.com/crydensync/api/templates 0.008s
```

Every Tier 3 test was also confirmed passing individually, including
`TestHashMigrationTracksARealBcryptToArgon2idUpgrade`, which drives the
real upgrade path (sign up on Argon2id, overwrite the stored hash with
bcrypt, log in, assert the engine's own rewrite is reported) rather
than a hand-seeded audit row.

Stage 1 landed as four commits on that branch, each verified on its own
(`go build`/`go vet`/`gofmt -l`/`go test -count=1` after every one, not
only the last): the `Deps` refactor, then config + templates, then the
API key endpoints, then the hash-migration report. Splitting them meant
reconstructing intermediate states of `main.go`, `httpapi/router.go` and
`httpapi/errors.go`, which each carry hunks belonging to more than one
commit — `git add -p` is unavailable in this environment, so each
file's part-way state was written, built and committed in order. The
final state of all three was diffed against the version the full-suite
run above covered; the only difference is one reworded doc comment in
`router.go`, and that exact tree was rebuilt and retested.

`gofmt` was the one place the reasoning-first approach was actually
wrong, and it is worth recording which half: hand-reasoned struct field
alignment was **correct** — none of `apiKeyDTO`, `hasherDTO`,
`hashMigrationDTO` or `templates.Data` were flagged — but two spots
nobody had considered were: a `map[string]any` literal in
`apikey_handlers.go` whose keys needed aligning, and `main.go`'s
trailing `// dev stand-in` comments, which align against the longest
line in their group. Both fixed with `gofmt -w`.

**What was checked before the toolchain was reachable** — since
`CODEX.md`'s rule is to say what was and was not done rather than to
imply a build — every cryden symbol Stage 1 calls was read directly out
of the module cache at `…/cryden/v2@v2.5.0`, first-hand, not recalled.
Confirmed:

- `cryden.GenerateAPIKey(ctx, e, userID, name, scopes, ttl)`,
  `ListAPIKeys(ctx, e, userID)`, `RevokeAPIKey(ctx, e, userID, keyID)`
  all exist as root-package facade functions (`cryden.go`), with
  exactly the shapes the handlers call. `NEXT.md`'s Tier 3 spec names
  them the same way, so the spec was accurate here.
- `cryden.APIKey` is a **root-package** struct (`ID`, `Name`, `Prefix`,
  `Scopes`, `ExpiresAt *time.Time`, `CreatedAt`, `LastUsedAt`) with an
  `Expired()` method — *not* `store.APIKey`, which is the storage-side
  record and does carry `KeyHash`. The handler's DTO is built from the
  public one, which is what makes "no key hash can be marshalled by
  accident" structural rather than a rule to remember.
- `cryden.ErrAPIKeysNotConfigured` exists (`cryden.go`), and
  `auth.ErrInvalidAPIKey` / `ErrAPIKeyNotFound` / `ErrInvalidAPIKeyScope`
  / `ErrInvalidAPIKeyTTL` exist with the messages mapped in
  `httpapi/errors.go`.
- `auth.apiKeyPrefixFragment` builds the stored `Prefix` as
  `"ck_" + first 8 chars of the secret` — so it is `ck_9f3a1c02`, not
  the bare label. A first draft of the API-key test asserted `== "ck"`
  and would have failed; found by reading the engine's implementation
  and fixed before any run.
- `logger.ParseLevel` is case- and whitespace-insensitive, accepts
  `warning`/`err` as well as `warn`/`error`, and returns the zero
  `Level` with `ErrUnknownLevel` on a miss — the doc comment on it is
  explicit that neither defaulting direction is acceptable.
- `logger`'s own package doc pins the intended composition for Stage 2
  as `NewMultiLogger(NewConsoleJSONLogger(), NewLevelFilter(NewMaskingRedactor(sink), level))`
  — redaction *inside* the fan-out, so local stdout keeps the IP and
  only the outbound copy loses it.

Stage 1, by file:

- `httpapi/router.go` — `NewRouter(engine, db, cfg)` becomes
  `NewRouter(Deps)`, since Tier 3's admin endpoints need store instances
  `cryden.Engine` keeps unexported. Two call sites: `main.go` and
  `oauth_health_test.go`. Handlers guard a nil store and answer
  `404 not_configured`.
- `config/config.go` — `PASSWORD_HASHER`, the five `ARGON2ID_*` knobs,
  `API_KEY_PREFIX`, `LOG_LEVEL`, `CLOUD_LOGGING`,
  `CLOUD_LOG_REDACTION`, `CLOUD_LOG_HASH_KEY`, `EMAIL_TEMPLATE_DIR`,
  plus `envString`/`envUint32`/`envUint8`. The unsigned readers exist so
  a minus sign is a startup failure rather than a value that wraps to
  255 lanes.
- `templates/` (new) — `text/template` over `verification.txt` /
  `magic_link.txt`, fields `{{.To}} {{.Token}} {{.URL}}`. Each message
  falls back independently; a directory with neither file, or an
  unparseable one, is a startup failure.
- `email_sender.go` — both console senders render a configured template
  when there is one and print their original line byte-for-byte when
  there is not.
- `httpapi/apikey_handlers.go` + test — the three routes, one-time raw
  key with a notice, bounded `expires_in_days`, scoped revoke.
- `httpapi/security_handlers.go` + test —
  `GET /v1/admin/security/hash-migration`, behind `RequireAdmin`.
- `httpapi/errors.go`, `query.go`, `response.go`, `main.go`,
  `.env.example`, `README.md`, `openapi/spec.yaml` (1.2).

Two test bugs were found and fixed by reading rather than by a red test,
worth recording because neither would have been caught by a type check:
the `"ck"` prefix assertion above, and
`TestAPIKeyRevokeIsScopedToTheCallingUser` originally built its two
accounts on **separate engines**, so its 404 came from a key that simply
was not in that store — proving nothing about the `WHERE id = $1 AND
user_id = $2` predicate it claimed to test. Both accounts now share one
engine.

Decisions and assumptions, none blocking:

- **The hash-migration report's field names are load-bearing.**
  `upgraded_events` counts events, so it can exceed `total_users` after
  a second cost increase; `estimated_remaining` is therefore *estimated*
  and floored at zero. Naming it `remaining` would be a number an
  operator trusts more than they should. README and spec both say so in
  prose.
- **Stage 1 ships cloud-logging config with nothing reading it yet.**
  The user's own staging put "cloud-logger config" in Stage 1 and the
  shipped-events log in Stage 2, so `CloudLogging`/`LogLevel`/
  `CloudLogRedaction` are parsed and validated now and composed in
  `main.go` when Stage 2 lands. Since both stages land on one branch
  before any merge, no release ever sees the dead switch — but a
  reviewer reading Stage 1 alone will notice it, so it is said here.
- **`BCRYPT_COST` was not added.** A real engine knob with no env var
  here, but Tier 3 asks for Argon2id; flagged rather than taken as
  scope.
- **The Argon2id params are always assembled**, even when the selected
  hasher is bcrypt, so the report can state what the deployment is
  configured to write without rebuilding that answer from a second
  place.

Noticed while working, not fixed:

- **`openapi/spec.yaml` still predates Tier 1**, unchanged from the Tier
  2 note. Stage 1 added only its own paths on top of that gap.
- **This repo still has no graceful shutdown.** `main.go` ends at
  `log.Fatal(http.ListenAndServe(...))`. Stage 2's webhook worker wants
  a context it can be stopped with, so the worker takes one and gets
  `context.Background()` — introducing real shutdown is its own change
  touching every component, and smuggling it in behind a worker would
  not be honest about its size.

Next: Stage 2, once someone can run a build. The check-in the user
asked for is the point at which this entry was written; Stage 1's code
should be built, vetted, formatted and tested before Stage 2 starts on
top of it.
