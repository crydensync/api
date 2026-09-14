# api — current state

## What's built

A thin HTTP wrapper around cryden v2.5.0 (bumped from v2.1.0 in Tier
0, see below). Routes cover signup, login, refresh, logout/logout-all,
sessions list/revoke, change password, delete account, email
verification and email change, and OAuth — Google, GitHub, Microsoft,
Discord and GitLab configured today (the router itself is
provider-agnostic via a `{provider}` path param, so a provider is one
switch-statement case in `httpapi/oauth_handlers.go` plus its env vars,
not a router change; Apple is the one provider that does not fit that
shape and is still open — see `NEXT.md` Tier 1).

Tier 1 also added the second-factor surface: TOTP enroll/confirm/
disable, passkey registration/list/delete, magic-link request/complete,
recovery-code generation, and the three public completion endpoints a
paused login uses. No authentication logic was added to this repo for
any of it — each handler is an engine call plus this repo's envelope;
the engine still owns hashing, token rotation, lockout and
second-factor state. TOTP, WebAuthn and recovery codes are optional per
deployment, gated on `ENCRYPTION_KEY` (see `main.go`), and an
unconfigured method answers `404`, never a startup failure.

Two independent rate-limit layers: cryden's own per-user engine-level
limiter, and this repo's own coarse per-IP edge limiter
(`httpapi/ratelimit.go`), in-memory and single-process, same caveat as
cryden's own default limiter.

Response envelope, error codes, and the migration-copying convention
are all established — see `README.md` and `CODEX.md`.

## Tier 0 — bump the engine to v2.5.0: DONE

`go.mod` now requires `cryden v2.5.0`. This alone doesn't add any new
functionality yet — every feature Tiers 1 through 4 need (TOTP,
WebAuthn, magic link, recovery codes, more OAuth providers, anomaly/
credential-stuffing detection, named sessions, Redis rate limiter,
Argon2id, JWT claims, API keys, webhooks, the AI-assisted admin tools)
is now available to import and wire up, none of it is wired up yet
except what Tier 0.5 needed.

**Verification gap, disclosed rather than glossed over:** this was
built and reviewed in a sandbox with no route to a Go ≥1.25 toolchain
or `proxy.golang.org` (cryden's own `go-webauthn` dependency floors the
whole module at Go 1.25). `gofmt` is clean on every new/changed file,
and every new file was checked by hand against cryden's real exported
signatures (confirmed via a local copy of the engine source, not
guessed). `go.sum` was **not** regenerated here and will need
`go mod tidy` run once on a machine with a real Go 1.25 toolchain
before this builds. That is the first thing to do before touching
anything else in this repo.

## Tier 0.5 — admin/operator authorization foundation: DONE

Console operator status is a concept this repo owns entirely, not
cryden — see `CODEX.md`'s ownership section for why.

- `migrations/003_operators.up.sql` / `.down.sql` — a new `operators`
  table, `user_id` (references cryden's own `users.id`), `role` (plain
  string, defaults to `"admin"`), `created_at`. Nothing about this
  table lives in cryden's schema or cryden's Go types.
- `operator/store.go` — `operator.Store`, a small `RoleFor`/`Grant`/
  `Revoke` API over that table. Its own importable package (not a file
  in `package main`) specifically so both the running server and the
  standalone bootstrap CLI below can use it, without one `package main`
  trying to import another, which Go doesn't allow.
- `cmd/grant-operator/main.go` — a standalone command-line tool that
  looks a user up by email via cryden's own `postgres.UserStore` and
  grants/revokes their operator row. Deliberately **not** an HTTP
  endpoint: an admin-bootstrap route reachable over the network, gated
  or not, is needless attack surface for something that only ever
  needs to run from a trusted machine with direct database access.
- `main.go` wires `operator.Store` into cryden's `Config.AccessTokenClaims`
  (via `token.ClaimsFunc`, cryden's own function-to-interface adapter):
  an operator's access token gets a `role` claim; an ordinary end
  user's token gets no extra claims at all, not even `role: "user"`.
- `httpapi/middleware.go` gained `RequireAdmin`, which verifies the
  token exactly like `RequireAuth` and additionally requires that
  `role` claim to equal `"admin"`. An unknown user, a revoked operator,
  and someone who was simply never an operator all fail identically —
  `errNotOperator` / `403 not_operator` — that distinction is not the
  caller's to learn.

**No admin endpoints exist yet.** This tier is only the mechanism later
tiers gate behind. The first real use of `RequireAdmin` will be
whichever Tier 4/5 endpoint lands first.

## Tier 1 — auth methods (all but Apple): DONE

Built on `feat/tier1-auth-methods` (its own branch, per `CODEX.md`'s
one-branch-per-tier rule), in this order:

- `migrations/004`-`008` — cryden's `0003`-`0007` copied in, renumbered
  to this repo's sequence, header line keeping the original cryden
  number so the source stays traceable. Verbatim below the header.
- **TOTP** (`httpapi/totp_handlers.go`): `POST /v1/totp/enroll`
  (returns the `otpauth://` URL), `/confirm`, `/disable` (password
  re-confirmation), and the public `POST /v1/login/totp` that finishes a
  paused login.
- **Passkeys** (`httpapi/passkey_handlers.go`): register begin/finish,
  list, delete-by-credential-ID (password re-confirmation), plus the
  public login begin/finish pair. Ceremony options and the browser's
  credential response are passed through as raw JSON — an object, not a
  JSON-encoded string — because that is what `navigator.credentials`
  produces and consumes.
- **Magic link** (`httpapi/magiclink_handlers.go` + a new
  `notify.MagicLinkSender` in `email_sender.go`): request (always the
  same `200` either way — it never creates accounts, and anything else
  would enumerate emails) and complete. cryden keeps `MagicLinkSender`
  separate from `EmailSender` on purpose, so this is a new small type,
  not a second method on the console sender.
- **Recovery codes** (`httpapi/recovery_handlers.go`): generate (the
  raw codes are shown exactly once and the response says so) and the
  public login completion.
- **Paused logins** (`httpapi/second_factor.go`): a correct password is
  no longer always enough, so `/v1/login`, the OAuth callback and
  `/v1/magic-link/complete` now answer `200` with
  `second_factor_required` + `pending_token` + `methods` instead of
  letting `*auth.ErrSecondFactorRequired` fall through to a 500. This
  response shape was not specified in `NEXT.md` and is this tier's one
  real design decision — see `PROGRESS.md`.
- **More OAuth providers**: Microsoft, Discord, GitLab — same
  authorization-code shape as Google/GitHub, one case each. The
  code-for-token exchange moved to a POST form body (RFC 6749 §4.1.3)
  because Microsoft and Discord require it and Google/GitHub accept it,
  replacing the previous query-string form rather than branching per
  provider.
- **Error mapping** (`httpapi/errors.go`): every new engine error mapped
  once there — the eight per-method errors and the four "not
  configured" sentinels (`404`, matching
  `oauth_provider_not_configured`).
- `httpapi/errors_test.go` — the first test files in this repo: the new
  `(status, code)` mappings (including when wrapped) and the paused-
  login response shape. Chosen deliberately as the largest slice
  verifiable without a database.

**Verification gap, disclosed rather than glossed over:** `go build
./...`, `go vet ./...` and `go test ./...` are clean on this branch
(Go 1.25.0, cryden v2.5.0 from the local module cache), and `gofmt -l`
is empty. The DB-backed smoke test was **not** run — this sandbox has
no Postgres and no network — so the end-to-end paths (especially the
WebAuthn ceremonies, which need a real browser authenticator) are
still owed a first run against a real database before Tier 1 counts as
verified the way cryden's own features are.

**Apple is the one open part of Tier 1** — not a fourth mechanical
provider case: its client secret is a self-signed short-lived JWT, and
the email arrives inside a signed `id_token` that has to be verified
against Apple's JWKS. Left open deliberately rather than half-built.

## Tier 2 through 5

Not started. See `NEXT.md` for the full, ordered, specced-in-detail
queue.
