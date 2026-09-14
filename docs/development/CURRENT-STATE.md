# api — current state

## What's built

A thin HTTP wrapper around cryden v2.5.0 (bumped from v2.1.0 in Tier
0, see below). Routes cover signup, login, refresh, logout/logout-all,
sessions list/revoke, change password, delete account, email
verification and email change, and OAuth (Google/GitHub configured
today; the router itself is provider-agnostic via a `{provider}` path
param, so adding a provider is mostly config plus one switch-statement
case in `httpapi/oauth_handlers.go`, not a router change — see `NEXT.md`
Tier 1).

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

## Tier 1 through 5

Not started. See `NEXT.md` for the full, ordered, specced-in-detail
queue.
