# CLAUDE.md — working conventions for this repo

Read this fully before writing any code. Then read `docs/development/CURRENT-STATE.md`
(what exists and why) and `docs/development/NEXT.md` (the ordered queue,
specced in enough detail that you should not need to guess). Update
`docs/development/PROGRESS.md` with a short entry every session, even
a failed one.

## What this repo is

A generic HTTP wrapper around [cryden](https://github.com/crydensync/cryden),
the actual auth engine. This repo owns HTTP concerns (routing, request
parsing, response envelopes, CORS, edge rate limiting) and nothing
about authentication logic itself — that all lives in cryden. If you
find yourself reimplementing something cryden already does (hashing,
token rotation, lockout, second-factor state), stop, you're doing the
engine's job in the wrong repo.

## The one hard rule carried over from the engine

Cryden's AI-assisted admin tools (weekly digest, support-ticket
assistant, config tuning advisor, ask-ai widget) are read-only and
surface-only by construction — none of them can take an action. That
rule does not stop at the engine boundary. Any endpoint this repo adds
on top of those tools must stay read-only too. A "config tuning
advisor" endpoint that writes the suggested value straight into live
config is a violation of this rule, not a shortcut. If a suggestion
needs to become a real change, it goes through the same explicit,
human-confirmed settings-save path every other config change uses —
see `docs/development/NEXT.md`'s Tier 4 section for the exact decision
already made here (pre-fill, never auto-apply).

## Ownership boundary: what's cryden's and what's this repo's

Cryden's `store.User` has no role, permission, or arbitrary-metadata
concept, on purpose — authorization is a host decision, not an engine
one (see cryden's own `docs/design-decisions.md`). Anything this repo
needs that isn't authentication mechanics belongs in this repo's own
tables and its own packages, never bolted onto cryden's schema or
forked into cryden's source. Concretely, as of this doc:

- **Console operator/admin status** — `operator/` package,
  `migrations/003_operators.*.sql`. Not a cryden concept.
- **Per-user custom metadata** (needed for JWT-claim mapping in the
  console) — will be its own table when Tier 3's JWT claims work
  starts. Not a cryden concept.
- **Delivery logs** (email, webhook, cloud-logging "shipped events")
  — each is this repo's own table, populated by this repo's own
  `notify.EmailSender`/`notify.WebhookSender`/`logger.Logger`
  implementations. Cryden calls the interface; it does not log a
  queryable history of what happened.
- **Digest scheduling and digest history** — cryden's
  `WeeklyDigest`/`DigestSince` just return a string on demand. Any
  cron/scheduling and any "past digests" list is this repo's own
  infrastructure.
- **LLM provider and read-only-DB-role configuration for the AI
  tools** — cryden's `ai.LLMProvider`/`ai.QueryableStore` are Go
  interfaces you implement in code. If the console needs to configure
  these at runtime through a settings screen instead of a redeploy,
  this repo owns that config storage and the glue that turns it into
  a live `ai.LLMProvider`/`ai.QueryableStore` at startup.

When in doubt: if cryden already answers the question (a count, a
report, a check), call it. If cryden has no concept of the thing at
all, it's this repo's job to add, not a reason to go patch cryden.

## Workflow

- **One branch per tier.** Tier 0 and Tier 0.5 were built directly on
  `main` as the foundation everything else sits on; every tier after
  that gets its own branch, same as cryden's own tiered branches.
- **Conventional commits** (`feat:`, `fix:`, `chore:`, `docs:`,
  `test:`), one logical step per commit, same discipline cryden's own
  history follows. Don't squash unrelated changes into one commit, 
  commit messages should not be more that five lines.
- **Update the docs at the end of each tier**: mark it done in
  `NEXT.md`, add its section to `CURRENT-STATE.md`, log it in
  `PROGRESS.md`. A tier isn't finished until the docs say so.
- **Migrations are copied, not referenced.** This repo keeps its own
  copy of every cryden Postgres migration (see README's existing note
  on `001`/`002`), so it stays self-contained for local dev and CI.
  Every tier that bumps the engine and picks up a new cryden migration
  must add the matching copy here too, numbered to continue this
  repo's own sequence, not cryden's. Cryden is currently five
  migrations ahead of what's copied here (TOTP, WebAuthn, recovery
  codes, login attempts, API keys) — see `NEXT.md` Tier 1.

## Response contract (already established, don't change it)

```json
// success
{ "data": { ... } }

// error
{ "error": { "code": "invalid_credentials", "message": "invalid email or password" } }
```

Every new endpoint follows this. `code` is stable and machine-branchable,
add new engine errors to `httpapi/errors.go`'s `mapError` once, every
handler that can return that error benefits automatically.

## Verification

Run `go build ./... && go test ./...` and, where relevant, the
matching cryden smoke test before calling a tier done. If your
environment can't reach a Go 1.25 toolchain or `proxy.golang.org`
(cryden's own `go-webauthn` dependency floors the whole module at Go
1.25), say so plainly in `PROGRESS.md` rather than claiming a build you
didn't actually run — see that file's own entries for the exact
pattern to follow.
