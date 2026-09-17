# api — current state

## What's built

A thin HTTP wrapper around cryden v2.5.0 (bumped from v2.1.0 in Tier
0, see below). Routes cover signup, login, refresh, logout/logout-all,
sessions list/revoke, change password, delete account, email
verification and email change, and OAuth — Google, GitHub, Microsoft,
Discord, GitLab and Apple configured today (the router itself is
provider-agnostic via a `{provider}` path param, so a provider is one
switch-statement case in `httpapi/oauth_handlers.go` plus its env vars,
not a router change; Apple is the one that does not fit that shape and
has its own `httpapi/apple.go` — see `NEXT.md` Tier 1).

Tier 2 added one admin endpoint on top of those, the first in this repo
— see below. Tier 3 added three more admin endpoints and this repo's
first three tables of its own, plus the config that lights up Argon2id,
cloud logging and email templates — see below. Tier 4 added six more
admin endpoints and two more tables of its own: Stage 1 is the weekly
digest and its recorded history, the support-ticket login diagnosis and
the config tuning advisor; Stage 2 is the AI provider settings — the LLM
provider, the read-only database and the ask-ai widget config. Tier 4 is
also where this repo stopped being purely a wrapper: it now ships a live
`ai.LLMProvider` over the Anthropic SDK and a live `ai.QueryableStore`
over a second database connection. Those two had no consumer when Tier 4
landed; the ask-ai widget's serving endpoint, carried forward from that
tier and built after Tier 5, is the consumer — see the section on it
below. Every admin endpoint here is read-only except the
`/v1/admin/settings/*` saves, which are the human half of the
pre-fill-never-auto-apply rule — nothing on that surface applies a
suggestion by itself. The widget's serving endpoint is not an admin
endpoint at all, and is the one AI-assisted surface here that answers an
end user rather than an operator.

Tier 6 made the database a choice: this API runs on Postgres or on
SQLite, picked by exactly one of `DATABASE_URL` and `SQLITE_PATH`. A
SQLite deployment serves core auth and nothing else — the whole admin
console answers `501 not_implemented_on_sqlite`, because every table it
reads is Postgres-only. See that section below; the one-sentence version
is that a small deployment can now skip Postgres entirely, and skipping
it costs the console.

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
(`httpapi/ratelimit.go`). Since Tier 2 the engine-level one can be
Redis-backed via `REDIS_URL`, which is the shared-window option for a
deployment with more than one replica; the edge limiter above it is
still in-memory and single-process either way, the same caveat cryden's
own default limiter carries.

Response envelope, error codes, and the migration-copying convention
are all established — see `README.md` and `CLAUDE.md`.

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
cryden — see `CLAUDE.md`'s ownership section for why.

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

## Tier 1 — auth methods: DONE

Built on `feat/tier1-auth-methods` (its own branch, per `CLAUDE.md`'s
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
- **Apple** (`httpapi/apple.go`): the one provider that is not another
  switch case. Its client secret is an ES256 JWT signed per exchange
  with the console's `.p8` key, and its identity comes from the token
  response's `id_token`, verified against Apple's JWKS (issuer,
  audience, expiry, RS256) with the key set cached and refetched on an
  unknown `kid`. Authorization uses `response_mode=query` so the
  existing GET callback route is unchanged. All four `APPLE_*` values
  are required; a partial config reads as unavailable.
- **Error mapping** (`httpapi/errors.go`): every new engine error mapped
  once there — the eight per-method errors, the four "not configured"
  sentinels (`404`, matching `oauth_provider_not_configured`), and the
  Apple verification failure.
- **Two pre-existing bugs found in passing and fixed** (their own
  commit): `auth.ErrPasswordPolicyViolation` and
  `auth.ErrPasswordBreached` had no `mapError` case, so a signup or
  password change that broke the configured policy answered `500
  internal_error`; both are now `400`, with the policy error's broken
  rule codes reaching the client in an optional `details` array. The
  tracked env file was also renamed `.env.exampl` → `.env.example` to
  match what the README has always told you to copy.
- `httpapi/errors_test.go` and `httpapi/apple_test.go` — the first test
  files in this repo. The mapping/`writeErr` behaviour, the paused-login
  response shape, and Apple's signing plus id_token verification
  (accepted case and seven rejection cases, including an `alg: none`
  token) are covered; that is deliberately the largest slice verifiable
  without a database or Apple credentials.

**Verification gap, disclosed rather than glossed over:** `go build
./...`, `go vet ./...` and `go test ./...` are clean on this branch
(Go 1.25.0, cryden v2.5.0 from the local module cache), and `gofmt -l`
is empty. The DB-backed smoke test was **not** run — this sandbox has
no Postgres and no network — so the end-to-end paths are still owed a
first run against a real database before Tier 1 counts as verified the
way cryden's own features are. Two paths additionally cannot be
verified here at all: the WebAuthn ceremonies (need a real browser
authenticator) and Apple (needs real Apple credentials; what is tested
offline is the signing and the id_token verification, against a local
JWKS).

## Tier 2 — anomaly detection, named sessions, OAuth health: DONE

Built on `feat/tier2-config-and-oauth-health`. No engine bump this
tier, so no new migrations: `004`-`008` are still the complete set of
cryden copies.

- **Anomaly detection and credential-stuffing detection**
  (`ANOMALY_DETECTION` plus threshold env vars, wired in `main.go`
  through `postgres.NewAnomalyStore`): off unless switched on, and
  report-only in every case — a flagged attempt records an audit event,
  no login is blocked or delayed. Both threshold structs are copied
  from cryden's own `security.Default*` values and only then
  overridden, because cryden reads every field of a non-zero
  thresholds struct: a struct assembled from just the env vars that
  were set would silently switch off every check left out.
- **Redis-backed engine rate limiter** (`REDIS_URL`, with
  `RATE_LIMIT_ATTEMPTS` / `RATE_LIMIT_WINDOW_SECONDS`): the shared
  window cryden's own config comment points at for more than one
  replica. Unset, nothing changes — the in-process limiter is still the
  default. Those two bounds are restated as cryden's own 10/minute
  rather than left at zero, because with `REDIS_URL` set it is this
  repo that constructs the limiter and
  `security.NewRedisRateLimiter` rejects a zero bound.
- **Named sessions** (`GET /v1/sessions`): `label`, `device` and
  `location` per entry, computed on read by `cryden.ListNamedSessions`
  — no new table, no migration, no backfill. A documented breaking
  change rather than a silent field: `openapi/spec.yaml` is at 1.1 with
  the new fields and the README says the same in prose. Labels are
  device-only (`"Chrome on macOS"`) because no geolocator is wired, and
  `location` is present-but-empty as a result — deliberate, see
  `PROGRESS.md`.
- **`GET /v1/admin/oauth/health`** (`httpapi/oauth_health.go`): the
  first endpoint behind `RequireAdmin`, and so the first real exercise
  of Tier 0.5's gate. Per provider: configured or not, and
  `ok` / `degraded` / `unreachable` / `not_configured`. Probes are bare
  GETs with no OAuth parameters (a 4xx from an authorize endpoint is
  proof of life, not a failure), concurrent, 5s each, and skipped
  entirely for a provider this deployment has no credentials for.
- **`config/config_test.go`**, and the first endpoint-level tests
  (`httpapi/session_handlers_test.go`, `httpapi/oauth_health_test.go`):
  cryden's own in-memory stores make a real engine — and now a real
  router, `RequireAdmin` gate included — constructible with no Postgres,
  so these pin actual response shapes rather than only error mapping.
  `internal/smoketest`'s sessions check also stops accepting "200 with
  anything in it".

## Tier 3 — config plus real endpoints: DONE

The first tier that adds things cryden has no concept of. Built in two
stages on `feat/tier3-config-and-endpoints`; `go build`, `go vet`,
`gofmt -l` and `go test ./...` are clean, and `PROGRESS.md` records what
that does and does not cover.

**Config that lights up an engine feature** (cryden already implements
all of it; this repo supplies values):

- **Argon2id** (`PASSWORD_HASHER=argon2id` plus the five `ARGON2ID_*`
  knobs). `Argon2idParams` starts from `security.DefaultArgon2idParams`
  and each env var overrides only the field it names — cryden's
  `NewArgon2idHasher` uses a partially-filled struct as a real custom
  configuration rather than as "defaults plus overrides", so building
  one from only the vars that happened to be set would silently drop
  the rest to zero. Switching hasher is safe at any time and needs no
  migration: existing bcrypt hashes keep verifying and are rewritten one
  successful login at a time.
- **Cloud logging** (`CLOUD_LOGGING`, `LOG_LEVEL`,
  `CLOUD_LOG_REDACTION`, `CLOUD_LOG_HASH_KEY`) — see the shipped-events
  log below.
- **Email templates** (`EMAIL_TEMPLATE_DIR`, new `templates/` package):
  cryden deliberately owns no message copy, so this is entirely this
  repo's. `verification.txt` and `magic_link.txt` rendered with
  `text/template` (`{{.To}}`, `{{.Token}}`, `{{.URL}}`). Unset keeps the
  console senders' built-in lines byte for byte; a set-but-broken
  directory is a startup failure.
- **API keys** (`API_KEY_PREFIX`, `POST`/`GET /v1/api-keys`,
  `DELETE /v1/api-keys/{keyID}`, all `RequireAuth`): cryden scopes every
  one to the calling user by deriving the user ID from the verified
  token, so a key belonging to another account, a key that does not
  exist and an already-revoked key all answer the same `404
  api_key_not_found`. The raw key is returned once and never again —
  cryden stores only its SHA-256 hash. **No endpoint authenticates
  *with* an API key yet**; that is a separate change.

**Endpoints over this repo's own tables:**

- **`GET /v1/admin/security/hash-migration`** (`RequireAdmin`,
  read-only): `store.UserStore.Count` against two `CountByType` calls on
  `EventPasswordHashUpgraded` — all-time and windowed — so an operator
  can watch a bcrypt-to-Argon2id migration drain. `upgraded_events`
  counts events, not users, so the field that actually answers "is this
  draining" is `upgraded_events_in_window`, and `estimated_remaining` is
  named as an estimate on purpose.
- **Per-user metadata** (`usermeta/`, `migrations/009`): this repo's own
  table, because cryden's `store.User` deliberately has no metadata
  concept. Its purpose is JWT claim mapping — `main.go` sets
  `AccessTokenClaims` to `usermeta.ClaimsProvider(...)`, which merges
  the operator `role` with every stored key, so a metadata change lands
  on that user's next login or refresh and never retroactively. Admin
  `GET`/`PUT`/`DELETE /v1/admin/users/{userID}/metadata[/{key}]`, per key
  rather than whole-map so two operators cannot lose each other's work.
  Key validation and the reserved-claim rule live in the store, not the
  handler, so they hold for any writer. The prefix merge costs **two
  queries on every login and every refresh**.
- **Webhook delivery log** (`webhook/`, `migrations/010`): `WEBHOOK_URL`
  is the on/off switch. cryden calls `notify.WebhookSender` on the login
  request path, so `SendWebhook` writes one `pending` row and returns;
  a background worker makes the call. **The row is the queue** — a
  channel would lose everything on restart. Exponential backoff 30s
  doubling to 30m up to `WEBHOOK_MAX_ATTEMPTS`, then `failed` and left
  readable. The body is built at enqueue and stored, so a retry sends
  identical bytes and the log can answer "what did we send" for a retry
  as well as a first attempt. `GET /v1/admin/webhooks/deliveries`
  (admin, read-only, no retry button). `id` is a `BIGSERIAL` surrogate
  rather than the event id, which cryden may leave **empty**.
- **Shipped-events log** (`shiplog/`, `migrations/011`): this repo ships
  no vendor SDK, so "shipped" means recorded in `shipped_log_events`,
  read back by `GET /v1/admin/logging/recent`. `main.go` composes
  exactly the shape cryden's `logger` doc prescribes — redacting
  *inside* the `MultiLogger` fan-out, so stdout keeps the IP that makes
  an incident debuggable and only the copy leaving loses it. `level=`
  means "at or above", the same direction the `LevelFilter` reads.
  `LOG_LEVEL` (default `info`) keeps the volume sane.

The three new tables (`009`–`011`) have **never been applied to a real
database** — there is no Postgres in this sandbox. The webhook worker's
claim and backoff behaviour is tested against `httptest` and an
in-memory double, not against Postgres `FOR UPDATE SKIP LOCKED`, and
that double cannot reproduce two workers racing. `PROGRESS.md` says all
of this plainly.

## Tier 4 — AI-assisted admin endpoints: DONE

Built in two stages on `feat/tier4-ai-admin-endpoints`, for the same
reason Tier 3 was: the three read-only reports below had their decisions
already made in `NEXT.md`, while Stage 2 needed two decisions that are
not a build session's to make. Those two were resolved by following
`NEXT.md`'s own instruction to make the reasonable call and record it —
see Stage 2 below. `go build`, `go vet`, `gofmt -l` and `go test ./...`
are clean, `httpapi` and the two new packages are also green under
`-race`, and `PROGRESS.md` records what that does and does not cover,
which is a lot.

### Stage 1 — the three read-only reports

Everything here is `RequireAdmin`, read-only, and buildable on the
engine alone — no LLM, no second database connection, no outbound call:

- **`GET /v1/admin/digest`** and **`GET /v1/admin/digest/history`**.
  The engine's `cryden.DigestSince` renders a report over a window on
  demand; the history is this repo's own (`digest/`,
  `migrations/012_digest_runs`), written only by the scheduled job. The
  on-demand endpoint **records nothing**, so an operator hitting it
  twenty times does not fill the history with twenty near-identical
  reports. The engine has no scheduling concept at all, so the job, the
  table and the history endpoint are all entirely this repo's. The first
  run lands one full interval after startup rather than at boot, since a
  process that restarts more often than the interval elapses would
  otherwise write a row per restart. Unset `DIGEST_INTERVAL_HOURS` (or
  `0`) means no schedule, no goroutine and a `404 not_configured`
  history, while the on-demand endpoint keeps working.
- **`GET /v1/admin/support/diagnose?email=...`** →
  `cryden.DiagnoseLoginIssue`. An unknown address is an **answer**
  (`found: false`), not a `404`: "we have never seen this address" is
  what a support ticket needs to be told. It describes a locked account;
  it cannot unlock one.
- **`GET /v1/admin/config-tuning`** → `admin.BuildTuningReport` called
  **directly**, not `cryden.ConfigTuningReport`. The structured
  `TuningSuggestion{Area, Finding, Suggestion}` list is the point — a
  console renders one card per suggestion, and a pre-rendered text blob
  cannot be turned back into cards. The raw audit `counts` are returned
  alongside, so the evidence is visible rather than a sentence asking to
  be trusted. `window_days` defaults to cryden's own 30 days (wider than
  the digest's week on purpose — a config knob should be judged against
  a month of traffic) and is bounded rather than clamped. The route
  accepts **GET and nothing else**, which is the HTTP-level half of the
  pre-fill-never-auto-apply decision: there is no POST that takes a
  suggestion, and applying one means pre-filling a settings field a
  human saves through the ordinary settings path.

**One behaviour change came out of this tier, and it was not the point
of it.** The tuning report is asked to judge the audit history against
"the settings in force", and building it surfaced that this repo had
never passed `LockoutThreshold`/`LockoutDuration` to the engine — so
every deployment so far ran with both at Go's zero value, and cryden
defaults neither. A zero threshold locks an account on its first failed
password; a zero duration locks it until an instant already past, which
is to say not at all. `config` now owns both knobs (cryden's own 5 and
15 minutes by default), `main.go` passes them, and a threshold below 1
is a startup error rather than being read as "off", because cryden has
no way to switch lockout off. It is a real change to what every existing
deployment does on its next restart, so it is called out in `README.md`,
`.env.example` and its commit message rather than buried.

The digest's new table (`012`) has **never been applied to a real
database**, the same as `009`–`011` — there is no Postgres in this
sandbox. The digest schedule used to be a goroutine on
`context.Background()`; it now takes the context the shutdown signal
cancels, so the paragraph that follows in the Tier 6 section applies here
too. `PROGRESS.md` says both plainly.

### Stage 2 — the providers and the widget config

This is the half of the tier that needed an LLM, a second database
connection and an outbound call, so it is the half where this repo
stopped being purely a wrapper. Three settings endpoints, all
`RequireAdmin`, all in `httpapi/settings_handlers.go`, backed by
`settings/` and `migrations/013_settings`:

- **`GET`/`PUT`/`DELETE /v1/admin/settings/llm-provider`** stores which
  model and key back `ai.LLMProvider`. `DELETE` was added alongside the
  specced pair: a settings screen with no way to clear a credential is
  a screen an operator cannot leave.
- **`GET`/`PUT`/`DELETE /v1/admin/settings/database-provider`** stores
  the connection `ai.QueryableStore` runs against.
- **`GET`/`PUT`/`DELETE /v1/admin/settings/ask-ai-widget`** stores the
  widget's enabled flag, allowed origins, entity scope and copy.

Both credentials are sealed with **AES-256-GCM before they reach the
table**, keyed from a new `SETTINGS_ENCRYPTION_KEY`. That key is
deliberately *not* cryden's `ENCRYPTION_KEY`: the two seal different
things with different lifetimes and blast radii, and this repo already
sets the precedent with `CLOUD_LOG_HASH_KEY`. An unset key is not a
startup failure — the three endpoints answer `404 not_configured`, like
every other optional feature here. The encryption itself is cryden's
`security.NewAESGCMEncryptor` rather than a second implementation of the
same primitive; see `settings/secrets.go`.

Three things in this stage are worth reading before touching them:

- **`PUT /database-provider` proves the role cannot write, then stores.**
  Order is the whole design: validate the shape, connect with the
  supplied credentials and attempt a write, and only store once the
  server refuses. The probe targets `pg_temp`, so a failed probe leaves
  nothing behind, and the pool is pinned to one connection so the
  `CREATE` and the `INSERT` share the session owning that temp table.
  Three outcomes are distinguished — refused is a pass, succeeded is
  `400 database_role_not_read_only`, anything else is
  `400 database_role_unverified` and **is not a pass**. Only SQLSTATE
  `42501` counts as a refusal, matched by code rather than message.
- **`aiprovider.ScopedProvider` gives the widget's `entities` setting
  teeth.** cryden's `widget.Ask` force-scopes every parsed intent to the
  calling end user's own rows, overwriting whatever identity filter the
  model produced rather than validating it — no oracle — but it does so
  over all of `ai.AllowedEntities`. Narrowing that is a host decision, so
  this repo refuses an out-of-scope entity in front of the provider.
- **`settings.AskAIWidgetConfig` is not a credential**, and that is why
  it has no `Redacted` counterpart while the other two do. All three are
  stored through the same `Secrets` wrapper anyway — one storage path
  with one rule about what reaches the table is worth more than saving a
  decryption.

`aiprovider.NewAnthropic` is a real `ai.LLMProvider` over the official
Anthropic Go SDK, and `aiprovider.NewPostgresSnapshot` a real
`ai.QueryableStore`. **Nothing wired either from the stored config when
this stage landed** — Stage 2 stored the settings and enforced the scope
but had no caller, so the glue landed with its first one. That caller is
the widget's serving endpoint, built after Tier 5; see its own section
below. An earlier version of this paragraph also said `allowed_origins`
was consulted at no request time and that the widget GET carried no
embed snippet because the URL in one would name a route this repo does
not serve — both of those stopped being true at the same moment, and the
reason the snippet is still not returned is a different one.

What Stage 2 does **not** have evidence for, and `PROGRESS.md` says in
full: `CheckReadOnly` has never run against a real Postgres (the tested
branch is the *unverifiable* one, not the pass), the Anthropic provider
has never called Anthropic (it is tested against a local fake in the
Messages API's wire shape), and `013_settings` has never been applied to
a database.

**The read-only rule has a named exception, and this is the second one.**
The settings routes are writes, but they were not the admin surface's
first — Tier 3's `PUT`/`DELETE /v1/admin/users/{userID}/metadata/{key}`
have written since then, and Tier 5's `PUT /v1/admin/anomalies/{eventID}`
is a third. The reading
is that `CLAUDE.md`'s rule covers the AI *tools* — which cryden builds
through interfaces carrying no way to act — rather than every route
under `/v1/admin`, and that a settings save is exactly what `NEXT.md`'s
pre-fill-never-auto-apply decision names as the human half. No
AI-assisted handler holds a reference to these routes, and none accepts
a suggestion as input. The alternative readings (store the key in
cryden, or environment-only) are worse and one of them is explicitly
ruled out by `NEXT.md`, which says this repo owns that config storage.

## Tier 5 — the users admin surface

Built on `feat/tier5-users-admin-surface`. Four endpoints, one migration,
one new package. `NEXT.md`'s Tier 5 section carries the same account of
what was and was not done; this is the state rather than the log.

**The user surface** — `GET /v1/admin/users` and `GET
/v1/admin/users/{userID}`. This is the one place in the API where an
operator can see an account that is not their own, so what is absent is
as load-bearing as what is present: no lock, no unlock, no password
reset, no delete. cryden's store exposes `LockAccount`, and wiring it to
a button would make this repo the thing that can lock somebody out of
their account.

- The email search is **exact and case-sensitive**, and every response
  says which mode produced it (`match: "exact_email"` or `"browse"`).
  `q` goes to `cryden.GetUser`, which is `WHERE email = $1`; cryden
  stores addresses as typed and has no `citext`. Partial search was
  declined rather than deferred: a `LIKE` against cryden's `users` table
  would be a second, silent definition of what a user is. A search that
  finds nothing is an empty 200, never a 404.
- `locked` is **computed** from `LockedUntil` rather than mirrored from
  the column, because cryden clears a lockout by time passing rather
  than by writing a null — a non-nil `locked_until` in the past is the
  normal state of an account somebody just waited out.
- `active_sessions` is a count, not a list. `ListByUser` returns only
  live sessions so the count is honest; listing them would publish every
  IP and user agent to anyone holding an operator token.
- `PasswordHash` is on the struct these are built from and never on the
  wire. `TestAdminUserResponsesNeverCarryAPasswordHash` asserts that
  against the raw body and proves the assertion is not vacuous by
  confirming the stored user really does have a hash.

**The MFA adoption report** — `GET /v1/admin/security/mfa-adoption`,
alongside the hash-migration report it is modelled on. It reports
enrolment and removal **events**, all-time and windowed, against the
user total, and derives **no adoption percentage**. cryden cannot answer
"how many accounts have a factor enrolled": `TOTPStore` and
`WebAuthnCredentialStore` are per-user with no `Count` and no `ListAll`,
and counting the rows in `totp_secrets` would be SQL against the
engine's schema. Every field is named `*_events` so the number cannot be
read as a user count. Recovery codes are excluded — they are a fallback
for an account that already has a factor, not a factor of their own.

**The flagged-event review queue** — `GET /v1/admin/anomalies` and `PUT
/v1/admin/anomalies/{eventID}`, backed by the new `anomalyreview/`
package and migration `014_reviewed_anomalies`. Two decisions were
settled by the human before it was written:

- **Dismiss is a status, not a delete.** `status IN
  ('unreviewed','confirmed','dismissed')`, no DELETE anywhere.
  Withdrawing a judgement stores `unreviewed` rather than removing the
  row, so the record of who looked survives the change of mind.
- **The queue is keyed on the audit event id**, and the existence check
  is carried by a foreign key from `reviewed_anomalies.event_id` to
  `audit_events.id` — cryden has no lookup by event id, so Go cannot
  check it and the database does. SQLSTATE `23503` maps to
  `404 audit_event_not_found`, reusing the repo's existing
  SQLSTATE-by-code precedent from `aiprovider/query.go`.
- **Confirming takes no action on any account** — no lock, no revoke, no
  threshold change. There is no machinery here that acts, which is what
  keeps this inside `CLAUDE.md`'s rule rather than being an exception to
  it.
- The queue is the two `signals`-carrying types (`anomaly_detected`,
  `credential_stuffing_detected`); widening it to the failure events
  around them would make the audit table the queue.
- Paging over-fetches `limit + offset` per type and refuses beyond 500
  rather than clamping; `has_more` means "this page came back full, ask
  again" and not "there is more", because the fetches give a window per
  type rather than a total.

**The third write on the admin surface.** The review endpoint joins
Tier 3's metadata `PUT`/`DELETE` and Tier 4's settings routes. The
reading recorded in Tier 4's section — that the rule covers the AI
*tools* rather than every route under `/v1/admin` — is unchanged, and
this tier is the first place the reading had to do real work rather than
just explain a settings form: a review is a record of a human judgement,
and the endpoint is built so that it cannot become an action.

**What is still owed, said plainly.** Migration `014` has **never been
applied to a database**, and `anomalyreview.PostgresStore` has never run
against a real Postgres — no Docker or Postgres was reachable in the
environment this was built in, the same constraint Tier 4's Stage 2
recorded for `013_settings`. The foreign key and its `23503` mapping are
verified by reasoning and by the in-memory double, which reproduces the
foreign key rather than accepting any id, so that the tested branch is
the one production runs. `-race` was not run this session.

**Still not built** (unchanged from Tier 4, not part of this tier):
per-user rate limiting on anything that calls a model. Graceful shutdown
was on this list and is not any more — see the last section of this file.
The widget's own serving endpoint was in this list when Tier 5 landed and
is not any more — see the next section.

## The ask-ai widget's serving endpoint — carried forward from Tier 4

Built on `feat/ask-ai-widget-serving`, after Tier 5 rather than with it.
`NEXT.md`'s Tier 4 carry-forward note asked for this to be picked up
"before or alongside Tier 6/7"; this is that, and it is the piece Tier 4
Stage 2 deliberately left to its first caller rather than writing blind.

Two new files and two small edits. `askai/` owns the glue — turning the
settings table into a live `ai.LLMProvider`/`ai.QueryableStore` pair —
and `httpapi/widget_handlers.go` owns the route. `POST /v1/ask-ai` is
registered with **`RequireAuth`, not `RequireAdmin`**, which is the
single most important thing about it.

- **It is not an admin endpoint, and that is the feature.** cryden's
  `widget` package exists for "a host application's own end users", and
  `widget.Ask` takes an `ownerUserID` that the host must supply from its
  own authentication. The widget answers questions about the signed-in
  user's own sessions and audit events. Putting it behind `RequireAdmin`
  would have been the easy mistake — every other AI surface here is
  admin-only — and it would have made the widget unusable for every
  person it is for. This was checked against three independent sources
  before the route was written: cryden's `widget/ask.go` package doc and
  `ownerUserID` contract, `README.md`'s own account of the widget, and
  `settings/widget.go`'s note that `"*"` is refused because the widget
  answers questions about the signed-in user. `NEXT.md` Tier 4's heading
  — "AI-assisted admin endpoints (all behind `RequireAdmin`)" — is true
  of the *settings* routes and was already misleading as a description
  of this one, which Tier 4 listed but never built.
- **The owner id comes from the verified token and from nowhere else.**
  The request body has no field that can name a user; one sent anyway is
  ignored rather than rejected, because there is nothing for it to
  reach. Two things hold that independently: `widget.Ask` discards the
  model's identity filter and substitutes the real one, and the id
  itself is read from the request context by `RequireAuth` rather than
  from anything in the request. `TestAskAIScopesToTheTokenNotTheBody`
  pins it end to end by sending a body that names another user and
  asserting the `user_id` filter that reached the query surface was the
  caller's.
- **`Composer` is nil, deliberately.** cryden documents a nil Composer
  as "a valid, strictly safer default" and falls back to `RenderResult`,
  a deterministic plain-text table. Supplying one means a second model
  call per question whose output nothing validates, to turn a table into
  prose. That is a decision to make on purpose if it is ever wanted, not
  one to fall into by omission.
- **`allowed_origins` is finally consulted, and it is defense in depth
  rather than the boundary.** The Bearer token is the boundary and is
  verified first. A request carrying *no* `Origin` is allowed, on
  purpose: refusing it would break every non-browser client — the
  console itself, a mobile app, a test — while stopping nobody, because
  a caller who can forge an allowlisted origin can equally omit it. What
  the check buys is a guard against a stray embed on a site nobody meant
  to authorise.
- **A real bug the tests caught, worth recording.** The first
  `canonicalOrigin` used `url.Parse(...).Hostname()`, which ignores the
  path — so `https://console.example.com/widget` canonicalised to the
  same key as the allowed origin and was accepted. Fixed by refusing a
  path, query, fragment or userinfo outright and requiring the scheme be
  `http`/`https`, which mirrors `settings.validateWidgetOrigin`. The two
  sides of one rule have to agree; a comparison that silently ignored a
  path would accept a value the operator could never have stored.
  Default ports are normalised away on both sides, because browsers omit
  `:443` and an operator who typed it would otherwise have configured an
  entry that could never match.
- **Settings are read per question; the built provider pair is cached on
  a content fingerprint.** Three short reads and two AES-GCM opens
  against one model call is a lopsided trade, and the failure mode of
  the other side is a saved change that does not take effect until a
  restart. The fingerprint is a **SHA-256 digest**, not the settings
  themselves, because two of its three inputs are credentials and a
  cache key lives as long as the process does. Rebuilds are cheap by
  design — `NewPostgresSnapshot` uses `sql.Open`, which does not connect
  — so a stored connection that has gone bad is reported by the query
  that uses it rather than at startup.
- **The `Providers` seam is exported on purpose.** `askai.New` builds
  the real Anthropic provider and Postgres snapshot; `NewWithProviders`
  takes a factory. It exists because the security properties worth
  testing — owner scoping, entity scoping, rebuild-on-change — cannot be
  observed without a database otherwise, and the httpapi tests use it to
  see the intent that actually reached the query surface. It is also the
  hook a host running a different LLM backend needs, which is why it is
  exported rather than a test-only accessor.
- **`Service.Close()` is called by the teardown in `main.go`.** It
  releases the last cached provider pool, after the server has drained
  and the background workers have stopped, so no question can be in
  flight against a provider that is being closed.

**What is still owed, said plainly.** No per-user rate limiting on this
route: it spends money per question and is bounded only by the global
per-IP edge limiter. That needs policy — per-user or per-deployment, and
what number — which is a deployment's call rather than something to
invent here. The Anthropic provider still has never called Anthropic, so
the live path from a question to a real model is exercised only through
the `Providers` seam with doubles; the wire shape is covered by
`aiprovider`'s own tests against a local fake.

## Tier 6 — SQLite backend, core auth only

Built on `feat/tier6-sqlite-backend`. This repo runs on Postgres or on
SQLite, chosen by exactly one variable. The scope decision was made in
advance rather than here — `NEXT.md`'s Tier 6 section carries it — and
this is the resulting state.

**The switch.** `DATABASE_URL` or `SQLITE_PATH`, mutually exclusive,
with `config.Load` refusing both or neither as a startup error.
`Config.UsesSQLite()` is the single expression of the rule; `main.go`'s
`openStores` returns one `stores` struct built from cryden's
`store/postgres` or `store/sqlite` constructors, and nothing downstream
of it knows which ran. The ten engine stores (`Users`, `Sessions`,
`Audit`, `Verifications`, `OAuth`, `TOTP`, `WebAuthn`, `RecoveryCodes`,
`APIKeys`, `Anomalies`) exist in both cryden packages, so this is wiring
rather than engine work — the one asymmetry is this repo's own three
Postgres-only stores, which are nil on SQLite.

**The whole admin console answers `501 not_implemented_on_sqlite`**, and
that is one decision in one place rather than a list of routes:
`httpapi.AdminOnly` is `RequireAdmin` on Postgres and a flat 501 on
SQLite, and all 25 admin registrations go through the value it returns.
The reason it is a 501 and not the 403 the existing gate would have
produced is the part worth keeping: `RequireAdmin` depends on the
`operators` table, so a SQLite deployment has no operators, so *every*
caller — including a legitimate operator — would have been told
`403 not_operator`. That reads as "you personally lack access" when the
truth is "this backend has no console". 501 is a statement about the
deployment, which is what this is.

- The console's tables (`operators`, `user_metadata`,
  `webhook_deliveries`, `shipped_log_events`, `digest_runs`, `settings`,
  `reviewed_anomalies`) remain Postgres-only, by the scope decision.
  Nothing was built twice.
- **`POST /v1/ask-ai` is not under `/v1/admin` and is still unavailable
  on SQLite** — the provider it reads lives in the `settings` table. It
  answers `404 not_configured`, the same shape it gives on a Postgres
  deployment with no provider stored, so a client never has to know
  which backend it is talking to. One rule: the AI-assisted surface
  needs `DATABASE_URL`.
- **The `AccessTokenClaims` provider is skipped entirely on SQLite.**
  This is not an optimisation. `usermeta.ClaimsProvider` dereferences
  its metadata store on every login, and a nil `*usermeta.PostgresStore`
  passed through the interface is a non-nil interface holding a nil
  pointer — it would pass its own nil check and panic on the first
  query, on every login and every refresh. `claimsProvider` returns nil
  for the SQLite case, which is the correct answer rather than a
  workaround: cryden treats a nil provider as "this host attaches no
  extra claims", and on SQLite there is nothing to attach. The
  consequence is the same fact as the 501 seen from the other end — a
  SQLite deployment issues tokens no admin route would accept anyway.
- **Nothing is inert silently.** `SETTINGS_ENCRYPTION_KEY`,
  `WEBHOOK_URL`, `CLOUD_LOGGING` and `DIGEST_INTERVAL_HOURS` are named
  in a startup warning when set on SQLite. `ENCRYPTION_KEY` gets its own
  positive log line precisely so it cannot be misread as part of that
  list: second factors are cryden's own tables and work on both
  backends.

**Migrations on SQLite are cryden's, not this repo's.** This is the
discovery that shaped the tier: cryden ships `sqlite.Migrate`, which
embeds its own `migrations/*.sql` and records what it applied in
`cryden_schema_migrations`, so `main.go` calls that at startup and there
is no migrate step for an operator on this backend. The copy under
`migrations/sqlite/` — cryden's `0001`–`0007`, verbatim, cryden's
filenames kept rather than renumbered into this repo's `001`–`014`
Postgres sequence — is therefore **reference material, not what runs**.
The mirror image of Postgres, where this repo's copies are exactly what
an operator pipes through `psql`. `migrations/sqlite/README.md` says so
at the point of use. Three DSN pragmas are load-bearing:
`foreign_keys(1)`, `busy_timeout(5000)` and `journal_mode(WAL)`; the
server checks the first two on every boot with cryden's own
`CheckPragmas` and refuses to start if the DSN and the driver have
drifted apart.

**What is still owed, said plainly.** The Postgres path is **not**
newly verified: `openStores`'s Postgres arm is asserted to construct
every store, but no Postgres was reachable in this environment, so
migrations `001`–`014` still have never been applied to a real database
and `anomalyreview.PostgresStore` still has never run — the same
constraint Tiers 4 and 5 recorded. The SQLite path, by contrast, is
verified end to end: cryden's own `store/sqlite` suite passes (run as
the spec asked, as reference for the pragmas and type mappings), and
this repo's server was started on a real SQLite file and passed the full
`internal/smoketest` run — health, signup, duplicate rejection, login,
wrong password, verify, session list, missing-header rejection, refresh
rotation, reuse detection, family revocation, and both OAuth refusals.
`-race` was still not run. Graceful shutdown was not built by this tier,
and on SQLite it had a second reason to exist: with no `Close()` there is
no checkpoint on exit, so a fresh deployment's entire schema could sit in
the `-wal` file — durable, but a backup that copies `api.db` alone can
silently produce an empty database. `README.md` warns about that where an
operator will see it. That gap is now closed — see the last section of
this file — but the warning stays, because a `kill -9` still leaves the
WAL uncheckpointed and the advice to copy all three files is still the
right advice. Per-user rate limiting on `POST /v1/ask-ai` is
unchanged.


## Graceful shutdown — the finding Tier 3 opened and Tier 6 sharpened

This is not a tier. It is the one item that appeared as owed in three
separate tier write-ups (Tiers 3, 5 and 6), so it is recorded once, here,
and the three write-ups now point at it instead of restating it.

**What it was.** `main.go` ended at
`log.Fatal(http.ListenAndServe(...))`. That single line meant three
things, and only the first was obvious:

1. **No signal handling.** A `SIGTERM` — which is what every process
   manager sends, including `docker stop` and a Kubernetes rolling
   deploy — killed the process where it stood. Every request in flight
   died with it.
2. **`os.Exit` runs no defers.** `log.Fatalf` calls `os.Exit(1)`, so the
   `defer db.Close()` two lines above it had never run once in this
   repo's life. Every clean shutdown leaked the pool.
3. **On SQLite, no close means no checkpoint.** The `-wal` file is
   durable — SQLite recovers from it — but the schema and every row a
   deployment had written lived only there. After two boots of the
   smoke run, `api.db` was still 4096 bytes while `api.db-wal` held
   461KB. A backup that copied `api.db` alone produced an empty
   database that opened without error.

Only the third is visible from outside, and it is the one that would
have cost somebody data.

**What it is now.** `signal.NotifyContext` on `SIGINT`/`SIGTERM` produces
one `appCtx` that everything hangs off. `net.Listen` is separated from
`srv.Serve` so a listen failure is an error to report rather than a
`Fatal` that skips teardown. The main goroutine selects on either
`Serve` returning on its own or the signal; on the signal it calls
`drain`, which is `srv.Shutdown` bounded by `shutdownDrainTimeout`
(30s, a constant in `shutdown.go` with its own reasoning) and falls back
to `srv.Close` when the bound is hit. Only then does teardown run, in
the order the components need: `stopSignals()`, `workers.Wait()` for the
webhook worker and the digest scheduler, then `askAI.Close()`,
`redisClient.Close()`, and `db.Close()` last — that last one being the
WAL checkpoint.

**The three properties `shutdown_test.go` pins**, because they are the
whole reason `drain` is a function instead of three lines in `main`:

- A request already in flight still gets its 200 after the signal
  arrives, and the drain does not return before it finishes. The test
  waits for the handler to actually be running rather than sleeping, so
  it is not racing the client.
- A request that will not finish does not hold the process open. The
  bound is honored and the error names the wait, because the operator
  reading it is looking at a deploy that took too long.
- A listener that fails on its own reports that error rather than
  having it translated into a clean shutdown by the
  `http.ErrServerClosed` check.

**Verified end to end, not just by unit test.** The binary was built,
started on a fresh `/tmp/walcheck.db`, driven through the full
`internal/smoketest` run (13/13), sent a real `SIGTERM`, and then the
database was opened **read-only with no sidecar files present**: 7
migrations recorded, 1 user, 2 sessions, all read back out of the
single `.db` file. Before the change the same sequence left 4096 bytes
and a 461KB `-wal`.

**What this does not do.** It does not make `shiplog`'s writes
asynchronous — the comment there has been updated from "there is no
shutdown path to hang off" to "the buffer and the flush policy are the
missing pieces, not the lifecycle", which is a different and smaller
problem. It does not add a readiness endpoint separate from `/v1/health`,
so a load balancer's behavior during the drain is unchanged. And
`shutdownDrainTimeout` is a constant rather than an env var on purpose:
if the ask-ai widget's model calls ever stop being bounded by the
provider's own client timeout, that becomes a knob.
