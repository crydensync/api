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
over a second database connection, neither of which is wired to a
consumer yet. Every admin endpoint here is read-only except the
`/v1/admin/settings/*` saves, which are the human half of the
pre-fill-never-auto-apply rule — nothing on that surface applies a
suggestion by itself.

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
sandbox — and the digest schedule is a goroutine on
`context.Background()`, because this repo still has no graceful
shutdown. `PROGRESS.md` says both plainly.

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
`ai.QueryableStore`. **Nothing wires either from the stored config yet**:
the only consumer would be a widget serving endpoint, which does not
exist, so that glue lands with its first caller rather than being
written blind. `allowed_origins` is stored and validated but nothing
consults it at request time for the same reason, and the widget GET
carries no embed snippet because the URL in one would name a route this
repo does not serve.

What Stage 2 does **not** have evidence for, and `PROGRESS.md` says in
full: `CheckReadOnly` has never run against a real Postgres (the tested
branch is the *unverifiable* one, not the pass), the Anthropic provider
has never called Anthropic (it is tested against a local fake in the
Messages API's wire shape), and `013_settings` has never been applied to
a database.

**The read-only rule now has a named exception, and it is this one.**
`/v1/admin/settings/*` is the admin surface's first write. The reading
is that `CLAUDE.md`'s rule covers the AI *tools* — which cryden builds
through interfaces carrying no way to act — rather than every route
under `/v1/admin`, and that a settings save is exactly what `NEXT.md`'s
pre-fill-never-auto-apply decision names as the human half. No
AI-assisted handler holds a reference to these routes, and none accepts
a suggestion as input. The alternative readings (store the key in
cryden, or environment-only) are worse and one of them is explicitly
ruled out by `NEXT.md`, which says this repo owns that config storage.

## Tier 5

Not started. See `NEXT.md` for the full, ordered, specced-in-detail
queue — the users admin surface, which has no engine gap and is just
missing endpoints, plus the widget's own serving endpoint, which is what
the Stage 2 config above is waiting for.

