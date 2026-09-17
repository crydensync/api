# api — next up

Ordered queue. Take the first unfinished item, build it completely,
verify it (see `CLAUDE.md`), update the three docs
(`CURRENT-STATE.md`/`NEXT.md`/`PROGRESS.md`), then stop for review
before starting the next tier. Specs below are deliberately detailed
so you don't need to ask anything mid-build — where something is
genuinely unspecified, make the most reasonable call consistent with
`CLAUDE.md`'s ownership rules and note the assumption in `PROGRESS.md`.

Tier 0 and Tier 0.5 are done — see `CURRENT-STATE.md`.
Tier 1 is done — see the status note under Tier 1 and `PROGRESS.md`'s
2026-09-14 entries for how far it is verified.
Tier 2 is done — see the status note under Tier 2 and `PROGRESS.md`'s
2026-09-15 entry. No engine bump this tier, so there were no new cryden
migrations to copy.
Tier 3 is done, in two stages on `feat/tier3-config-and-endpoints` — see
the status note under Tier 3 and `PROGRESS.md`'s 2026-09-15 entries.
Tier 4 is **in progress** on `feat/tier4-ai-admin-endpoints`: Stage 1
(digest + scheduling + history, support diagnosis, config tuning
advisor) is built — see the status note under Tier 4. Stage 2 (the LLM
and database providers, and the ask-AI widget config) is not started.

---

## Tier 1 — auth methods

> **Status: every sub-item below is built, Apple included, on
> `feat/tier1-auth-methods`.** `go build`/`go vet`/`go test` are clean
> and the new mapping/`writeErr` behaviour is unit-tested, including
> Apple's client-secret signing and its id_token verification
> (signature, audience, issuer, expiry, algorithm) against a local JWKS.
> What is still owed: a first DB-backed smoke-test run (no Postgres in
> this sandbox), a live Apple round trip (no Apple credentials here), and
> the WebAuthn ceremonies, which need a real browser authenticator.
> `PROGRESS.md` says all of that plainly, per `CLAUDE.md`'s verification
> rule, rather than counting green unit tests as end-to-end coverage.

Each of these mirrors an existing engine feature that already has a
full smoke-test-verified implementation in cryden. The work here is
almost entirely translation: engine call in, HTTP request/response
shape out, matching this repo's existing envelope and error-mapping
conventions.

**Before any of it:** copy cryden's Postgres migrations `0003`
through `0007` into this repo's `migrations/`, renumbered to continue
this repo's own sequence (`004` through `008` — `003` is already
`operators`). Same "kept here so this repo is self-contained" reasoning
as the existing `001`/`002` copies. Check cryden's own
`store/postgres/migrations/` for the exact source content; don't
reconstruct from memory.

`004`-`008` are copied; the TOTP/passkey/recovery-code endpoints,
the two magic-link endpoints, the shared paused-login response and the
three mechanical OAuth providers are built. Notes worth keeping:

- TOTP, WebAuthn and recovery codes are gated on `ENCRYPTION_KEY` in
  `main.go` (cryden refuses to build an engine with either store set and
  no key). Unconfigured means `404` per request, not a refusal to start.
- A login that pauses for a second factor had to become a `200`
  (`second_factor_required` + `pending_token` + `methods`) — repo-wide
  that is the shape `/v1/login`, the OAuth callback and
  `/v1/magic-link/complete` all use now. This was not spelled out in the
  original spec below; it is the one place the spec's "translation only"
  framing needed a real decision, and it is recorded in `PROGRESS.md`.
- The code-for-token exchange moved to a POST form body (RFC 6749
  §4.1.3) because Microsoft and Discord require it; Google and GitHub
  accept it, so there is one path rather than a per-provider branch.

### TOTP
- `POST /v1/totp/enroll` (auth required) → `cryden.EnrollTOTP`, return
  the `otpauth://` URL for the client to render as a QR code.
- `POST /v1/totp/confirm` (auth required) → `cryden.ConfirmTOTP`, body
  `{ "code": "..." }`.
- `POST /v1/totp/disable` (auth required) → `cryden.DisableTOTP`, body
  `{ "password": "..." }`.
- `POST /v1/login/totp` (no auth — this completes a paused login) →
  `cryden.CompleteLoginWithTOTP`, body
  `{ "pending_token": "...", "code": "..." }`.

### WebAuthn / passkeys
- `POST /v1/passkeys/register/begin` (auth required) →
  `cryden.BeginRegisterPasskey`, return the ceremony options JSON and
  a ceremony token.
- `POST /v1/passkeys/register/finish` (auth required) →
  `cryden.FinishRegisterPasskey`, body includes the ceremony token, the
  client's response JSON, and an optional nickname.
- `GET /v1/passkeys` (auth required) → `cryden.ListPasskeys`.
- `DELETE /v1/passkeys/{credentialID}` (auth required, password
  re-confirmation in body) → `cryden.DeletePasskey`.
- `POST /v1/login/passkey/begin` (no auth) →
  `cryden.BeginWebAuthnLogin`, takes the pending token from the
  second-factor-required response.
- `POST /v1/login/passkey/finish` (no auth) →
  `cryden.CompleteLoginWithWebAuthn`.

### Magic link
- `POST /v1/magic-link/request` → `cryden.RequestMagicLink`. Same
  enumeration-safety property as the engine: always `200`/`{"data":{}}`
  regardless of whether the email exists.
- `POST /v1/magic-link/complete` → `cryden.CompleteMagicLink`.
- Needs a `notify.MagicLinkSender` implementation wired into `Config`
  alongside the existing `consoleEmailSender` — a separate interface
  from `EmailSender` on cryden's side, so this is a new small type in
  `email_sender.go`, not a change to the existing one.

### Recovery codes
- `POST /v1/recovery-codes/generate` (auth required) →
  `cryden.GenerateRecoveryCodes`. Response should make clear to the
  client this is the only time the raw codes are shown.
- `POST /v1/login/recovery-code` (no auth) →
  `cryden.CompleteLoginWithRecoveryCode`.

### More OAuth providers
Router and handler pattern already support this without a route
change — extend the provider switch in `httpapi/oauth_handlers.go` and
`config/config.go`'s env var loading, following the exact pattern
Google/GitHub already use.

- **Microsoft, Discord, GitLab**: same OAuth2 authorization-code shape
  as Google/GitHub, just different authorize/token/userinfo URLs and
  response field names. Mechanical.
- **Apple**: genuinely different, not mechanical. Apple's client
  "secret" is a JWT you generate yourself, signed with a private key
  from Apple's developer console, short-lived and needs regenerating
  periodically — not a static string like every other provider. The
  user's email comes back inside a signed `id_token` JWT from the
  token endpoint, not from a separate userinfo call, and Apple only
  sends the user's name on the *first* authorization ever, never
  again. Budget real time for this one; don't estimate it at the same
  size as the other three.

**Apple: done** (its own commit, `httpapi/apple.go` + `apple_test.go`).
It needed exactly what was foreseen here: an ES256 client-secret JWT
signed per exchange with the console key, and the identity read from the
token response's `id_token` after verifying it against Apple's JWKS.
Two details were decided rather than assumed, and are recorded in
`PROGRESS.md`:

- `response_mode=query` so the existing GET callback route works
  unchanged. The consequence is that Apple's one-time `user` payload
  (name, first authorization only) is not captured — this repo stores the
  id_token's email, not names.
- No `nonce` parameter. Apple requires one for the hybrid/implicit flow;
  this is the authorization-code flow, where the code is single-use and
  bound to this client and the redirect already carries a CSRF `state`
  cookie. Worth revisiting only if a hybrid flow is ever added.

---

## Tier 2 — mostly config, one endpoint

> **Status: all three sub-items built on
> `feat/tier2-config-and-oauth-health`.** `go build`/`go vet`/`go test`
> are clean and `gofmt -l` is empty, and this tier's tests are the first
> in this repo that exercise endpoints rather than only error mapping:
> cryden ships its own in-memory stores, so a real engine — and now a
> real router — can be built with no Postgres at all. Everything still
> owed is unchanged from Tier 1 and repo-wide: the first DB-backed
> smoke-test run, the WebAuthn ceremonies (need a real authenticator)
> and a live Apple round trip (needs Apple credentials).

- **Anomaly detection, credential-stuffing detection, Redis rate
  limiter**: `Config.Anomalies`, `Config.AnomalyThresholds`,
  `Config.CredentialStuffingThresholds`, `Config.RateLimiter` — wire
  from env vars in `config/config.go`, following the existing pattern
  for optional engine config. No new routes; these are transparent to
  every existing auth endpoint.

  **Done.** `ANOMALY_DETECTION` switches both detections on (one switch,
  because they share one store as their on/off switch), the threshold
  knobs and `REDIS_URL` / `RATE_LIMIT_ATTEMPTS` /
  `RATE_LIMIT_WINDOW_SECONDS` sit alongside them, and `main.go` wires the
  store, the thresholds and the limiter. Two decisions worth reading the
  code comments for: the thresholds start as the engine's own
  `security.Default*` values and only then take overrides (cryden reads
  every field of a non-zero thresholds struct, so a partial struct is not
  partly-defaulted — it is partly-disabled), and the two rate-limit
  bounds are restated as 10/minute rather than left at zero because with
  `REDIS_URL` set it is this repo that constructs the limiter, and
  `security.NewRedisRateLimiter` rejects a zero bound.
- **Named sessions**: change `GET /v1/sessions`'s response shape to
  use `cryden.ListNamedSessions` instead of the current session list,
  so each entry includes its `Label` (e.g. `"Chrome on macOS, San
  Francisco, CA"`). This is a breaking response-shape change for
  existing consumers — bump the response, don't silently add a field
  if the existing shape is documented in `openapi/spec.yaml` as fixed;
  check there first.

  **Done**, as a documented change rather than a silent addition: the
  four existing fields keep their names and types, `label`, `device` and
  `location` are new, `openapi/spec.yaml` goes to 1.1 with the schema and
  path description saying so, and the README says the same in prose. The
  spec was *not* marked fixed or additive-only, so "bump" here meant
  documenting the break in both places, which is what the version bump
  signals.

  The label is device-only — `"Chrome on macOS"` — because no geolocator
  is wired. That is a decision, not an omission: it is
  `Config.Geolocator`, and cryden deliberately ships no implementation
  because every implementation calls somebody else's internet service.
  `location` is present-but-empty as a result, and `label` is never empty
  either way. See `PROGRESS.md` for the full reasoning.
- **OAuth provider health check** (new, for the console): `GET
  /v1/admin/oauth/health` (behind `RequireAdmin`) — for each configured
  provider, a lightweight reachability check against its authorize
  endpoint (HEAD or a cheap GET, not a real OAuth flow), returning
  per-provider status. This is entirely this repo's own logic; cryden
  has no concept of provider health.

  **Done**, and it is the first endpoint in this repo behind
  `RequireAdmin` — so it is also the first real exercise of Tier 0.5's
  gate, which its tests now cover through the actual router. A cheap GET,
  no OAuth parameters, concurrent with a 5s timeout each. Four verdicts
  rather than a bool: `ok` (answered below 500 — a bare GET legitimately
  gets a 4xx from an authorize endpoint, which still proves it is up),
  `degraded` (5xx), `unreachable` (no response, with the transport
  error), `not_configured` (no credentials, nothing probed).

---

## Tier 3 — config plus real endpoints

> **Status: every sub-item below is built, in two stages on
> `feat/tier3-config-and-endpoints`.** Stage 1: Argon2id, cloud-logger
> and email-template config, API keys, hash-migration. Stage 2:
> `user_metadata` with JWT claim mapping, webhooks with a delivery log
> and background worker, cloud-logging shipped-events log. `go build`,
> `go vet`, `gofmt -l` and `go test ./...` are all clean on this branch.
> What is still owed, and said plainly rather than implied: the
> migrations `009`–`011` have **never been applied to a real database**
> (no Postgres in this sandbox), the webhook worker's claim and backoff
> behaviour is tested against `httptest` and an in-memory double
> **rather than against Postgres `FOR UPDATE SKIP LOCKED`**, the
> in-memory double cannot reproduce two workers racing (one mutex), and
> this repo still has **no graceful shutdown** — owed before the
> shipped-events sink could move off the request goroutine. `PROGRESS.md`
> has all of it.
>
> Two deliberate deviations from the spec below, both argued in
> `PROGRESS.md`: `webhook_deliveries` uses a `BIGSERIAL` surrogate
> primary key rather than the event id (which cryden may leave **empty**,
> by design, when its `crypto/rand` generator fails), and the shipped
> copy is recorded in this repo's own table rather than sent to a vendor,
> because this repo ships no vendor SDK.

- **Argon2id, cloud loggers, custom email templates**: config only.
  Custom email templates specifically need **no engine change at
  all** — cryden deliberately has no template config (there's a test
  in cryden pinning that `Config` can never grow email-template
  knobs), templates are entirely owned by whatever implements
  `EmailSender`/`MagicLinkSender` here. If the console wants
  admin-editable templates, that's a new table in this repo storing
  template content per purpose, read by this repo's own sender
  implementations.
- **Argon2id migration progress** (new): `GET
  /v1/admin/security/hash-migration` (behind `RequireAdmin`) —
  computable via `AuditStore.SearchByType`/count against
  `EventPasswordHashUpgraded` versus total user count. No new cryden
  call needed, cryden already emits that event.
- **JWT claims**: needs a new **per-user metadata table**, owned by
  this repo (`user_metadata` or similar — `user_id`, arbitrary
  key/value or JSON blob, whatever shape the console's claim-mapping
  UI needs). This is what the csax+ prototype's `user.metadata.field`
  references; cryden's `store.User` has no such field and won't gain
  one. Wire a `token.ClaimsFunc` that reads this table the same way
  `operator.Store`'s claims wiring already does, extended to include
  both role and mapped metadata fields in one claims provider.
- **API keys**: `POST /v1/api-keys` → `cryden.GenerateAPIKey`,
  `GET /v1/api-keys` → `cryden.ListAPIKeys`,
  `DELETE /v1/api-keys/{keyID}` → `cryden.RevokeAPIKey`. All auth
  required, all scoped to the calling user, same ownership-check
  pattern as sessions.
- **Webhooks**: `Config.Webhooks`/`Config.WebhookEvents` from env
  config, plus a **delivery log** (new, this repo's own table) —
  cryden's `notify.WebhookSender` is called synchronously and cryden
  itself keeps no history, so this repo's `WebhookSender`
  implementation should record each attempt (event ID, status,
  timestamp, response code) to its own table, and expose `GET
  /v1/admin/webhooks/deliveries` (behind `RequireAdmin`) to read it
  back. Retry, if built, is this repo's own logic on top of that log.
- **Cloud logging shipped-events log** (new): same shape as the
  webhook delivery log — this repo's `logger.Logger` implementation
  records what it actually shipped to the vendor, own table, own
  `GET /v1/admin/logging/recent` endpoint.

---

## Tier 4 — AI-assisted admin endpoints (all behind `RequireAdmin`)

> **Status: Stage 1 and Stage 2 are both built on
> `feat/tier4-ai-admin-endpoints`.** The weekly digest and its schedule
> and history, the support-ticket assistant, the config tuning advisor,
> the LLM provider config, the read-only database provider config and the
> ask-ai widget config all exist, are wired in `main.go`, and are tested
> end to end on the in-memory stores — `go build`/`go vet`/`go test ./...`
> clean, `httpapi` also green under `-race`.
>
> What is still owed, said plainly, because none of it is a small
> caveat:
>
> - **No migration in this tier has ever been applied to a database.**
>   There is still no Postgres in this sandbox, so `012_digest_runs` and
>   `013_settings` have only been reasoned about, not run — the same is
>   true of `009`–`011`. Every `PostgresStore` added here is unexercised.
> - **`aiprovider.CheckReadOnly` has never run against a real Postgres.**
>   The probe is a `CREATE TEMP TABLE` plus an `INSERT`, and the branch
>   that matters — SQLSTATE 42501 arriving as a `*pq.Error` — has only
>   been tested against a closed port, which is the *unverifiable*
>   outcome rather than the pass. The accepting path is the one no test
>   here covers.
> - **The Anthropic provider has never called Anthropic.** It is tested
>   against a local `httptest` server in the Messages API's wire shape,
>   which pins the request this repo builds and the response it parses,
>   but it is not evidence that the live service agrees.
> - **The ask-ai widget has no serving endpoint.** Stage 2 stores its
>   embed and scope configuration and enforces the scope in
>   `aiprovider.ScopedProvider`; nothing yet calls `widget.Ask`. So
>   `allowed_origins` is recorded and validated but nothing consults it
>   at request time, and the GET response deliberately carries no embed
>   snippet, because the URL in one would name a route this repo does
>   not serve.
>
> What is still owed from Stage 1:
>
> - the digest schedule is a goroutine on `context.Background()`, because
>   this repo still has no graceful shutdown.
>
> Three things this tier changed that were not in the spec below, all
> recorded because they are behaviour rather than plumbing:
>
> - **`LOCKOUT_THRESHOLD`/`LOCKOUT_DURATION_MINUTES` are now passed to
>   the engine.** cryden does not default these — it reads whatever it
>   is handed, and `0`/`0` means an account is locked on its first
>   failed password until an instant already past, which is to say
>   never. Until this tier the engine ran with both at zero. So this is
>   a real behaviour change, not a tidy-up, and it is why the tuning
>   report can quote the lockout settings in force rather than cryden's
>   documented defaults.
> - **`GET /v1/admin/digest` records nothing.** The spec puts scheduling
>   and history in this repo, and that is still exactly where the
>   writing happens — but the on-demand endpoint deliberately does not
>   write a row, so an operator hitting it twenty times does not fill
>   the history with twenty near-identical reports. Only the scheduled
>   job writes.
> - **The read-only rule below has been read as covering the AI
>   *tools* rather than every route under `/v1/admin`.** The reasoning is
>   in `SettingsHandlers`' doc comment and in `CLAUDE.md`'s own wording: a
>   settings save is what "a human still has to explicitly save that
>   change through the normal config UI" names, and no AI-assisted
>   handler holds a reference to it. The alternative reading — store the
>   LLM key in cryden, or in the environment only — is worse: the spec
>   below explicitly says this repo owns that config storage.
>
>   *(Correction: this bullet originally said `/v1/admin/settings/*` was
>   the admin surface's first write. It was not — Tier 3's `PUT`/`DELETE
>   /v1/admin/users/{userID}/metadata/{key}` have written since then, so
>   the admin surface was never read-only and this tier did not change
>   that. The reading above is unaffected; the claim about precedence
>   was simply wrong.)*
>
> The two decisions this tier had recorded as open were resolved by
> following this file's own instruction to make the reasonable call and
> note it: the live provider is built on the **official Anthropic Go
> SDK** rather than hand-rolled HTTP, and the settings credentials use a
> **dedicated `SETTINGS_ENCRYPTION_KEY`** rather than reusing cryden's
> `ENCRYPTION_KEY`, matching this repo's existing convention of
> purpose-specific keys (`CLOUD_LOG_HASH_KEY`).

Every AI-assisted endpoint in this tier is read-only by construction —
see `CLAUDE.md`'s hard rule at the top. The settings routes at the end of
this list are not AI-assisted endpoints: they are the settings save those
tools' suggestions pre-fill.

- **Weekly digest**: `GET /v1/admin/digest` → `cryden.WeeklyDigest`/
  `DigestSince`. Plus **scheduling and history** (new, this repo's own
  infrastructure): a scheduled job that calls `WeeklyDigest`
  periodically and stores the result in its own table, and `GET
  /v1/admin/digest/history` to list past ones. Cryden has no
  scheduling concept at all; this is entirely api-side.
- **Support-ticket assistant**: `GET
  /v1/admin/support/diagnose?email=...` → `cryden.DiagnoseLoginIssue`.
- **Config tuning advisor**: call `admin.BuildTuningReport` directly
  (import `github.com/crydensync/cryden/v2/admin`), not the flattened
  `cryden.ConfigTuningReport` text helper — the console needs the
  structured `TuningSuggestion{Area, Finding, Suggestion}` list to
  render individual cards, not a pre-rendered text blob. Expose as
  `GET /v1/admin/config-tuning`.
  - **The "Apply" button, already decided, don't relitigate this**:
    Apply must never write a suggested value into live config
    automatically. It returns/pre-fills the suggested value into
    whatever settings field it corresponds to, and a human still has
    to explicitly save that settings change through the normal config
    UI. This preserves cryden's own non-negotiable rule that these
    tools suggest and never act, and it avoids a bad suggestion
    silently changing production config with no confirmation step.
- **Ask-AI widget**: needs `ai.LLMProvider` and `ai.QueryableStore`
  wired up before any endpoint here does anything. See below.
- **LLM Provider config** (new): a settings screen/endpoint pair
  (`GET`/`PUT /v1/admin/settings/llm-provider`) letting an operator
  configure which model/API key backs `ai.LLMProvider`, stored in this
  repo's own config table (never in cryden, never in plaintext without
  at-rest encryption — treat this credential with the same care as
  `JWT_SECRET`). This repo then constructs the real `ai.LLMProvider`
  implementation from that stored config at startup or on change.
  **Built, with one piece of this bullet not done.** The endpoints
  exist, `DELETE` was added alongside `GET`/`PUT` (a settings screen
  with no way to clear a credential is a screen an operator cannot
  leave), and `aiprovider.NewAnthropic` is the real implementation,
  built on the official Anthropic Go SDK. What is **not** built is the
  last sentence: nothing reads the stored config and constructs a
  provider from it, because nothing consumes one yet — the widget's
  serving endpoint does not exist. The glue lands with its first
  caller rather than before it, so it is not written blind.
- **Database Provider config** (new): same shape, for pointing
  `ai.QueryableStore` at a read-only database role/connection string.
  **The read-only-role requirement is not optional** — cryden's own
  design decision is that the credential boundary, not just the
  allowlist, is the real safety guarantee for this feature. Whatever
  this screen lets an operator configure, validate that the supplied
  role is actually read-only before accepting it if there's any
  feasible way to check (e.g. attempt a write and confirm it's
  rejected), don't just trust a checkbox in the UI.
  **Built.** `PUT` connects with the supplied credentials and refuses
  to store anything until the server has rejected a write on that
  connection — see `aiprovider.CheckReadOnly`. Two outcomes are
  distinguished that the bullet does not mention, because they call
  for different words: a role that *can* write, and a check that could
  not reach a conclusion. The second is refused too, since treating it
  as a pass would make the check succeed exactly when it is least able
  to tell. `aiprovider.NewPostgresSnapshot` is the matching
  `ai.QueryableStore`; like the provider above, nothing constructs it
  from the stored config yet, for the same reason.
- **Ask-AI widget embed/scope config** (new): once the two providers
  above exist, `widget.Ask` itself needs no new engine work — expose
  whatever embed snippet / scope configuration the csax+ console needs
  as its own settings endpoint.
  **Built, with two deliberate departures.** The endpoint stores the
  widget's enabled flag, origins, entity scope and copy.
  `aiprovider.ScopedProvider` then *enforces* the entity scope —
  cryden's `widget.Ask` scopes every intent to the calling end user but
  does so over all of `ai.AllowedEntities`, so narrowing that is a host
  decision and a scope setting nothing consulted would be worse than no
  setting. And the response carries **no embed snippet**: the snippet is
  markup the console renders into its own pages, and the URL in one
  would name a route this repo does not serve. The console gets the
  configuration a snippet is built from instead.

---

## Tier 5 — users admin surface (new, no engine gap, just missing endpoints)

> **Status: built on `feat/tier5-users-admin-surface`.** All four
> endpoints exist, are wired in `main.go`, and are tested end to end on
> the in-memory stores — `go build`, `go vet` and `go test ./...` clean.
> Migration `014_reviewed_anomalies` is written and copied into
> `migrations/`; it has **never been applied to a database**, and
> `anomalyreview.PostgresStore` has never run against a real Postgres.
> No Docker or Postgres was available in the environment this was built
> in, so the migration's foreign key and its `23503` mapping are
> verified by reasoning and by the in-memory double, not by execution.
> `-race` was not run this session either. `PROGRESS.md` says all of this
> in full rather than implying a verification that did not happen.

- `GET /v1/admin/users?q=...&limit=...&offset=...` → `cryden.GetUser`
  for an exact match, `ListAll`/`Count` for browsing. Behind
  `RequireAdmin`.
  **Built as specced, with the search narrowed to exact-only.** `q` goes
  to `cryden.GetUser` and nothing else: partial search would mean SQL
  against cryden's own `users` table, which is the ownership boundary
  this repo has kept everywhere else. The match is also case-*sensitive*,
  because cryden stores addresses exactly as typed and compares them
  with `=` — so the response carries `match: "exact_email"` and a
  console can explain a zero-result search instead of leaving an
  operator to conclude the account is gone. A search that finds nothing
  is an empty 200, never a 404.
- `GET /v1/admin/users/{userID}` → account detail view, likely
  composing `GetUser` with session count and recent audit history.
  **Built.** `active_sessions` is a count rather than a list,
  deliberately — listing devices would publish every IP and user agent
  an account has signed in from to anyone holding an operator token.
  `locked` is computed from the lockout deadline rather than mirrored
  from the column, because cryden clears a lockout by time passing, not
  by writing a null. `PasswordHash` is on the struct this is built from
  and is kept off the wire, with a test asserting that against the raw
  body.
- **MFA/passkey adoption stats** (new, no engine gap): computable via
  `AuditStore.SearchByType`/count against `EventTOTPEnabled`/
  `EventWebAuthnRegistered` versus total user count — same pattern as
  the Argon2id migration progress endpoint in Tier 3.
  **Built as `GET /v1/admin/security/mfa-adoption`, and it reports
  events rather than users.** The spec above assumed a user count was
  available to divide by; it is not. cryden's `TOTPStore` and
  `WebAuthnCredentialStore` are per-user with no `Count` and no
  `ListAll`, so "how many accounts have a factor" is a question the
  engine cannot be asked — and answering it here would mean counting
  rows in cryden's own tables. Every field is therefore named
  `*_events`, and **no adoption percentage is derived anywhere**: a
  ratio of events to `total_users` would look like coverage and move for
  the wrong reasons (a user who enrols, loses a phone and disables
  contributes one of each and is enrolled zero times over).
- **Anomaly review/dismiss state** (new, this repo's own table):
  cryden's `AnomalyStore`/`AuditStore` record signals but have no
  concept of a human having reviewed one. A `reviewed_anomalies` table
  here (audit event ID, reviewer, status, timestamp) backs a
  review/dismiss workflow the console can drive; cryden's own audit
  history is never mutated to reflect this.
  **Built as `GET /v1/admin/anomalies` + `PUT /v1/admin/anomalies/{eventID}`.**
  Two decisions were settled by the human before it was written, and
  both are load-bearing:
  - **Dismiss is a status, not a delete, and the evidence stays.** The
    table has `status IN ('unreviewed','confirmed','dismissed')` and no
    DELETE anywhere; withdrawing a judgement stores `unreviewed` rather
    than removing the row, so the record of who looked — and that they
    changed their mind — survives.
  - **The queue is keyed on the audit event id**, which is what a
    console has in hand. Since cryden has no lookup by event id, the
    existence check is carried by a foreign key from
    `reviewed_anomalies.event_id` to `audit_events.id`, with the
    resulting SQLSTATE `23503` mapped to a clean
    `404 audit_event_not_found`.
  - **Confirming takes no action on any account.** No lock, no session
    revoke, no threshold change. This repo has no machinery that acts on
    an account beyond what an operator does by hand, and putting one
    behind a confirm button is exactly the automatic action `CLAUDE.md`
    forbids. The queue is the two `signals`-carrying event types
    (`anomaly_detected`, `credential_stuffing_detected`); widening it to
    the failure events around them would make the audit table the queue.

**Not built, and not part of this tier**: the widget's own serving
endpoint. The Stage 2 widget *configuration* exists, but nothing serves
an embeddable widget, so `allowed_origins` is still stored and
unenforced — the same gap `CURRENT-STATE.md` records for Tier 4.
