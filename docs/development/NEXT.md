# api — next up

Ordered queue. Take the first unfinished item, build it completely,
verify it (see `CODEX.md`), update the three docs
(`CURRENT-STATE.md`/`NEXT.md`/`PROGRESS.md`), then stop for review
before starting the next tier. Specs below are deliberately detailed
so you don't need to ask anything mid-build — where something is
genuinely unspecified, make the most reasonable call consistent with
`CODEX.md`'s ownership rules and note the assumption in `PROGRESS.md`.

Tier 0 and Tier 0.5 are done — see `CURRENT-STATE.md`.

---

## Tier 1 — auth methods

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

---

## Tier 2 — mostly config, one endpoint

- **Anomaly detection, credential-stuffing detection, Redis rate
  limiter**: `Config.Anomalies`, `Config.AnomalyThresholds`,
  `Config.CredentialStuffingThresholds`, `Config.RateLimiter` — wire
  from env vars in `config/config.go`, following the existing pattern
  for optional engine config. No new routes; these are transparent to
  every existing auth endpoint.
- **Named sessions**: change `GET /v1/sessions`'s response shape to
  use `cryden.ListNamedSessions` instead of the current session list,
  so each entry includes its `Label` (e.g. `"Chrome on macOS, San
  Francisco, CA"`). This is a breaking response-shape change for
  existing consumers — bump the response, don't silently add a field
  if the existing shape is documented in `openapi/spec.yaml` as fixed;
  check there first.
- **OAuth provider health check** (new, for the console): `GET
  /v1/admin/oauth/health` (behind `RequireAdmin`) — for each configured
  provider, a lightweight reachability check against its authorize
  endpoint (HEAD or a cheap GET, not a real OAuth flow), returning
  per-provider status. This is entirely this repo's own logic; cryden
  has no concept of provider health.

---

## Tier 3 — config plus real endpoints

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

Every endpoint in this tier stays read-only/surface-only, no
exceptions — see `CODEX.md`'s hard rule at the top.

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
- **Database Provider config** (new): same shape, for pointing
  `ai.QueryableStore` at a read-only database role/connection string.
  **The read-only-role requirement is not optional** — cryden's own
  design decision is that the credential boundary, not just the
  allowlist, is the real safety guarantee for this feature. Whatever
  this screen lets an operator configure, validate that the supplied
  role is actually read-only before accepting it if there's any
  feasible way to check (e.g. attempt a write and confirm it's
  rejected), don't just trust a checkbox in the UI.
- **Ask-AI widget embed/scope config** (new): once the two providers
  above exist, `widget.Ask` itself needs no new engine work — expose
  whatever embed snippet / scope configuration the csax+ console needs
  as its own settings endpoint.

---

## Tier 5 — users admin surface (new, no engine gap, just missing endpoints)

- `GET /v1/admin/users?q=...&limit=...&offset=...` → `cryden.GetUser`
  for an exact match, `ListAll`/`Count` for browsing. Behind
  `RequireAdmin`.
- `GET /v1/admin/users/{userID}` → account detail view, likely
  composing `GetUser` with session count and recent audit history.
- **MFA/passkey adoption stats** (new, no engine gap): computable via
  `AuditStore.SearchByType`/count against `EventTOTPEnabled`/
  `EventWebAuthnRegistered` versus total user count — same pattern as
  the Argon2id migration progress endpoint in Tier 3.
- **Anomaly review/dismiss state** (new, this repo's own table):
  cryden's `AnomalyStore`/`AuditStore` record signals but have no
  concept of a human having reviewed one. A `reviewed_anomalies` table
  here (audit event ID, reviewer, status, timestamp) backs a
  review/dismiss workflow the console can drive; cryden's own audit
  history is never mutated to reflect this.
