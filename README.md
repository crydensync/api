# api

A generic HTTP wrapper around [CrydenSync](https://github.com/crydensync/cryden) — self-hosted, not a hosted multi-tenant service. Deploy your own instance next to your own Postgres; this is not a shared server other people's apps connect to.

Every consumer talks to this over plain HTTP — no Go required. This is what a JS/Python SDK calls under the hood, and what you can call directly with `curl`/`fetch` in the meantime.

## Prerequisites

- Go 1.22+ (check `go.mod` for exact version)
- A running Postgres instance (local, Docker, or hosted — e.g. Supabase, Neon, RDS) — or nothing but a writable path, if you run on SQLite (see [The two backends](#the-two-backends))

## Getting started

```bash
git clone https://github.com/crydensync/api
cd api
cp .env.example .env   # fill in DATABASE_URL, JWT_SECRET, CORS_ORIGINS
go run .
```

Run the migrations in `migrations/` against your database first, in order (copies of CrydenSync's own migrations, kept here so this repo is self-contained for local dev and CI — same as `typebook` keeps its own copy). `002_oauth_identities` is required even if you don't use OAuth yet — `NewOAuthStore` is wired into the engine config unconditionally. `004` through `008` are the TOTP, WebAuthn, recovery-code, login-attempt and API-key tables; run them even if you leave `ENCRYPTION_KEY` unset, since `007` is what the engine's credential-stuffing detection reads once Tier 2 wires it up and `008` is what the API-key work will use.

That paragraph is the Postgres path only. On SQLite there is nothing to run by hand — `main.go` calls cryden's own `sqlite.Migrate` at startup. See [The two backends](#the-two-backends).

OAuth is optional. To enable a provider, set its client ID/secret plus `BASE_URL` (used to build the callback URL registered in that provider's console):

```
BASE_URL=https://api.example.com
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

A provider missing its client ID or secret is simply unavailable — its endpoints return `404 oauth_provider_not_configured` rather than the server refusing to start.

Supported providers are `google`, `github`, `microsoft`, `discord`, `gitlab` and `apple`.

`google`/`github`/`microsoft`/`discord`/`gitlab` all have the same authorization-code shape, so each is one case in `httpapi/oauth_handlers.go` plus its env vars:

```
MICROSOFT_CLIENT_ID=...       MICROSOFT_CLIENT_SECRET=...
DISCORD_CLIENT_ID=...         DISCORD_CLIENT_SECRET=...
GITLAB_CLIENT_ID=...          GITLAB_CLIENT_SECRET=...
```

Apple is the one that does not fit that shape, and it is the only provider needing more than an ID and a secret:

```
APPLE_CLIENT_ID=com.example.web        # your Services ID, not the app bundle ID
APPLE_TEAM_ID=XXXXXXXXXX
APPLE_KEY_ID=XXXXXXXXXX
APPLE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----
```

- Its client "secret" is a short-lived ES256 JWT this API signs itself (`httpapi/apple.go`), which is why it needs the `.p8` key rather than a string. In `.env`, write the key's newlines as `\n`; a real multiline value passed through a secret manager is used as-is.
- There is no userinfo endpoint. The email and account ID come from the `id_token` in the token response, verified against Apple's published signing keys (issuer, audience, expiry and RS256 all enforced) rather than merely decoded.
- The authorization request pins `response_mode=query`, so the existing GET callback route works unchanged. Consequently the one-time `user` payload (the name Apple sends only on a first authorization) is not captured — this API stores the id_token's email, not names.

All four `APPLE_*` values are required; a partially configured Apple is simply unavailable, like any other unconfigured provider.

## The two backends

This API runs on Postgres or on SQLite, chosen by exactly one environment variable:

```
DATABASE_URL=postgres://...      # everything
SQLITE_PATH=/var/lib/cryden/api.db   # core auth only
```

Setting both is a startup error, and so is setting neither. That is deliberate rather than a convenience: `DATABASE_URL` is what the admin console needs and `SQLITE_PATH` is what the store wiring reads, so quietly preferring one would run a deployment on a backend its own configuration does not describe.

**SQLite runs core auth and nothing under `/v1/admin`.** Signup, login, refresh, sessions, password change, email change, OAuth, TOTP, passkeys, recovery codes, magic links and API keys all work. Every admin route — the whole console: the user surface, metadata, webhook and log history, the digest, support diagnosis, config tuning, flagged-event review, AI settings — answers:

```json
{"error": {"code": "not_implemented_on_sqlite", "message": "the admin console requires a Postgres backend; this deployment runs on SQLite"}}
```

with `501`, before the token is looked at. This is one decision applied in one place (`httpapi.AdminOnly`), not a list of routes to maintain: the admin console's tables are this repo's own and Postgres-only, and `RequireAdmin` itself depends on the `operators` table, so there is no partial console to offer and no way for a SQLite deployment to have an operator at all. A `403 not_operator` would have been the easy answer and the wrong one — it tells a legitimate operator they personally lack access when the truth is that this backend has no console.

The one AI surface that is *not* under `/v1/admin` is `POST /v1/ask-ai`, which serves the widget to a signed-in end user. It is still unavailable on SQLite, because the provider behind it lives in the Postgres-only `settings` table: it answers `404 not_configured`, the same shape it gives on a Postgres deployment that has not configured a provider. One rule, stated once: **the AI-assisted surface needs `DATABASE_URL`.**

These variables are accepted but inert on SQLite, and the server says so at startup rather than letting an operator wonder — `SETTINGS_ENCRYPTION_KEY`, `WEBHOOK_URL`, `CLOUD_LOGGING`, `DIGEST_INTERVAL_HOURS`. `ENCRYPTION_KEY` is *not* in that list: TOTP and passkeys are cryden's own tables and work on both backends.

No migration step exists on SQLite. `main.go` calls cryden's own `sqlite.Migrate` at startup, which embeds its migrations and records what it applied, so a second boot is a no-op. The copy of those files under `migrations/sqlite/` is reference material, not what runs — see the README in that directory.

The connection is opened with three pragmas, all of them load-bearing: `foreign_keys(1)` (off by default, so the schema's `ON DELETE` clauses would silently not run), `busy_timeout(5000)` (zero by default, so a concurrent writer gets an immediate `SQLITE_BUSY` instead of waiting), and `journal_mode(WAL)`. The server verifies the first two on every boot with cryden's own `CheckPragmas` and refuses to start if the DSN and the driver have drifted apart.

**Backing up a SQLite deployment means copying `api.db`, `api.db-wal` and `api.db-shm` together**, or checkpointing first. With WAL, recent writes — including, on a fresh deployment, the entire schema — live in the `-wal` file until a checkpoint folds them into the main file. Copying `api.db` alone can silently produce an empty database in that window.

A clean stop is what closes that window: on `SIGTERM` or `SIGINT` the server stops accepting connections, waits up to 30 seconds for the requests already in flight, stops the webhook worker and digest scheduler, and closes the database — which on SQLite is the checkpoint that folds the `-wal` file back into `api.db` and removes the sidecar files. So `systemctl stop`, `docker stop` and Ctrl-C all leave a `api.db` that is complete on its own. A `kill -9`, a crash or a power loss does not, which is why the paragraph above still stands.

## Second factors

TOTP and passkeys are optional and all-or-nothing on `ENCRYPTION_KEY`: cryden refuses to construct an engine with a TOTP or WebAuthn store set and no encryption key (a TOTP secret must be recoverable in plaintext to check a code, so it is encrypted rather than hashed). With the key unset, both methods answer `404 totp_not_configured` / `404 passkeys_not_configured` per request, the same shape an unconfigured OAuth provider uses, rather than the server refusing to start.

```
ENCRYPTION_KEY=...                 # required for TOTP and/or passkeys
TOTP_ISSUER_NAME=YourApp           # cosmetic; shown in the authenticator app
WEBAUTHN_RP_ID=yourapp.com         # your real registrable domain — a security parameter, not a label
WEBAUTHN_RP_DISPLAY_NAME=Your App Inc
WEBAUTHN_RP_ORIGINS=https://yourapp.com
```

Passkeys also need all three `WEBAUTHN_*` values; setting only some of them logs a startup warning and leaves passkeys off.

Magic-link login needs no extra configuration — it reuses the same `Verifications` store email change uses, and `consoleMagicLinkSender` (in `email_sender.go`) is a dev stand-in exactly like `consoleEmailSender`.

**Once an account has a confirmed second factor, a correct password is no longer enough.** `POST /v1/login`, the OAuth callback and `/v1/magic-link/complete` all answer `200` with:

```json
{ "data": { "second_factor_required": true, "pending_token": "...", "methods": ["totp", "webauthn"] } }
```

`pending_token` is then handed to whichever completion endpoint matches a listed method: `/v1/login/totp`, `/v1/login/passkey/begin` + `/v1/login/passkey/finish`, or `/v1/login/recovery-code`. It is not an access or refresh token and does nothing on any other endpoint.

## Rate limiting

Two independent layers:
- **Engine-level** (per-user, on login/signup/magic-link) — already built into CrydenSync itself. `RATE_LIMIT_ATTEMPTS` / `RATE_LIMIT_WINDOW_SECONDS` tune it (default 10 per minute). In-memory and per-process by default, which is correct for exactly one instance; set `REDIS_URL` and every replica counts against one shared window instead of each keeping its own. Note the trade-off that comes with that: cryden fails those three entry points closed while Redis is unreachable, rather than letting them run unlimited.
- **Edge-level** (per-IP, applied to every request) — coarser, protects the whole API surface from being hammered generally. Configurable via `EDGE_RATE_LIMIT` (default 100 requests/minute per IP). Still in-memory and per-process, `REDIS_URL` or not — a shared window for the coarse per-IP guard is its own decision, not this one.

## Anomaly detection

Off by default. Set `ANOMALY_DETECTION=true` to turn on cryden's login anomaly detection and credential-stuffing detection — they share one store as their on/off switch, because they are the same login-attempt history read two ways. Both are **report-only**: a flagged attempt records an audit event (`anomaly_detected`, `credential_stuffing_detected`) and nothing else. No login is ever blocked, delayed or challenged by them, and neither returns an error a client could branch on.

Every threshold below defaults to the engine's own value and only needs setting to tune it. Zero means whatever the engine says it means per knob (off for most, "no event suppression" for the stuffing cooldown) — check cryden's own `security` package before setting one to `0`.

```
ANOMALY_WINDOW_MINUTES=15              ANOMALY_HISTORY_SIZE=20
ANOMALY_USER_FAILURE_VELOCITY=5        ANOMALY_IP_FAILURE_VELOCITY=20
ANOMALY_MAX_CONCURRENT_SESSIONS=10     ANOMALY_TOKEN_REUSE_LOOKBACK_MINUTES=1440
CREDENTIAL_STUFFING_WINDOW_MINUTES=60  CREDENTIAL_STUFFING_TARGET_ACCOUNTS=10
CREDENTIAL_STUFFING_COOLDOWN_MINUTES=15
```

## Response contract

Every response follows one of two shapes:

```json
// success
{ "data": { ... } }

// error
{ "error": { "code": "invalid_credentials", "message": "invalid email or password" } }
```

`code` is the stable string to branch on programmatically. `message` is for humans — never parse it.

One error carries a third, optional key: `password_policy_violation` includes a `details` array holding every broken rule at once as stable codes (`min_length`, `max_length`, `require_uppercase`, `require_lowercase`, `require_digit`, `require_symbol`), so a client can list them together instead of discovering one per submit. Every other error has exactly the two keys above.

```json
{ "error": { "code": "password_policy_violation", "message": "password does not meet the required policy", "details": ["min_length", "require_digit"] } }
```

## Endpoints

```
POST   /v1/signup
POST   /v1/login
POST   /v1/refresh
POST   /v1/logout                    (auth required)
POST   /v1/logout-all                (auth required)
GET    /v1/verify                    (auth required)
GET    /v1/sessions                  (auth required)
DELETE /v1/sessions/{id}             (auth required)
POST   /v1/change-password           (auth required)
POST   /v1/delete-account            (auth required)
POST   /v1/email/request-change      (auth required)
POST   /v1/email/confirm-change
GET    /v1/oauth/{provider}
GET    /v1/oauth/{provider}/callback
GET    /v1/oauth/{provider}/link              (auth required)
GET    /v1/oauth/{provider}/link/callback
GET    /v1/health

POST   /v1/totp/enroll               (auth required)
POST   /v1/totp/confirm              (auth required)
POST   /v1/totp/disable              (auth required)
POST   /v1/passkeys/register/begin   (auth required)
POST   /v1/passkeys/register/finish  (auth required)
GET    /v1/passkeys                  (auth required)
DELETE /v1/passkeys/{credentialID}   (auth required, password in body)
POST   /v1/recovery-codes/generate   (auth required)
POST   /v1/magic-link/request
POST   /v1/magic-link/complete
POST   /v1/login/totp                (completes a paused login)
POST   /v1/login/passkey/begin       (completes a paused login)
POST   /v1/login/passkey/finish      (completes a paused login)
POST   /v1/login/recovery-code       (completes a paused login)

POST   /v1/api-keys                  (auth required, raw key returned once)
GET    /v1/api-keys                  (auth required)
DELETE /v1/api-keys/{keyID}          (auth required)

POST   /v1/ask-ai                    (auth required, NOT admin — see below)

GET    /v1/admin/oauth/health             (admin required)
GET    /v1/admin/security/hash-migration  (admin required)
GET    /v1/admin/security/mfa-adoption    (admin required)
GET    /v1/admin/users                    (admin required)
GET    /v1/admin/users/{userID}           (admin required)
GET    /v1/admin/users/{userID}/metadata  (admin required)
PUT    /v1/admin/users/{userID}/metadata/{key}     (admin required)
DELETE /v1/admin/users/{userID}/metadata/{key}     (admin required)
GET    /v1/admin/anomalies                (admin required)
PUT    /v1/admin/anomalies/{eventID}      (admin required)
GET    /v1/admin/webhooks/deliveries      (admin required)
GET    /v1/admin/logging/recent           (admin required)
GET    /v1/admin/digest                   (admin required)
GET    /v1/admin/digest/history           (admin required)
GET    /v1/admin/support/diagnose         (admin required)
GET    /v1/admin/config-tuning            (admin required)
GET|PUT|DELETE /v1/admin/settings/llm-provider        (admin required)
GET|PUT|DELETE /v1/admin/settings/database-provider   (admin required)
GET|PUT|DELETE /v1/admin/settings/ask-ai-widget       (admin required)
```

`GET /v1/sessions` answers with *named* sessions: each entry keeps its `id`, `ip`, `user_agent` and `created_at`, and gains `label`, `device` and `location`, all computed on read from the session's own IP and User-Agent — nothing new is stored and no migration exists for it. `label` is the string a "your devices" screen shows (`Chrome on macOS`, or `Unknown device` for a client that sent no User-Agent). `location` is present but empty unless a geolocator is configured, and this repo wires none on purpose: every implementation of that interface calls somebody else's internet service, which is a deployment's decision rather than this repo's. The response shape is documented in `openapi/spec.yaml`.

`{provider}` is `google`, `github`, `microsoft`, `discord`, `gitlab` or `apple`.
The two OAuth flows are separate
on purpose:
- `/oauth/{provider}` → `/oauth/{provider}/callback` is login/signup —
  no auth required, since this IS how you get authenticated.
- `/oauth/{provider}/link` → `/oauth/{provider}/link/callback` attaches
  a provider to an already-logged-in user. `/link` itself requires a
  Bearer token, but `/link/callback` deliberately does NOT — a browser
  redirect to the provider and back carries no Authorization header,
  so `/link` signs the caller's user ID into a short-lived cookie
  instead, verified again at `/link/callback`.

A login attempt whose email matches an existing password-based account
returns `409 oauth_email_conflict` instead of silently linking the two
— the client should route the user to log in with their password, then
call `/oauth/{provider}/link` while authenticated to resolve it.

Authenticated endpoints expect `Authorization: Bearer <access_token>`.

## Admin endpoints

Everything under `/v1/admin` requires an **operator** token: a valid access token whose `role` claim is `admin`. Operator status is this repo's own concept, not cryden's — it lives in its own `operators` table (`migrations/003_operators.*.sql`), and the claim is attached to the token at issue time by the `AccessTokenClaims` provider in `main.go`. An ordinary user's token carries no `role` claim at all, so "revoked operator", "never was one" and "no such user" are indistinguishable to a caller, deliberately.

On a SQLite deployment this entire section is unavailable and every route in it answers `501 not_implemented_on_sqlite` — the console's tables are Postgres-only. See [The two backends](#the-two-backends).

The first operator is created with `cmd/grant-operator`, from a machine with direct database access — deliberately not an HTTP bootstrap route, which would be needless attack surface reachable over the network:

```
go run ./cmd/grant-operator -db "$DATABASE_URL" -email you@example.com
go run ./cmd/grant-operator -db "$DATABASE_URL" -email you@example.com -revoke
```

Because the claim is baked in at issue time, a grant takes effect on that user's next login or refresh, and a revoke the same way — an already-issued token keeps its claim until it expires (15 minutes by default).

`GET /v1/admin/oauth/health` reports, per provider, whether it is configured and whether its authorize endpoint answers:

| `status` | meaning |
| --- | --- |
| `ok` | Answered below 500. A bare GET with no OAuth parameters legitimately gets a 4xx, which still proves the endpoint is serving. |
| `degraded` | Answered 5xx. |
| `unreachable` | No HTTP response at all (DNS, TLS, connect, timeout) — `error` carries the transport error. |
| `not_configured` | No client ID/secret for it, so nothing was probed. |

Probes run concurrently with a 5-second timeout each, carry no OAuth parameters and cannot start or complete a login. This is api-side logic: cryden knows whether a provider is configured, not whether it is reachable.

`GET /v1/admin/security/hash-migration` reports how far a password-hash migration has got:

```json
{"data": {
  "hasher": {"algorithm": "argon2id", "memory_kib": 65536, "iterations": 3, "parallelism": 4},
  "total_users": 1234,
  "upgraded_events": 900,
  "estimated_remaining": 334,
  "window_days": 7,
  "upgraded_events_in_window": 120
}}
```

Set `PASSWORD_HASHER=argon2id` and every login whose stored hash is out of date gets rewritten with Argon2id — that gradual rewrite is the migration, and there is no separate command to run. This endpoint only watches it:

- `hasher` is what this deployment is configured to **write**, read from config, not from the users table. cryden deliberately exposes no bulk way to inspect stored hash algorithms, and adding one would be the engine's job rather than this repo's.
- `upgraded_events` counts **events**, not users. A user whose hash is rewritten twice — a second cost increase a year later — contributes two, so this number can exceed `total_users`.
- `estimated_remaining` is therefore *estimated*, floored at zero, and is `total_users - upgraded_events`.
- `upgraded_events_in_window` is the field that actually answers "is this draining": the all-time count only ever rises, while a windowed one falls to zero as the last stragglers log in. `window_days` (1–365, default 7) sets that window.

`GET /v1/admin/support/diagnose?email=` answers the support ticket "why can't this person log in", from the account's own recorded history: whether it is locked and until when, its consecutive failed-attempt count, how many sessions it currently holds, and the recent failure-type events behind all of that, newest first.

```json
{"data": {"email": "dana@example.com", "text": "Login diagnosis for dana@example.com\n\nAccount is LOCKED until 14:32 UTC.\n5 consecutive failed attempts currently recorded…"}}
```

- **An unknown address is the answer, not a 404.** cryden's `admin.DiagnoseLogin` returns `Found: false` rather than an error, and the report says "No account exists for this email address." A 404 would be indistinguishable from a broken endpoint, and "you have the wrong address" is exactly what a support agent pasting a typo'd email needs to be told.
- The text is the engine's, passed through verbatim. This repo does not reformat a report it does not own — and `email` is echoed alongside it so an agent working through a queue can see which address was answered.
- **Read-only structurally, not by convention.** The report is built through interfaces carrying no `LockAccount`, `ResetFailedAttempts` or `Revoke`, so the endpoint cannot unlock the very account it is describing, whatever the caller asks for. That is cryden's design and this repo adds nothing on top of it.
- A missing `email` is a `400`, not a diagnosis of the empty string — which would come back as "no account exists", an answer to a question nobody asked.

`GET /v1/admin/security/mfa-adoption` reports second-factor enrolment the same way, from the engine's own audit events:

```json
{"data": {
  "total_users": 1234,
  "window_days": 7,
  "factors": [
    {"factor": "totp", "enrolled_events": 300, "removed_events": 40,
     "enrolled_events_in_window": 12, "removed_events_in_window": 3},
    {"factor": "passkey", "enrolled_events": 90, "removed_events": 2,
     "enrolled_events_in_window": 7, "removed_events_in_window": 0}
  ]
}}
```

**It is not "N of M users have MFA", and that is not an oversight.** cryden cannot be asked how many accounts have a factor enrolled: `TOTPStore` and `WebAuthnCredentialStore` are per-user (`GetByUserID`, `ListByUser`) with no `Count` and no `ListAll`. Counting the rows in `totp_secrets` from here would answer it exactly and would also be this repo writing SQL against the engine's own schema — the boundary drawn in [Design notes](#design-notes). So the report gives what the engine does record system-wide, and names every field accordingly:

- **Every field counts events, not users.** A user who turns TOTP on, loses their phone and turns it off contributes one enrolment and one removal and is enrolled zero times over. `enrolled_events` is not an adoption figure, and no percentage is derived from it anywhere in the API — a ratio of events to `total_users` would look like coverage and move for the wrong reasons.
- **The pair against each other is the honest read.** A factor whose removals keep pace with its enrolments is churning; the windowed pair says whether that is happening now.
- **Recovery codes are not in the list.** They are a fallback for an account that already has a second factor, not a factor of their own, so counting `recovery_codes_generated` as enrolment would report a different thing than the label says.
- Both factors are always present, including at zero. A report that omitted a factor with no events would leave a console unable to tell "nobody has enrolled" from "this deployment does not support it".

## The user surface

Two endpoints, both read-only, for the console's account screen:

```
GET /v1/admin/users?q=&limit=&offset=      # exact-email lookup, or browse
GET /v1/admin/users/{userID}               # one account, its sessions, its history
```

This is the one place in this API where an operator can see an account that is not their own, so what is *not* here matters as much as what is. There is no lock, no unlock, no password reset and no delete. cryden's store exposes `LockAccount`, and wiring it to a button would make this repo the thing that can lock somebody out of their account; an operator who needs that has the engine's own admin path, not an HTTP endpoint this repo invented. The detail view reports lockout state so it can be diagnosed, and stops there.

- **The email search is exact and case-sensitive, and the response says so.** `q` goes to `cryden.GetUser`, which is `WHERE email = $1` — cryden stores addresses exactly as typed and has no `citext`, so `Alice@example.com` does not find an account created as `alice@example.com`. Every response carries `match: "exact_email"` or `"browse"` so a console can label the result and explain a zero-result search, rather than leaving an operator to conclude the account is gone. A search that finds nothing is an empty `200`, never a `404` — answering `404` would make a console render "error" for the most ordinary outcome a search has.
- **There is no partial search, deliberately.** A `LIKE` against cryden's `users` table would cross the ownership boundary this repo keeps everywhere else: the engine owns that table, and a query written here would be a second, silent definition of what a user is. If partial search is wanted later, it is its own deliberate piece of work.
- **`locked` is computed, not mirrored.** cryden clears a lockout by time passing rather than by writing a null, so a row can carry a `locked_until` already in the past — reporting `locked: true` for a non-nil column would tell an operator an account is locked out when it is not, and the ones that look like that are exactly the ones somebody just waited out.
- **Sessions are counted, not listed.** `active_sessions` is a number. cryden's `ListByUser` returns only live sessions, so the count is honest; listing them would publish every IP and user agent an account has signed in from to anyone holding an operator token. The support assistant's report makes the same choice for the same reason.
- **`PasswordHash` is on the struct these are built from and never on the wire.** A struct tag is not a guarantee, so a test asserts against the raw response body for any hash-shaped field — and proves the assertion is not vacuous by confirming the stored user really does have one.

## Flagged-event review queue

`GET /v1/admin/anomalies` is the queue of what the engine flagged, and `PUT /v1/admin/anomalies/{eventID}` is where an operator records what they decided about it:

```
GET /v1/admin/anomalies?status=&limit=&offset=
PUT /v1/admin/anomalies/{eventID}   {"status": "confirmed", "note": "real, from the office VPN"}
```

The queue is the two event types cryden writes when a login looks *wrong* rather than merely failing — `anomaly_detected` and `credential_stuffing_detected` — merged newest first, each carrying its review. Both carry a `signals` key naming what tripped, which is what makes them reviewable: an operator can read the event and form a judgement. Widening this to the failure events around them (`login_failed`, `token_reuse_detected`) would not make a bigger queue, it would make the audit table the queue.

- **A review is a row in this repo's own table, keyed on the audit event id.** The event the engine recorded reads exactly the same before and after — nothing here rewrites cryden's audit history. The id is what a console has in hand and what the engine's record is filed under.
- **Nothing deletes.** Dismissing is a status, not a removal, and withdrawing a judgement stores `unreviewed` rather than dropping the row — so the record that somebody looked, and who they were, survives the change of mind. See `anomalyreview`'s package doc.
- **Confirming takes no action.** Marking an event real records the judgement and nothing else: no account is locked, no session revoked, no threshold tuned. There is no machinery in this repo that acts on an account beyond what an operator does by hand, which is exactly what keeps this on the right side of the read-only rule rather than being an exception to it.
- **An event that does not exist is refused, not stored.** cryden has no lookup by event id, so Go cannot check that a flagged event is real — the table does it instead, with a foreign key from `reviewed_anomalies.event_id` to `audit_events.id` and a clean `404 audit_event_not_found` from the resulting SQLSTATE. A console acting on a stale list is told rather than shown a success that annotates nothing.
- **`status=unreviewed` matches an event with no row at all.** The two are the same thing by design, so the filter compares against the default the response reports rather than against what the store happened to return — otherwise the one tab an operator opens first would be empty.
- **Paging is refused past what the merge can fetch.** cryden's per-type search takes a limit and no offset, so the merged window is fetched to `limit + offset` from each type and sliced here. That makes each page an exact prefix of the queue rather than a sample of it — but `limit + offset` beyond 500 is a `400`, not a silent clamp, because a clamped offset would return a page from further up the queue than the caller asked for, which on a review queue means showing events they have already dealt with.
- **`has_more` means "this page came back full, ask again", not "there is more".** Deciding the latter exactly would mean knowing the queue's total size and the fetches give a window per type, so the endpoint says what it can support. A page short of `limit` *is* the end, precisely because the merged window is an exact prefix.
- **The response to a save is the review alone, not the queue row.** Re-reading the event would need a lookup by event id that the engine does not have, so a save returns the decision and a client refreshes the list it already has.

## API keys

`POST /v1/api-keys` mints a machine-to-machine credential for the calling user and returns the raw key **once** — cryden stores only its SHA-256 hash and can never reproduce it, so a caller that loses it has to mint a new one. The response carries the raw key, the stored record (`id`, `name`, `prefix`, `scopes`, `expires_at`, `expired`, `created_at`, `last_used_at`) and a `notice` saying so; a client that renders the key without that notice is the failure this guards against.

```json
POST /v1/api-keys   {"name": "ci deploy", "scopes": ["read"], "expires_in_days": 90}
```

- `expires_in_days` of `0` or absent means the key never expires, which is cryden's own default and the honest one for a credential living in a deploy pipeline's environment: revocation, not expiry, is what actually stops a key.
- `GET /v1/api-keys` lists the calling user's live keys. Revoked keys are absent; expired-but-unrevoked ones are present with `"expired": true`, because "your CI key expired on Tuesday" is exactly what someone needs to see to understand why a pipeline broke.
- `DELETE /v1/api-keys/{keyID}` revokes, irreversibly — the reason a key gets revoked is that somebody else may have it, so mint a new one rather than offering an un-revoke.

Every one of these is scoped to the calling user by cryden itself, which derives the user ID from the verified token rather than from the request. A key belonging to another account, a key that does not exist, and an already-revoked key all answer the same `404 api_key_not_found` — a caller can never learn whether somebody else's key exists.

**No endpoint in this repo authenticates *with* an API key yet.** These three manage them; cryden's `auth.AuthenticateAPIKey` is the other half, and wiring it into a `RequireAPIKey` middleware is a separate change.

## User metadata

`store.User` in cryden deliberately has no metadata concept — authorization and extra per-user data are a host decision, not an engine one — so per-user metadata is this repo's own table (`migrations/009_user_metadata.*.sql`) and its own package (`usermeta/`).

Its purpose is **JWT claim mapping**: a console operator attaches a key to a user, and that key appears as a claim in every access token issued for them from then on. `main.go` sets `AccessTokenClaims` to `usermeta.ClaimsProvider(...)`, which merges the user's operator `role` (if any) with every stored metadata key. Because cryden calls that provider at issue time, a metadata change takes effect on that user's next login or refresh — the same latency an operator grant or revoke has, and not retroactive over tokens already issued.

```json
GET  /v1/admin/users/{userID}/metadata
{"data": {"user_id": "...", "metadata": {"plan": "pro", "tenant_id": 41}, "reserved_claim_names": ["aud","exp","iat","iss","jti","nbf","role","sub"]}}

PUT  /v1/admin/users/{userID}/metadata/plan   {"value": "pro"}
DELETE /v1/admin/users/{userID}/metadata/plan
```

- Writes are **per key**, not a whole-map `PUT`, so two operators editing different fields of one user cannot overwrite each other's work.
- Keys are validated `^[A-Za-z_][A-Za-z0-9_.-]{0,63}$` and refused if they collide with a registered claim name (`sub`, `role`, …) — so a bad key fails when the operator saves it, rather than at every user's next login. The rule lives in `usermeta` rather than in the handler, because it is a data invariant any writer has to pass through. `reserved_claim_names` is reported by `GET` so a console can grey those out instead of letting an operator discover the rule by rejection.
- Values are JSON and stored as `JSONB`, so an object or array is preserved rather than being stringified. Omitting a value and sending an explicit `null` are different things, and the API keeps them different.
- A write for a user that does not exist answers `404 not_found` rather than letting the foreign key fail and surface as a `500`. The path's `{key}` is URL-decoded by `net/http` before it reaches the handler, so a key written `a%2Fb` is judged by the validator above rather than being rejected by URL parsing.

The claims provider runs **two queries on every login and every refresh** — roughly once per `ACCESS_TOKEN_TTL` per active session. That is the price of claims that are current rather than frozen at signup.

## Webhooks

Setting `WEBHOOK_URL` turns on cryden's webhook dispatch: the engine calls this repo's `notify.WebhookSender` for each event in `WEBHOOK_EVENTS` (unset means cryden's own default set, which deliberately excludes `login_success`, `login_failed` and `token_rotated` — the three that fire constantly and say nothing).

**This repo only enqueues.** cryden calls `SendWebhook` synchronously, in the same goroutine as the login that triggered it, so an HTTP call there would be your receiver's downtime becoming your users' login latency. `SendWebhook` writes one `pending` row to `webhook_deliveries` and returns; a background worker makes the call. The row is the queue — a channel would be faster and would lose everything on restart, and a delivery log that cannot answer "was that lockout announced" for events that vanished before a row was written is not worth having.

The request body is built once, at enqueue, and stored. Retries send the identical bytes, which is what lets the delivery log answer "show me what we sent that endpoint" for a retry as well as a first attempt.

| header | meaning |
| --- | --- |
| `X-Cryden-Signature` | `sha256=` + lowercase hex HMAC-SHA256 of the raw body under `WEBHOOK_SECRET`. Absent entirely when no secret is set — never computed over an empty key. |
| `X-Cryden-Event-Type` | the `store.AuditEventType` that fired |
| `X-Cryden-Event-Id` | the engine's idempotency key for this occurrence, **which may be empty** (cryden generates it with `crypto/rand` and deliberately delivers without one rather than dropping the event) |
| `X-Cryden-Delivery-Attempt` | 1-based attempt count, for the receiver's own logs. Not covered by the signature. |

A receiver in Go can use `webhook.Sign`/`webhook.Verify` rather than reimplementing; in another language it is HMAC-SHA256, key = the shared secret as UTF-8, message = the body byte for byte. **Only the body is signed** — the headers above are informational and a receiver must not make a decision on them.

Retries use exponential backoff (30s doubling, capped at 30m) up to `WEBHOOK_MAX_ATTEMPTS`, after which the row is `failed` and stays readable. Anything outside `2xx` is a failure, including redirects. A delivery is attempted by exactly one worker: the claim is a single `UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED)` statement, and a row whose worker died mid-delivery is reclaimed once its `claimed_at` goes stale — so raising the worker count later needs no change to the claim.

`GET /v1/admin/webhooks/deliveries?limit=&status=` lists the log newest first. `response_code` is absent when nothing came back at all (a connection failure, which an operator fixes in a different place from a receiver answering 500). There is deliberately **no** "retry this delivery" endpoint: this surface is read-only (see the design notes), and re-queuing a delivery has consequences for a third party.

## Cloud logging and shipped events

`CLOUD_LOGGING` composes a second, redacted, filtered copy of the engine's log records alongside the full-detail JSON line on stdout, in exactly the shape cryden's `logger` package doc prescribes:

```go
logger.NewMultiLogger(
    logger.NewConsoleJSONLogger(),                 // full detail, stays on stdout
    logger.NewLevelFilter(                         // and the copy that leaves
        logger.NewMaskingRedactor(shipSink),       // without the personal data
        cfg.LogLevel,
    ),
)
```

Redacting *inside* the fan-out rather than around it is the point: stdout keeps the IP address that makes an incident debuggable, and only the shipped copy loses it. `CLOUD_LOG_REDACTION` picks how — `mask` replaces the value with `[redacted]`, `hash` replaces it with a keyed HMAC digest so the same address still reads as the same address across records ("one IP, forty accounts" is the shape credential stuffing has, and a mask destroys it). `hash` requires `CLOUD_LOG_HASH_KEY`, which should be a value of its own rather than a reuse of `JWT_SECRET` — this key is handed to the component whose job is to hand its output to a third party.

There is no vendor here: this repo ships no SDK, so "shipped" means "recorded in `shipped_log_events`", which `GET /v1/admin/logging/recent?limit=&level=` reads back. It is the same bytes a hosted aggregator would have received, which is what makes it a stand-in for one rather than a second, different log beside it — swapping in a real client later is a change to one line of `main.go`.

- `level=warn` means **warn and above**, the same direction the `LevelFilter` above the sink reads the word. One word, one meaning, within one feature.
- An unknown `level` is a `400` naming the four valid values, not an empty list — which is indistinguishable from "the engine has been quiet".
- The write is **synchronous**, on the goroutine that logged. That is a real cost and is not the shape a busy deployment wants; it is the shape this one can have, because an asynchronous sink needs a flush policy and a shutdown path, and this repo has no graceful shutdown anywhere yet. A buffer that is never flushed on exit is a log that silently drops its last records before a crash, which for a log is the failure that matters most. `LOG_LEVEL` (default `info`) is what keeps the volume sane in the meantime, since the engine's debug records never reach the sink.

## Config tuning advisor

`GET /v1/admin/config-tuning?window_days=` reads the recent audit history, compares it against the settings **actually in force**, and returns the suggestions as a structured list — one object per knob, ready to render as a card:

```json
{"data": {
  "since": "…", "until": "…", "window_days": 30,
  "counts": {"account_locked": 5, "login_failed": 5},
  "suggestions": [{
    "area": "Lockout",
    "finding": "5 accounts were locked out of 5 recorded in this window (100%) — LockoutThreshold is currently 5, LockoutDuration 15m0s.",
    "suggestion": "If most of these are real users mistyping a password rather than an attack, consider raising LockoutThreshold…"
  }]
}}
```

- **There is no write path, and there is not going to be one.** No parameter changes a setting, and no counterpart endpoint applies a suggestion. The decision recorded for this surface is **pre-fill, never auto-apply**: a suggestion pre-fills the settings field it concerns, and a human still saves that change through the ordinary settings path. An endpoint that wrote a suggested value straight into live config would be the violation `CLAUDE.md`'s hard rule names, and would let a bad suggestion change production with no confirmation. The route accepts `GET` and nothing else.
- It calls `admin.BuildTuningReport` **directly**, not the flattened `cryden.ConfigTuningReport` text helper. The text is right for a CLI and wrong for a console: a pre-rendered blob cannot become one card per suggestion, and a client would be back to parsing English to find which knob a paragraph was about.
- `counts` is the raw audit evidence the suggestions were computed from, including event types cryden does not define — so a console can show the numbers rather than asking an operator to trust a sentence.
- Every value in the report comes from the config this process built the engine from, never a second reading of the environment. `UsingDefaultRateLimiter` is derived from `RedisURL` being empty — the same condition `main.go` uses to build the Redis limiter — so the report and the wiring cannot drift.
- `window_days` (1–365) defaults to cryden's own **30**-day tuning window, deliberately wider than the digest's week: a config knob should be judged against a month of traffic, not whatever happened this week.
- The password-strength finding always says the breach checker is not set. That is **accurate rather than a stub**: this repo has never wired `Config.BreachedPasswordChecker`, because cryden ships no implementation and every real one calls somebody else's corpus.

`LOCKOUT_THRESHOLD` and `LOCKOUT_DURATION_MINUTES` (defaults 5 and 15 minutes) are passed through to the engine explicitly, for the two reasons above at once: cryden reads them straight off its config with no defaulting, so a deployment that left them implicit was running a lockout that could never actually trigger; and the tuning report describes the settings in force, so it should not have to guess what the engine was handed.

## Weekly digest

Two endpoints, and only one of them depends on any configuration:

```
GET /v1/admin/digest?window_days=            # built now, records nothing
GET /v1/admin/digest/history?limit=          # what the schedule recorded
```

`GET /v1/admin/digest` returns `cryden.DigestSince`'s report verbatim — the text is the engine's, and this repo does not reformat a report it does not own — alongside `since` and `until`, because a client should not have to parse English out of a digest to learn what it covers. `window_days` (1–365, default 7) is passed to the engine rather than implemented here; the seven-day default is what makes it a *weekly* digest. **Asking twice leaves no trace**: the endpoint records nothing, and if that ever stopped being true an operator could no longer tell what the schedule produced from what somebody happened to open.

Setting `DIGEST_INTERVAL_HOURS` (168 is weekly) turns on the schedule: a background job calls the same report every N hours and writes the rendered result to the `digest_runs` table, which `GET /v1/admin/digest/history` lists newest first. Unset means no schedule — no goroutine runs, nothing is written, and the history endpoint answers `404 not_configured` rather than an empty list an operator would read as "nothing has ever happened".

- **cryden has no scheduling concept.** `WeeklyDigest`/`DigestSince` build a report on demand and return a string; there is no run record and nothing that remembers a digest was ever generated. So the table, the job and the history endpoint are entirely this repo's own.
- **The row is the report, not a recipe for one.** The rendered text is stored rather than the counts behind it, because a digest covers a window that has *ended*: re-running its query later would not reproduce it, since "the last seven days" is anchored to when it was built.
- **The first run is one full interval after startup**, not at boot. A process that restarts more often than the interval elapses — a crashloop, a deploy pipeline, a laptop — would otherwise write one row per restart, and a history that grows with restarts rather than with time is not a history of anything.
- A failed run is **logged and swallowed**. This runs in a goroutine with nobody to hand an error to, and a scheduler that stopped at the first database blip would silently stop producing digests for the rest of the process's life.
- Nothing on the HTTP surface can create a digest run. Only the scheduler writes, and it is a process component rather than a request handler — the read-only rule the whole admin surface follows.

## AI provider settings

The AI-assisted admin features need two things only this repo can supply, because cryden defines them as interfaces the host implements: an `ai.LLMProvider` that turns a question into a `QueryIntent`, and an `ai.QueryableStore` that runs one. Three settings endpoints configure them, all operator-only:

```
GET|PUT|DELETE /v1/admin/settings/llm-provider
GET|PUT|DELETE /v1/admin/settings/database-provider
GET|PUT|DELETE /v1/admin/settings/ask-ai-widget
```

These are one of the admin surface's three write blocks, and they are the other half of the read-only rule rather than a hole in it. A tuning suggestion pre-fills one of these forms; an operator presses save; this is what handles that save. No AI-assisted handler in this repo holds a reference to any of them, and none accepts a suggestion as input.

All three answer `404 not_configured` when `SETTINGS_ENCRYPTION_KEY` is unset — without a key there is nowhere safe to put a credential, so the API refuses rather than storing one in the clear.

### Credentials

The LLM API key and the database connection string are sealed with **AES-256-GCM before they reach the table**, keyed from `SETTINGS_ENCRYPTION_KEY`. Treat it like `JWT_SECRET`: set it, keep it out of source control, and expect a rotation to need the old value for as long as rows written under it exist.

- **Separate from cryden's `ENCRYPTION_KEY` on purpose.** The two seal different things with different lifetimes — cryden's covers what the engine stores (TOTP secrets), this one covers what the API stores — so one leaking or rotating need not touch the other. Same reasoning as `CLOUD_LOG_HASH_KEY`.
- **Never returned, in any form.** Not masked, not truncated to the last four characters: `api_key_set` and `dsn_set` booleans are what a console renders "saved" from, and returning any part of the value would put it in a browser's memory and a devtools panel. `GET` on the database provider returns the host and database name only, so an operator can tell which connection is stored without being shown a password.
- **A changed key is `409 setting_undecryptable`, not `404`.** The row is still there, and reporting it as missing would send an operator to re-enter a credential that is fine. `DELETE` needs no key at all, which is what makes it the way out for a deployment that has lost one.
- **The credential is required on every `PUT`**, rather than optional with "blank means keep the existing one". That convention is the usual one and it is wrong here: an omitted field and a deliberately cleared one would be the same request, and getting it wrong means a form that appears to save a key while silently storing an empty one.

### The read-only database requirement

`PUT /v1/admin/settings/database-provider` **connects with the supplied credentials and attempts a write before storing anything.** cryden's own position is that for this feature "the credential boundary, not just the allowlist, is the real safety guarantee" — a role that cannot `INSERT` cannot `INSERT` whatever the query builder does with its input. So the order is: validate the shape, prove the role cannot write, and only then store.

- **An attempted write, not a reading of the role's attributes.** A role with `rolsuper` set, or a connection string containing the word "readonly", or a "read-only?" checkbox in the console, are all claims. Only the server's refusal is evidence, and it is evidence about the actual role, on the actual database, through the actual credentials. It cannot be done client-side either — a browser cannot open a Postgres connection.
- **The probe writes to `pg_temp`**, the session's own temporary schema. The table lives only for the life of that connection and is dropped when it closes, so a probe that fails leaves nothing for an operator to clean up. The pool is capped at one connection so the `CREATE` and the `INSERT` share the session that owns the temp table — a pool that split them would have the `INSERT` fail on a missing table, which looks like a refusal and is not one.
- **Three outcomes, deliberately distinct.** A refused write is a pass. A successful write is `400 database_role_not_read_only`. Anything else — no connection, a timeout, a `CREATE` that failed for a reason other than privilege — is `400 database_role_unverified`, **which is not a pass**. Treating "could not find out" as success would make the check pass exactly when it is least able to tell. Only Postgres' own SQLSTATE `42501` (`insufficient_privilege`) counts as a refusal, and it is matched by code rather than by message, since the message is localized and reworded between major versions.
- **It is slower than its neighbours**, because it opens a connection and runs statements before answering, bounded by a ten-second timeout. That is paid once per save, not per query.

### The ask-ai widget

`GET|PUT /v1/admin/settings/ask-ai-widget` stores the widget's enabled flag, the origins allowed to embed it, the entities it answers over, and its copy. It is the one setting here that is **not** a credential, so there is nothing to redact.

- **`entities` has teeth.** cryden's `widget.Ask` force-scopes every parsed intent to the calling end user's own rows — it discards whatever identity filter the model produced and substitutes the real one, rather than validating and rejecting, so there is no oracle — but it scopes over the whole of `ai.AllowedEntities`. Narrowing that further is a host decision, so `aiprovider.ScopedProvider` enforces the configured subset in front of the provider. A scope setting nothing consulted would be worse than no setting at all. The list is validated against cryden's own allowlist rather than a copy of it.
- **`"*"` as an origin is refused by name**, with the reason in the message: this widget answers questions about the signed-in user's sessions and audit events, so a wildcard origin would let any page on the internet ask them through a visitor's browser.
- **The refusal names neither the entity nor the scope.** That error reaches an end user through the widget; listing the configured entities would be describing the console's schema to whoever is typing questions at it.
- **A disabled widget may be otherwise empty**, so switching the feature off does not require filling in fields that are about to stop mattering. Anything that *is* filled in is still validated, so a form cannot store a value that was never checked and would be rejected the moment it was switched on.
- **No embed snippet is returned.** The snippet is markup the console renders into its own pages, and this repo has no opinion on another repo's markup. An earlier version of this note gave a different reason — that the URL in a snippet would name an endpoint that did not exist — and that expired in spec 1.7, when `POST /v1/ask-ai` started serving the widget. What this endpoint owes the console is the configuration a snippet is built from.

### Serving the widget

`POST /v1/ask-ai` is where the widget's questions are answered, and it is the **one AI-assisted endpoint here that is not behind `RequireAdmin`**. That is the feature, not an oversight: the widget belongs to an end user and answers questions about *their own* account — the sessions and audit events on their own row. An operator is also a user of their own account, so an operator's token works too, but it works as an account holder, not as an operator.

```json
// POST /v1/ask-ai          Authorization: Bearer <any signed-in user's token>
{ "question": "when did I last log in" }
// 200
{ "data": { "answer": "id | created_at\ns-2 | 2026-09-17T09:12:44Z", "row_count": 1 } }
```

- **The caller's identity is the token and nothing else.** The body has no field that can name a user; one sent anyway is ignored rather than rejected, because there is nothing for it to reach. Two independent things hold that: `widget.Ask` discards whatever identity filter the model produced and substitutes the id this repo verified from the token, and the id itself comes from `RequireAuth` rather than from anything the request can carry. A body that tries to name someone else is the case the tests pin.
- **`answer` is rendered, not composed.** `widget.Config.Composer` is left nil deliberately, so cryden falls back to `RenderResult` — a deterministic plain-text table over rows that have already been scoped to this one user. Supplying a composer would mean a second model call per question whose output nothing validates, to turn a table into prose. That is worth doing deliberately if it is ever wanted; it is not a default to fall into.
- **`allowed_origins` is defense in depth, not the boundary.** The Bearer token is the boundary and it is verified first. `Origin` is a header a browser sets and anything that is not a browser sets freely, which is why a request carrying *no* Origin is allowed: refusing it would break every non-browser client — the console, a mobile app, a test — while stopping nobody, since whoever can forge an allowlisted origin can also omit it. What the check does buy is a guard against a stray embed on a site nobody meant to authorise, which would otherwise put one user's answers in front of whoever is browsing that page. Origins are compared on scheme and host with the default port normalised away, so `https://console.example.com:443` and `https://console.example.com` are the same entry rather than one that silently never matches.
- **Settings are read per question, not cached behind an invalidation.** Three short reads and two AES-GCM opens against one model call that takes hundreds of milliseconds at best — the trade is lopsided, and the failure mode of the other side is a saved settings change that does not take effect until a restart, or takes effect only if every future writer remembers to poke a hook. What *is* cached is the built provider pair, keyed on a SHA-256 digest of the settings it was built from. Hashed rather than held, because two of the three inputs are credentials and a cache key lives as long as the process does.
- **Building the provider is cheap on purpose.** `aiprovider.NewPostgresSnapshot` uses `sql.Open`, which does not connect, so a rebuild is an allocation rather than a round trip and a stored connection that has since gone bad is reported by the query that uses it. That is what keeps a broken setting from being a startup failure.
- **Switched off and never configured are one answer** — `404 ask_ai_widget_disabled`. The stored config's zero value is disabled, so there is no way to tell them apart, and there is no reason a caller should care. `404 not_configured` is the different case: the widget is on but the deployment has no LLM provider or no read-only database stored.
- **It costs money per question and is not rate-limited per user.** It is bounded only by `EDGE_RATE_LIMIT`, which counts requests per edge, not per account. A real per-user limit needs a policy this repo has not decided — the numbers are deployment-specific — so it is recorded as owed in `PROGRESS.md` rather than invented here.

## Design notes

- `CORS_ORIGINS` is required, no wildcard default — an API handling auth tokens should never allow every origin.
- `consoleEmailSender` (in `email_sender.go`) is a dev stand-in — logs verification tokens to the console instead of sending real email. Replace with a real provider (Resend, SES, SendGrid) before real users depend on email verification. Set `EMAIL_TEMPLATE_DIR` and it renders your own `verification.txt` / `magic_link.txt` (`text/template`, fields `{{.To}}`, `{{.Token}}`, `{{.URL}}`) instead of its built-in line; cryden owns no message copy on purpose, so templates are entirely this repo's — see `templates/`.
- Every engine error is mapped to a stable `(status, code)` pair in `httpapi/errors.go` — add new engine errors there once, every handler benefits. `*auth.ErrOAuthEmailConflict` is the one non-sentinel case in that file (it's a struct carrying `Email`/`Provider`, unwrapped via `errors.As` rather than `errors.Is`).
- The OAuth linking flow's HMAC-signed cookie (`oauth_handlers.go`) is genuinely new plumbing, not copied from an existing pattern elsewhere in this repo — worth reading closely if you're touching that code, not just trusting it because it compiles.
- A paused login is a `200`, not an error: nothing failed, the caller just has one more step. `httpapi/second_factor.go` is the one place that response shape is written.
- `DELETE /v1/passkeys/{credentialID}` takes a JSON body (`{"password": "..."}`) — the password is re-confirmation, so a stolen access token alone cannot weaken an account's own auth requirements.
- Passkey ceremony options and the browser's credential response travel as raw JSON (an object, not a JSON-encoded string), since that is exactly what `navigator.credentials.create()`/`.get()` produce and consume.
- **Six of this repo's tables are not cryden's and never will be**: `user_metadata`, `webhook_deliveries`, `shipped_log_events`, `digest_runs`, `settings` and `reviewed_anomalies`. cryden calls an interface and moves on; it keeps no queryable history of what a sender or a logger did, no schedule, no run record, no configuration storage, and no record of a person having read one of its events — and `store.User` has no metadata concept on purpose. Each lives in its own package (`usermeta/`, `webhook/`, `shiplog/`, `digest/`, `settings/`, `anomalyreview/`) with a Postgres store and an in-memory double behind one interface, mirroring the `store/interfaces.go` + `store/memory` + `store/postgres` split cryden itself uses — which is what makes an endpoint over them testable with no database. `reviewed_anomalies` is the one that carries a foreign key back into cryden's schema (`event_id → audit_events(id)`), deliberately: it is the only way this repo can tell a real flagged event from a fabricated id, since the engine has no lookup by event id.
- **The admin surface is read-only by default, and every write on it is a named exception.** `GET /v1/admin/webhooks/deliveries` and `GET /v1/admin/logging/recent` report; neither offers a "retry this delivery" button, a "replay this event", or any way to write a log record or a delivery row. That is the same rule cryden's AI admin tools are built under, carried across the repo boundary: an operator reads the state of the system, and every change to it goes through the explicit path that owns that change (or through the receiving system, for a delivery). Adding a write here is a design change, not a convenience, and there are exactly three of them. `PUT`/`DELETE /v1/admin/users/{userID}/metadata/{key}` writes per-user metadata, which becomes JWT claims — the write *is* the feature, and a read-only version of it would do nothing. `PUT /v1/admin/anomalies/{eventID}` records an operator's judgement about an event the engine flagged, keyed on the audit event id; it takes no action on any account, which is why it is a record rather than an exception. `PUT`/`DELETE /v1/admin/settings/*` is a settings save, the "a human still saves it" half of the pre-fill rule, not an action any AI tool can reach; its credentials are encrypted at rest and it is the only place in this API that stores one. All three are an operator acting deliberately on a named thing, and none is reachable from an AI feature — no tool holds a reference to any of these handlers, and the engine's interfaces carry no method that could call one. If you are adding a write under `/v1/admin` that is none of these, the answer is no.
- `webhook_deliveries.id` is a `BIGSERIAL` surrogate key rather than the natural key you might expect. The event id it corresponds to **can be empty** — cryden generates it with `crypto/rand` and deliberately delivers an event without one rather than dropping it — and a delivery log whose primary key could be blank is a log that loses exactly the rows you would most want to see. The engine's own id is recorded beside it as `event_id` and is used for the receiver's idempotency.
- This repo has **no graceful shutdown**, and as of this tier that is a stated gap rather than an unnoticed one: `main.go` ends at `log.Fatal(http.ListenAndServe(...))`, so the webhook worker's context is never cancelled and the shipped-events sink has no flush-and-exit path. Both were built so that adding one later is a change to `main.go` alone — the worker takes a `context.Context`, which today is `context.Background()`. The sink writes synchronously for the same reason: a buffered sink with no shutdown path drops its last records on a crash.

## License

MIT
