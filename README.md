# api

A generic HTTP wrapper around [CrydenSync](https://github.com/crydensync/cryden) — self-hosted, not a hosted multi-tenant service. Deploy your own instance next to your own Postgres; this is not a shared server other people's apps connect to.

Every consumer talks to this over plain HTTP — no Go required. This is what a JS/Python SDK calls under the hood, and what you can call directly with `curl`/`fetch` in the meantime.

## Prerequisites

- Go 1.22+ (check `go.mod` for exact version)
- A running Postgres instance (local, Docker, or hosted — e.g. Supabase, Neon, RDS)

## Getting started

```bash
git clone https://github.com/crydensync/api
cd api
cp .env.example .env   # fill in DATABASE_URL, JWT_SECRET, CORS_ORIGINS
go run .
```

Run the migrations in `migrations/` against your database first, in order (copies of CrydenSync's own migrations, kept here so this repo is self-contained for local dev and CI — same as `typebook` keeps its own copy). `002_oauth_identities` is required even if you don't use OAuth yet — `NewOAuthStore` is wired into the engine config unconditionally. `004` through `008` are the TOTP, WebAuthn, recovery-code, login-attempt and API-key tables; run them even if you leave `ENCRYPTION_KEY` unset, since `007` is what the engine's credential-stuffing detection reads once Tier 2 wires it up and `008` is what the API-key work will use.

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
```

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

## Design notes

- `CORS_ORIGINS` is required, no wildcard default — an API handling auth tokens should never allow every origin.
- `consoleEmailSender` (in `email_sender.go`) is a dev stand-in — logs verification tokens to the console instead of sending real email. Replace with a real provider (Resend, SES, SendGrid) before real users depend on email verification.
- Every engine error is mapped to a stable `(status, code)` pair in `httpapi/errors.go` — add new engine errors there once, every handler benefits. `*auth.ErrOAuthEmailConflict` is the one non-sentinel case in that file (it's a struct carrying `Email`/`Provider`, unwrapped via `errors.As` rather than `errors.Is`).
- The OAuth linking flow's HMAC-signed cookie (`oauth_handlers.go`) is genuinely new plumbing, not copied from an existing pattern elsewhere in this repo — worth reading closely if you're touching that code, not just trusting it because it compiles.
- A paused login is a `200`, not an error: nothing failed, the caller just has one more step. `httpapi/second_factor.go` is the one place that response shape is written.
- `DELETE /v1/passkeys/{credentialID}` takes a JSON body (`{"password": "..."}`) — the password is re-confirmation, so a stolen access token alone cannot weaken an account's own auth requirements.
- Passkey ceremony options and the browser's credential response travel as raw JSON (an object, not a JSON-encoded string), since that is exactly what `navigator.credentials.create()`/`.get()` produce and consume.

## License

MIT
