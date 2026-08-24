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

Run the migrations in `migrations/` against your database first (copies of CrydenSync's own migrations, kept here so this repo is self-contained for local dev and CI — same as `typebook` keeps its own copy). `002_oauth_identities` is required even if you don't use OAuth yet — `NewOAuthStore` is wired into the engine config unconditionally.

OAuth is optional. To enable a provider, set its client ID/secret plus `BASE_URL` (used to build the callback URL registered in that provider's console):

```
BASE_URL=https://api.example.com
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

A provider missing its client ID or secret is simply unavailable — its endpoints return `404 oauth_provider_not_configured` rather than the server refusing to start.

## Rate limiting

Two independent layers:
- **Engine-level** (per-user, on login/signup specifically) — already built into CrydenSync itself, protects against credential stuffing.
- **Edge-level** (per-IP, applied to every request) — coarser, protects the whole API surface from being hammered generally. Configurable via `EDGE_RATE_LIMIT` (default 100 requests/minute per IP). In-memory, per-process — like the engine's own limiter, this does NOT share state across multiple instances behind a load balancer. Fine for a single instance; a Redis-backed version is the natural upgrade path once you scale horizontally.

## Response contract

Every response follows one of two shapes:

```json
// success
{ "data": { ... } }

// error
{ "error": { "code": "invalid_credentials", "message": "invalid email or password" } }
```

`code` is the stable string to branch on programmatically. `message` is for humans — never parse it.

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
```

`{provider}` is `google` or `github`. The two OAuth flows are separate
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

## License

MIT
