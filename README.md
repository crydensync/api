# api

A generic HTTP wrapper around [CrydenSync](https://github.com/crydensync/cryden) — self-hosted, not a hosted multi-tenant service. Deploy your own instance next to your own Postgres; this is not a shared server other people's apps connect to.

Every consumer talks to this over plain HTTP — no Go required. This is what a JS/Python SDK calls under the hood, and what you can call directly with `curl`/`fetch` in the meantime.

## Setup

```bash
cp .env.example .env   # fill in DATABASE_URL, JWT_SECRET, CORS_ORIGINS
go run .
```

Run the migration in `migrations/0001_initial_schema.up.sql` against your database first (this is a copy of CrydenSync's own migration, kept here so this repo is self-contained for local dev and CI — same as `typebook` keeps its own copy).

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
GET    /v1/health
```

Authenticated endpoints expect `Authorization: Bearer <access_token>`.

## Design notes

- `CORS_ORIGINS` is required, no wildcard default — an API handling auth tokens should never allow every origin.
- `consoleEmailSender` (in `email_sender.go`) is a dev stand-in — logs verification tokens to the console instead of sending real email. Replace with a real provider (Resend, SES, SendGrid) before real users depend on email verification.
- Every engine error is mapped to a stable `(status, code)` pair in `httpapi/errors.go` — add new engine errors there once, every handler benefits.

## License

MIT
