# SQLite migrations

Copies of cryden's own SQLite migrations, kept here so this repo is
self-contained — the same reasoning as `migrations/` one directory up, and
the same reasoning `typebook` uses for its own copies.

## These files are not what runs

Read this before assuming they are the SQLite counterpart of `../*.sql`.

On Postgres, the files in `migrations/` are the ones that get applied: an
operator (or CI) pipes them through `psql`, and cryden ships none of its
own because a Postgres deployment already has psql and usually a migration
tool besides.

On SQLite the arrangement is the mirror image. Cryden ships a migration
runner — `sqlite.Migrate(ctx, db)` in `store/sqlite/migrate.go` — which
embeds its own copy of these same files with `//go:embed
migrations/*.sql` and applies them at startup, recording each one in a
`cryden_schema_migrations` table so a second call is a no-op. `main.go`
calls that when `SQLITE_PATH` is set. So **the migrations a SQLite
deployment actually runs come from cryden's embedded copy, not from this
directory** — including on the day cryden adds an `0008` this repo has not
copied yet.

These files are here to be read, diffed and grepped without a trip to the
module cache: what the SQLite schema contains, how it maps cryden's types,
and what a fresh deployment will look like. Treat a change here as a change
to a copy — the source is `store/sqlite/migrations/` in the pinned cryden
version.

## Why they are numbered `0001`–`0007` and not `015`+

`migrations/` (Postgres) runs `001`–`014` and is this repo's own sequence:
every file in it is numbered to continue this repo's history, cryden's
copies included, and this repo's own tables (`003_operators`,
`009_user_metadata`, `010`–`014`) are interleaved among the cryden copies.

These are a different backend's schema, not a later chapter of that
history, so they keep cryden's own filenames verbatim. Renumbering them
would invent a correspondence that does not exist — SQLite `0002` is not
Postgres `002` plus anything, and the two schemas already differ (there is
no `operators` table here at all; see below). Deliberately a straight
7-for-7 copy, not a consolidation into fewer files.

The *runner* leans on that numbering too — it applies files in filename
order, which is what makes the `0001`/`0002`/… prefix load-bearing rather
than decorative.

## What is in them, and what is not

`0001`–`0007` are cryden's own tables only: users, sessions, verification
tokens, audit events, OAuth identities, TOTP secrets, WebAuthn credentials,
recovery codes, login attempts, API keys.

Every table this repo adds is **absent**, and stays absent by decision
(NEXT.md Tier 6): `operators`, `user_metadata`, `webhook_deliveries`,
`shipped_log_events`, `digest_runs`, `settings` and `reviewed_anomalies`
are Postgres-only. That is why the whole admin console answers
`501 not_implemented_on_sqlite` on a SQLite deployment — `RequireAdmin`
itself depends on `operators`, so there is no partial console to offer. See
`httpapi.AdminOnly`.

If this repo ever needs its own SQLite table, it gets its own numbered file
continuing this sequence (`0008_…`) rather than being folded into one of
the cryden copies. That file would also need somewhere to be applied from:
cryden's runner only reads cryden's embedded files, so a repo-owned SQLite
migration needs this repo's own apply step, not just a file in this
directory. Nothing needs one yet; noting it so the first person to add one
does not assume the file is sufficient.

## Down-migrations

The `.down.sql` files are copied for the same completeness reason as
everything else here. Cryden's runner never executes them — an automatic
rollback of a schema holding live credentials is not something that should
be reachable by accident — so a down-migration is applied by hand,
deliberately, by an operator who has decided to.
