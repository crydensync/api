package main

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2/store/sqlite"
)

// postgresMigrations is this repo's own Postgres schema, compiled into the
// binary so a released artifact never needs the source tree beside it.
//
// Exactly one of this repo's two migration directories is embedded, and
// which one is not is worth stating: migrations/sqlite/ is deliberately
// absent. cryden ships a runner for SQLite that reads cryden's *own*
// embedded copy of those files, and main.go calls that — so this repo's
// copies under migrations/sqlite/ are reference material for a human
// reading the schema, and embedding them would put files in the binary
// that nothing ever opens. See that directory's README.md.
//
// The consequence to know: a table this repo adds for SQLite has to be
// applied by this repo, because cryden's runner only ever reads cryden's
// files. There is no such table today — every table this repo owns is
// Postgres-only, which is what makes the admin console 501 on SQLite.
//
//go:embed migrations/*.sql
var postgresMigrations embed.FS

// postgresMigrationDir is where the embedded files live inside the FS
// above. Named once because the test FS has to mirror it.
const postgresMigrationDir = "migrations"

// migrationTable is the Postgres tracking table: one row per applied file.
//
// The name is unprefixed, unlike cryden's SQLite table
// (cryden_schema_migrations), and cryden's own comment gives the reason —
// a SQLite database is very often an application's only database and is
// shared with the host's other tables, so the prefix is doing real work
// there. A dedicated Postgres database is this repo's, so the plain name
// is the honest one and matches what a Postgres operator already expects
// from Flyway, golang-migrate and friends.
//
// The DDL below is written to run on both backends unchanged: TEXT and
// PRIMARY KEY mean the same thing on each, and applied_at is RFC3339 text
// rather than a TIMESTAMPTZ so the statement needs no per-backend variant.
// That is not decoration — it is what lets the ordering, recording and
// rollback logic be tested without a Postgres, which this repo has never
// had in its environment. See migrate_test.go.
const migrationTable = "schema_migrations"

// insertMigrationSQL is the *only* statement the runner issues that is not
// portable: lib/pq numbers its placeholders and SQLite does not. Passing
// it in rather than branching on a driver name is what keeps the rest of
// the runner backend-agnostic.
const (
	postgresInsertSQL = `INSERT INTO ` + migrationTable + ` (name, applied_at) VALUES ($1, $2)`
	sqliteInsertSQL   = `INSERT INTO ` + migrationTable + ` (name, applied_at) VALUES (?, ?)`
)

// createMigrationTableSQL is one statement for both backends, per the note
// on migrationTable.
const createMigrationTableSQL = `
	CREATE TABLE IF NOT EXISTS ` + migrationTable + ` (
		name       TEXT PRIMARY KEY NOT NULL,
		applied_at TEXT NOT NULL
	)
`

// applyMigrations applies every up-migration in migrations that has not run
// against db yet, in filename order, and records each one so a second call
// is a no-op. It returns the names it applied, in order, so the caller can
// say what happened rather than only that something did.
//
// The design follows cryden's own SQLite runner closely — same tracking
// table shape, same filename ordering, same one-transaction-per-file,
// same "up only" rule — because a host running both backends should not
// have to hold two different mental models of what "migrated" means.
//
// Each file is executed as a single string, so the driver must accept
// multiple statements in one Exec. Both do: lib/pq takes its simple-query
// path when an Exec has no arguments (conn.go: `if len(args) == 0`), and
// every SQLite driver does. Splitting on semicolons instead would be the
// bug this avoids — it breaks on dollar-quoted function bodies and on a
// semicolon inside a string literal.
//
// Each file also runs inside its own transaction. Postgres DDL is
// transactional, so a file that fails halfway leaves no half-built schema
// and no marker claiming it ran.
func applyMigrations(ctx context.Context, db *sql.DB, migrations fs.FS, insertSQL string) ([]string, error) {
	if _, err := db.ExecContext(ctx, createMigrationTableSQL); err != nil {
		return nil, fmt.Errorf("creating %s: %w", migrationTable, err)
	}

	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return nil, err
	}

	names, err := upMigrationNames(migrations)
	if err != nil {
		return nil, err
	}

	var did []string
	for _, name := range names {
		if applied[name] {
			continue
		}
		body, err := fs.ReadFile(migrations, name)
		if err != nil {
			return did, fmt.Errorf("reading migration %s: %w", name, err)
		}
		if err := applyOne(ctx, db, name, string(body), insertSQL); err != nil {
			return did, err
		}
		did = append(did, name)
	}
	return did, nil
}

func applyOne(ctx context.Context, db *sql.DB, name, body, insertSQL string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("applying migration %s: %w", name, err)
	}
	defer tx.Rollback() // no-op once Commit succeeds

	if _, err := tx.ExecContext(ctx, body); err != nil {
		return fmt.Errorf("applying migration %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx, insertSQL, name, formatMigrationTime(time.Now())); err != nil {
		return fmt.Errorf("recording migration %s: %w", name, err)
	}
	return tx.Commit()
}

// baselineMigrations records every embedded up-migration as applied
// without running any of them, and returns the names it recorded.
//
// It exists for exactly one situation, and it is not a rare one: a
// database that already has this schema, applied by hand or by CI, before
// this binary grew a runner. That database has no tracking table, so
// applyMigrations would start at 001 and die on
// `relation "users" already exists` — a deployment that cannot start,
// caused by the feature meant to make starting easier.
//
// It is a separate, explicit command rather than something the boot path
// detects, because the alternative is guessing. "The tracking table is
// missing but users exists, so assume everything ran" is right for the
// case above and silently wrong for a database that is genuinely
// half-migrated — it would mark unrun migrations as applied and the next
// deploy would look for columns that were never created. An operator
// saying so once is the only version of this that cannot be wrong about
// someone's data.
//
// A baselined row is indistinguishable from an applied one afterwards.
// That is deliberate: nothing today needs to tell them apart, and a
// column marking it would be a schema change to the tracking table for a
// question nobody is asking. If that changes, it is the obvious
// extension.
func baselineMigrations(ctx context.Context, db *sql.DB, migrations fs.FS, insertSQL string) ([]string, error) {
	if _, err := db.ExecContext(ctx, createMigrationTableSQL); err != nil {
		return nil, fmt.Errorf("creating %s: %w", migrationTable, err)
	}

	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return nil, err
	}

	names, err := upMigrationNames(migrations)
	if err != nil {
		return nil, err
	}

	var did []string
	now := formatMigrationTime(time.Now())
	for _, name := range names {
		if applied[name] {
			continue
		}
		if _, err := db.ExecContext(ctx, insertSQL, name, now); err != nil {
			return did, fmt.Errorf("recording migration %s: %w", name, err)
		}
		did = append(did, name)
	}
	return did, nil
}

func appliedMigrations(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM `+migrationTable)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", migrationTable, err)
	}
	defer rows.Close()

	applied := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		applied[name] = true
	}
	return applied, rows.Err()
}

// upMigrationNames returns the up-migrations sorted by filename, which is
// what makes the 001/002/... prefix load-bearing rather than decorative.
// Down-migrations are shipped for an operator to apply deliberately and
// are never run from here — an automatic rollback of a schema holding live
// credentials is not a thing this should be able to do by accident.
func upMigrationNames(migrations fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(migrations, ".")
	if err != nil {
		return nil, fmt.Errorf("reading embedded migrations: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// formatMigrationTime is RFC3339 in UTC. A constant format matters more
// than which one: these values are written by one backend and read by
// nobody, so the only real requirement is that they compare as strings.
func formatMigrationTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// migrate brings the configured database up to date and returns a
// human-readable line about what it did.
//
// This is the one place that knows the two backends differ, and the
// difference is not cosmetic: Postgres migrations are this repo's own and
// are applied by the runner above, while SQLite migrations are cryden's
// own and are applied by cryden's runner. Neither backend applies the
// other's files, and a table this repo adds for SQLite would need this
// repo to grow an apply step for it — see postgresMigrations' comment.
func migrate(ctx context.Context, db *sql.DB, usesSQLite bool) (string, error) {
	if usesSQLite {
		// cryden owns the SQLite schema and ships the runner for it, so
		// this calls that rather than applying this repo's copy under
		// migrations/sqlite/. It is also idempotent by design, so there is
		// no baseline equivalent here: a SQLite deployment's files and its
		// tracking table could only ever have been written together.
		if err := sqlite.Migrate(ctx, db); err != nil {
			return "", fmt.Errorf("sqlite migration: %w", err)
		}
		return "sqlite schema is up to date (applied by cryden's own runner)", nil
	}

	sub, err := fs.Sub(postgresMigrations, postgresMigrationDir)
	if err != nil {
		return "", fmt.Errorf("reading embedded migrations: %w", err)
	}
	applied, err := applyMigrations(ctx, db, sub, postgresInsertSQL)
	if err != nil {
		return "", err
	}
	if len(applied) == 0 {
		return "postgres schema is up to date (no pending migrations)", nil
	}
	return fmt.Sprintf("postgres: applied %d migration(s): %s",
		len(applied), strings.Join(applied, ", ")), nil
}

// baseline is the operator escape hatch described on baselineMigrations.
// It is refused on SQLite rather than being a no-op there: a SQLite
// deployment cannot have the problem it solves, so answering "done"
// would be a lie about work that did not happen.
func baseline(ctx context.Context, db *sql.DB, usesSQLite bool) (string, error) {
	if usesSQLite {
		return "", errors.New("--baseline is for a Postgres database that already has this schema; a SQLite deployment is migrated by cryden's runner, which cannot be in that state")
	}

	sub, err := fs.Sub(postgresMigrations, postgresMigrationDir)
	if err != nil {
		return "", fmt.Errorf("reading embedded migrations: %w", err)
	}
	recorded, err := baselineMigrations(ctx, db, sub, postgresInsertSQL)
	if err != nil {
		return "", err
	}
	if len(recorded) == 0 {
		return "nothing to baseline: every embedded migration is already recorded", nil
	}
	return fmt.Sprintf("baselined %d migration(s) as applied without running them: %s",
		len(recorded), strings.Join(recorded, ", ")), nil
}
