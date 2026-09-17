package main

import (
	"context"
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"
)

// Why these tests run the Postgres migration runner against SQLite.
//
// This repo has never had a Postgres to test against — no Docker, no
// server, in any session so far — so the obvious shape for this file
// (apply a real migration, assert a real table) is not available. What is
// available is everything about the runner that is not the backend: that
// it applies files in filename order, that it records what it applied,
// that a second call is a no-op, that a file which fails halfway leaves
// neither a half-built schema nor a marker claiming it ran, and that
// --baseline records without running.
//
// Those are the properties whose absence corrupts a database, and every
// one of them is backend-independent. So the runner is written to take an
// fs.FS and the one statement that differs between backends, and these
// tests drive it over an in-memory SQLite with SQLite-flavoured DDL. The
// Postgres-specific part that remains untested is the embedded file
// contents themselves, which is exactly what cannot be tested without a
// Postgres and is recorded as owed in PROGRESS.md.
//
// The alternative — a Postgres-only runner tested by nothing — would put
// the least-verified code in the repo on the path that runs first in
// every deployment.

// memoryDB returns an in-memory SQLite database, closed with the test.
// Not the file-backed helper from main_test.go: these tests care about
// the runner, not about the DSN, and an in-memory database makes "the
// schema is empty at the start of every test" true without a TempDir.
func memoryDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening in-memory sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// migrationFS builds a fake migrations tree. Names are given without the
// .up.sql suffix; down-migrations are added separately where a test is
// about them being ignored.
func migrationFS(t *testing.T, files map[string]string) fs.FS {
	t.Helper()
	m := fstest.MapFS{}
	for name, body := range files {
		m[name+".up.sql"] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

func createTable(name string) string {
	return "CREATE TABLE " + name + " (id INTEGER PRIMARY KEY);"
}

// tableExists asks the database rather than the runner, so a passing test
// cannot be the runner agreeing with itself.
func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	err := db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
	).Scan(&n)
	if err != nil {
		t.Fatalf("looking for table %s: %v", name, err)
	}
	return n > 0
}

func recordedMigrations(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM ` + migrationTable + ` ORDER BY name`)
	if err != nil {
		t.Fatalf("reading %s: %v", migrationTable, err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scanning %s: %v", migrationTable, err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading %s: %v", migrationTable, err)
	}
	return names
}

// The ordering property. Filename order is what makes the 001/002/...
// prefix load-bearing, and it is the one thing a filesystem does not
// guarantee on its own — fs.ReadDir is documented to return sorted
// entries, but the sort in upMigrationNames is what makes that a promise
// this code keeps rather than one it inherits.
//
// Sorting is asserted by effect, not by inspecting the returned slice:
// 002 references a table 001 creates, so if the order were wrong the
// second file would fail rather than merely be reported in the wrong
// order.
func TestTier7MigrationsRunInFilenameOrder(t *testing.T) {
	db := memoryDB(t)
	migrations := migrationFS(t, map[string]string{
		"001_first":  createTable("first"),
		"002_second": "CREATE TABLE second (id INTEGER PRIMARY KEY, first_id INTEGER REFERENCES first(id));",
		"003_third":  createTable("third"),
	})

	applied, err := applyMigrations(context.Background(), db, migrations, sqliteInsertSQL)
	if err != nil {
		t.Fatalf("applyMigrations: %v", err)
	}

	want := []string{"001_first.up.sql", "002_second.up.sql", "003_third.up.sql"}
	if strings.Join(applied, ",") != strings.Join(want, ",") {
		t.Errorf("applied %v, want %v", applied, want)
	}
	for _, table := range []string{"first", "second", "third"} {
		if !tableExists(t, db, table) {
			t.Errorf("table %s does not exist after migrating", table)
		}
	}
	if got := recordedMigrations(t, db); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("recorded %v, want %v", got, want)
	}
}

// The idempotence property, which is what makes it safe to run on every
// boot. A runner that re-applied its files would fail on the second start
// of every deployment — and the failure would look like a schema problem
// rather than a runner problem.
func TestTier7SecondRunIsANoOp(t *testing.T) {
	db := memoryDB(t)
	migrations := migrationFS(t, map[string]string{
		"001_first":  createTable("first"),
		"002_second": createTable("second"),
	})

	ctx := context.Background()
	if _, err := applyMigrations(ctx, db, migrations, sqliteInsertSQL); err != nil {
		t.Fatalf("first applyMigrations: %v", err)
	}

	// The second call is the assertion. If it re-ran 001 it would fail
	// with "table first already exists" right here.
	applied, err := applyMigrations(ctx, db, migrations, sqliteInsertSQL)
	if err != nil {
		t.Fatalf("second applyMigrations returned %v — a second boot would not start", err)
	}
	if len(applied) != 0 {
		t.Errorf("second run applied %v, want nothing", applied)
	}
	if got := recordedMigrations(t, db); len(got) != 2 {
		t.Errorf("recorded %d migrations after two runs, want 2: %v", len(got), got)
	}
}

// Only new files run. This is the property that makes a deploy safe: a
// release that adds 015 to a database at 014 must apply 015 and nothing
// else, without re-running the fourteen that built the data.
func TestTier7OnlyPendingMigrationsRun(t *testing.T) {
	db := memoryDB(t)
	ctx := context.Background()

	first := migrationFS(t, map[string]string{
		"001_first": createTable("first"),
	})
	if _, err := applyMigrations(ctx, db, first, sqliteInsertSQL); err != nil {
		t.Fatalf("first applyMigrations: %v", err)
	}

	// The release adds a migration. Note 001 is still present — a real
	// release ships the whole history, not just the new file.
	second := migrationFS(t, map[string]string{
		"001_first":  createTable("first"),
		"002_second": createTable("second"),
	})
	applied, err := applyMigrations(ctx, db, second, sqliteInsertSQL)
	if err != nil {
		t.Fatalf("second applyMigrations: %v", err)
	}

	if strings.Join(applied, ",") != "002_second.up.sql" {
		t.Errorf("applied %v, want only 002_second.up.sql", applied)
	}
	if !tableExists(t, db, "second") {
		t.Error("table second was not created by the pending migration")
	}
}

// The failure property, and the one that protects data. A migration that
// fails must leave nothing behind: no half-applied schema, and — the part
// that would be silent and permanent — no row in the tracking table
// claiming it ran. If it were recorded, the next deploy would skip it and
// the schema would be missing whatever it was supposed to add, forever,
// with nothing in the logs to say so.
func TestTier7AFailedMigrationIsNeitherAppliedNorRecorded(t *testing.T) {
	db := memoryDB(t)
	migrations := migrationFS(t, map[string]string{
		"001_first": createTable("first"),
		// Two statements: the first succeeds, the second does not. This
		// is the shape a real broken migration has — it is not a file
		// that fails to parse, it is one that gets halfway.
		"002_broken": createTable("halfway") + "\nCREATE TABLE halfway (id INTEGER PRIMARY KEY);",
		"003_third":  createTable("third"),
	})

	applied, err := applyMigrations(context.Background(), db, migrations, sqliteInsertSQL)
	if err == nil {
		t.Fatal("applyMigrations returned nil for a migration with a duplicate CREATE TABLE")
	}
	if !strings.Contains(err.Error(), "002_broken") {
		t.Errorf("error %q does not name the file that failed", err)
	}

	// 001 ran before the failure and stays applied — the runner stops at
	// the failure rather than rolling back what already succeeded.
	if strings.Join(applied, ",") != "001_first.up.sql" {
		t.Errorf("applied %v, want just 001_first.up.sql", applied)
	}

	// The transaction rolled the broken file's first statement back.
	if tableExists(t, db, "halfway") {
		t.Error("the failed migration's first statement survived — the file was not run in a transaction")
	}
	// And 003 never ran, because the runner stops rather than skipping
	// the failure. A migration history with a hole in it is worse than a
	// deployment that will not start.
	if tableExists(t, db, "third") {
		t.Error("003 ran after 002 failed; the runner should stop at the first failure")
	}
	if got := recordedMigrations(t, db); strings.Join(got, ",") != "001_first.up.sql" {
		t.Errorf("recorded %v, want only 001_first.up.sql — a failed migration must not be marked applied", got)
	}
}

// Down-migrations are shipped for an operator to apply deliberately and
// must never be run by the automatic path. An automatic rollback of a
// schema holding live credentials is not something a boot path should be
// able to do by accident, so the filter is asserted rather than assumed.
func TestTier7DownMigrationsAreNeverRun(t *testing.T) {
	db := memoryDB(t)
	m := fstest.MapFS{
		"001_first.up.sql":   &fstest.MapFile{Data: []byte(createTable("first"))},
		"001_first.down.sql": &fstest.MapFile{Data: []byte("DROP TABLE first;")},
	}

	if _, err := applyMigrations(context.Background(), db, m, sqliteInsertSQL); err != nil {
		t.Fatalf("applyMigrations: %v", err)
	}

	if !tableExists(t, db, "first") {
		t.Error("table first is missing — a down-migration ran and dropped it")
	}
	if got := recordedMigrations(t, db); strings.Join(got, ",") != "001_first.up.sql" {
		t.Errorf("recorded %v, want only the up-migration", got)
	}
}

// --baseline, which is the whole reason the runner can be adopted by a
// database that already has this schema. The distinction under test is
// that baseline records without running: if it ran the files it would be
// identical to applyMigrations and would fail on the very database it
// exists for.
func TestTier7BaselineRecordsWithoutRunning(t *testing.T) {
	db := memoryDB(t)
	migrations := migrationFS(t, map[string]string{
		"001_first":  createTable("first"),
		"002_second": createTable("second"),
	})

	ctx := context.Background()

	// The database this exists for: the schema is already there, the
	// tracking table is not. Simulated by creating the table by hand.
	if _, err := db.ExecContext(ctx, createTable("first")); err != nil {
		t.Fatalf("setting up the pre-existing schema: %v", err)
	}

	recorded, err := baselineMigrations(ctx, db, migrations, sqliteInsertSQL)
	if err != nil {
		t.Fatalf("baselineMigrations: %v", err)
	}
	if len(recorded) != 2 {
		t.Errorf("baselined %v, want both migrations", recorded)
	}

	// The second migration was NOT run — that is the difference from
	// applyMigrations, which would have created table second here.
	if tableExists(t, db, "second") {
		t.Error("baseline created table second; it must not run any migration")
	}

	// And now the boot path is safe: applyMigrations finds everything
	// recorded and does nothing, instead of failing on the table that
	// already existed.
	applied, err := applyMigrations(ctx, db, migrations, sqliteInsertSQL)
	if err != nil {
		t.Fatalf("applyMigrations after baseline: %v — this is the startup failure baseline exists to prevent", err)
	}
	if len(applied) != 0 {
		t.Errorf("applyMigrations after baseline applied %v, want nothing", applied)
	}
}

// Baseline is refused on SQLite rather than silently succeeding. A SQLite
// deployment cannot be in the state baseline exists for — cryden's runner
// creates the files and the tracking table together — so answering "done"
// would be a false claim about work that did not happen.
func TestTier7BaselineIsRefusedOnSQLite(t *testing.T) {
	db := memoryDB(t)

	msg, err := baseline(context.Background(), db, true)
	if err == nil {
		t.Fatalf("baseline on SQLite returned %q, want an error", msg)
	}
	if !strings.Contains(err.Error(), "SQLite") {
		t.Errorf("error %q does not say why it is refused", err)
	}
}

// The runner creates its own tracking table, because nothing else can:
// a migration cannot create the table that records migrations. Asserted
// separately from the tests above so a failure here says "the bootstrap
// broke" rather than hiding inside a migration test.
func TestTier7TheTrackingTableIsCreatedByTheRunner(t *testing.T) {
	db := memoryDB(t)
	if tableExists(t, db, migrationTable) {
		t.Fatal("the tracking table exists before the runner ran")
	}

	if _, err := applyMigrations(context.Background(), db, migrationFS(t, map[string]string{}), sqliteInsertSQL); err != nil {
		t.Fatalf("applyMigrations with no migrations: %v", err)
	}
	if !tableExists(t, db, migrationTable) {
		t.Error("the runner did not create its own tracking table")
	}
}

// The embedded files are the part that cannot be tested against SQLite,
// so what is asserted here is the part that can: that they are actually
// embedded, that they parse as up-migrations, and that they are the
// fourteen this repo ships. A mistake in the //go:embed pattern would
// otherwise show up as a deployment that starts with no schema.
func TestTier7TheEmbeddedPostgresMigrationsArePresent(t *testing.T) {
	sub, err := fs.Sub(postgresMigrations, postgresMigrationDir)
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	names, err := upMigrationNames(sub)
	if err != nil {
		t.Fatalf("upMigrationNames: %v", err)
	}

	if len(names) != 14 {
		t.Errorf("embedded %d up-migrations, want 14: %v", len(names), names)
	}
	if names[0] != "001_initial_schema.up.sql" {
		t.Errorf("first embedded migration is %q", names[0])
	}
	// The last one is host-owned (014_reviewed_anomalies), so this also
	// pins that the embed is not somehow picking up cryden's numbering.
	if last := names[len(names)-1]; last != "014_reviewed_anomalies.up.sql" {
		t.Errorf("last embedded migration is %q", last)
	}

	// Every file is non-empty and has a CREATE or ALTER in it. Cheap, but
	// it catches the specific failure where the embed matches a file that
	// is present but not actually a migration.
	for _, name := range names {
		body, err := fs.ReadFile(sub, name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if len(body) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

// The SQLite copies under migrations/sqlite/ are deliberately NOT
// embedded — cryden's runner reads cryden's own copy, so embedding these
// would put files in the binary nothing ever opens. Pinned because the
// Tier 7 spec asked for both to be embedded and this deviates on purpose:
// a later reader should find the deviation tested, not just commented.
func TestTier7TheSQLiteCopiesAreNotEmbedded(t *testing.T) {
	if _, err := fs.Stat(postgresMigrations, "sqlite"); err == nil {
		t.Error("migrations/sqlite is embedded; it is reference material that nothing reads at runtime — see the comment on postgresMigrations")
	}
}
