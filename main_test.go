package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/sqlite"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/httpapi"
)

// testPassword is the same value the httpapi fixtures use — long enough to
// clear cryden's policy, and a constant so nothing here depends on a
// generated secret.
const testPassword = "correct-horse-battery-staple-42"

// openTestSQLite builds the database exactly as main.go does for a SQLite
// deployment — the same DSN helper, the same migrate-then-check order —
// because the point of these tests is that that path works, not that some
// equivalent one does.
func openTestSQLite(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	t.Cleanup(func() { db.Close() })

	if err := sqlite.Migrate(context.Background(), db); err != nil {
		t.Fatalf("sqlite.Migrate: %v", err)
	}
	if err := sqlite.CheckPragmas(context.Background(), db); err != nil {
		t.Fatalf("sqlite.CheckPragmas: %v", err)
	}
	return db
}

// The DSN is the entire configuration of SQLite's behaviour, and three of
// its parameters are load-bearing rather than decorative: foreign_keys is
// off by default (so the schema's ON DELETE clauses would silently not
// run), busy_timeout is zero by default (so a concurrent writer gets an
// immediate SQLITE_BUSY instead of waiting), and WAL is what lets readers
// proceed during a write.
//
// Pinned as a literal because the spelling is the driver's, not SQLite's:
// this is modernc's `_pragma=name(value)`, and mattn's driver spells the
// same three differently. A change here without a change to the blank
// import in main.go would give a DSN that parses and sets nothing — which
// the test below catches even if this one is updated to match.
func TestTier6SQLiteDSNSetsThePragmasThatMatter(t *testing.T) {
	dsn := sqliteDSN("/var/lib/cryden/api.db")
	for _, want := range []string{
		"file:/var/lib/cryden/api.db",
		"_pragma=foreign_keys(1)",
		"_pragma=busy_timeout(5000)",
		"_pragma=journal_mode(WAL)",
	} {
		if !strings.Contains(dsn, want) {
			t.Errorf("sqliteDSN = %q, want it to contain %q", dsn, want)
		}
	}
}

// The end of the same argument: cryden's own CheckPragmas reads the two it
// can observe back off a live connection, so a DSN that *looks* right in a
// string but does not reach the driver fails here. This is also the test
// that proves the schema applies — Migrate runs all seven of cryden's
// migrations in order, and would fail on the first syntax error.
//
// Migrate is called a second time deliberately: it runs on every boot of
// every SQLite deployment, so "a second call is a no-op" is the normal
// case rather than an edge one. A runner that re-applied its files would
// fail on the first CREATE TABLE.
func TestTier6SQLiteMigratesAndThePragmasSurviveTheDriver(t *testing.T) {
	db := openTestSQLite(t)

	if err := sqlite.Migrate(context.Background(), db); err != nil {
		t.Fatalf("second Migrate (the every-boot path) failed: %v", err)
	}

	// The runner records what it applied, and that table is the evidence
	// that all seven files ran rather than that the call returned.
	var applied int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cryden_schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("reading cryden_schema_migrations: %v", err)
	}
	if applied != 7 {
		t.Errorf("%d migrations recorded, want 7 — cryden's own 0001-0007", applied)
	}
}

// openStores has to return the same set of interfaces on both backends,
// because nothing downstream of it knows which ran. The three Postgres-only
// stores are the one asymmetry, and on SQLite they must be nil rather than
// typed nils or Postgres stores over a SQLite handle — main.go relies on
// that nil to skip wiring the claims provider, and every route that reads
// them answers 501 before it can dereference one.
func TestTier6OpenStoresReturnsEveryEngineStoreOnBothBackends(t *testing.T) {
	sqliteDB := openTestSQLite(t)

	st := openStores(config.Config{SQLitePath: "api.db"}, sqliteDB)
	for name, store := range map[string]any{
		"users":         st.users,
		"sessions":      st.sessions,
		"audit":         st.audit,
		"verifications": st.verifications,
		"oauth":         st.oauth,
		"totp":          st.totp,
		"webauthn":      st.webauthn,
		"recovery":      st.recovery,
		"apiKeys":       st.apiKeys,
		"anomalies":     st.anomalies,
	} {
		if store == nil {
			t.Errorf("%s is nil on SQLite, want a store", name)
		}
	}
	// Asserted field by field rather than through a map[string]any, and
	// that is not a style choice: boxing a nil *operator.Store into an
	// `any` produces a NON-nil interface holding a nil pointer, which is
	// the exact trap main.go's own comments warn about for the interface
	// stores. Compared directly, the pointer's nilness is the thing being
	// asked about.
	if st.operators != nil {
		t.Error("operators is non-nil on SQLite, want nil — its table is Postgres-only")
	}
	if st.metadata != nil {
		t.Error("metadata is non-nil on SQLite, want nil — its table is Postgres-only")
	}
	if st.reviews != nil {
		t.Error("reviews is non-nil on SQLite, want nil — its table is Postgres-only")
	}

	// The Postgres arm is asserted on the same three fields, from a
	// *sql.DB that is never queried: openStores constructs stores and
	// opens nothing, so this needs no database to be reachable. That is
	// the only part of the Postgres path these tests can exercise — there
	// is no Postgres in this environment to run the other six against.
	pg := openStores(config.Config{DatabaseURL: "postgres://user:pw@localhost/db"}, nil)
	if pg.operators == nil || pg.metadata == nil || pg.reviews == nil {
		t.Error("openStores left a Postgres-only store nil on the Postgres arm")
	}
	if pg.users == nil || pg.anomalies == nil {
		t.Error("openStores left an engine store nil on the Postgres arm")
	}
}

// And the claim the whole tier rests on: a SQLite deployment serves core
// auth. Not "the stores construct" — a real engine over those stores, a
// real signup and login, and the resulting token accepted by the real
// route table.
//
// The admin route in the same test is the contrast that makes the first
// half mean something: one deployment, one router, and the end-user
// surface works while the console does not.
func TestTier6CoreAuthServesOnSQLiteWhileTheConsoleDoesNot(t *testing.T) {
	ctx := context.Background()
	db := openTestSQLite(t)
	cfg := config.Config{SQLitePath: "api.db", JWTSecret: "test-secret"}
	st := openStores(cfg, db)

	engine, err := cryden.New(cryden.Config{
		JWTSecret:         cfg.JWTSecret,
		Users:             st.users,
		Sessions:          st.sessions,
		Audit:             st.audit,
		Verifications:     st.verifications,
		OAuth:             st.oauth,
		APIKeys:           st.apiKeys,
		APIKeyPrefix:      "ck",
		EmailSender:       discardSender{},
		MagicLinkSender:   discardSender{},
		AccessTokenClaims: claimsProvider(st.operators, st.metadata),
	})
	if err != nil {
		t.Fatalf("cryden.New over the SQLite stores: %v", err)
	}

	if _, err := cryden.SignUp(ctx, engine, "user@example.com", testPassword, "203.0.113.1"); err != nil {
		t.Fatalf("signup on SQLite: %v", err)
	}
	tokens, err := cryden.Login(ctx, engine, "user@example.com", testPassword, "203.0.113.1", "go-test")
	if err != nil {
		t.Fatalf("login on SQLite: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("login returned no access token")
	}

	router := httpapi.NewRouter(httpapi.Deps{
		Engine: engine,
		DB:     db,
		Config: cfg,
		Users:  st.users,
		Audit:  st.audit,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/verify", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/verify with a real SQLite-issued token = %d, want 200 — body: %s", rec.Code, rec.Body.String())
	}

	// The same token on the console: 501, and not because of anything
	// about this user. They are not an operator and could not be one —
	// there is no operators table to be in.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("GET /v1/admin/users on SQLite = %d, want 501 — body: %s", rec.Code, rec.Body.String())
	}

	// The health endpoint is the one route that reports on the database
	// itself; it must ping the SQLite file rather than a Postgres URL.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/health on a migrated SQLite file = %d, want 200 — body: %s", rec.Code, rec.Body.String())
	}
}

// claimsProvider's nil case is not a nicety: usermeta.ClaimsProvider
// dereferences its metadata store on every login, so handing it a nil
// *PostgresStore through the interface would panic rather than degrade.
// Both halves are pinned — nil when there is nothing to read, a real
// provider when there is.
func TestTier6ClaimsProviderIsNilOnlyWhenThereIsNothingToRead(t *testing.T) {
	if got := claimsProvider(nil, nil); got != nil {
		t.Error("claimsProvider(nil, nil) returned a provider; a SQLite login would panic on the first query")
	}
	// A Postgres deployment has both. The stores are constructed over a
	// nil *sql.DB — ClaimsProvider only stores them, so nothing queries
	// until a login happens, which this test does not do.
	pg := openStores(config.Config{DatabaseURL: "postgres://user:pw@localhost/db"}, nil)
	if got := claimsProvider(pg.operators, pg.metadata); got == nil {
		t.Error("claimsProvider returned nil on the Postgres arm, so no token would carry a role claim")
	}
}

// discardSender is the two notify interfaces cryden needs to build an
// engine at all, satisfied by doing nothing: these tests are about the
// backend, not about delivery, and nothing here reads a mailbox.
type discardSender struct{}

func (discardSender) SendVerification(context.Context, string, string) error { return nil }
func (discardSender) SendMagicLink(context.Context, string, string) error    { return nil }
