package aiprovider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	crydenai "github.com/crydensync/cryden/v2/ai"
)

// ErrNotReadOnly means the supplied role CAN write, so it must not back
// the AI query surface.
var ErrNotReadOnly = errors.New("aiprovider: the database role is not read-only")

// ErrCannotVerifyReadOnly means the check could not reach a conclusion.
// Separate from ErrNotReadOnly on purpose: "this role can write" and "we
// could not find out" call for different words, and the second one is
// almost always a connection problem the operator can fix.
var ErrCannotVerifyReadOnly = errors.New("aiprovider: could not verify the database role is read-only")

// readOnlyProbeTimeout bounds the whole check. It is short because this
// runs inside an HTTP request from a settings form — a check that hangs
// for a minute would look like a broken console, and an operator
// configuring a second database expects a few seconds at most.
const readOnlyProbeTimeout = 10 * time.Second

// probeTable is the scratch table the write attempt targets. It lives in
// pg_temp, the session's own temporary schema, which is what makes this
// check safe to run: the table exists only for the life of this
// connection, is invisible to every other session, and is dropped by
// Postgres when the connection closes — so a failed CREATE leaves nothing
// behind for the operator to clean up.
//
// It is a single-column table with a single row. The point is not the
// data, it is whether the server says yes.
const (
	probeCreate = `CREATE TEMP TABLE cryden_readonly_probe (id int)`
	probeInsert = `INSERT INTO cryden_readonly_probe (id) VALUES (1)`
)

// CheckReadOnly verifies that dsn names a role which cannot write.
//
// This is the check cryden's ai.QueryableStore interface asks for by name:
// "MUST use a read-only Postgres role for this connection — that's a real
// credential-level guarantee, not just a promise made in code, so a bug
// in validation still can't cause a write." The allowlist in ai.validate.go
// is the first line of defence; this is the line that holds when the
// first one has a bug, because a role that cannot INSERT cannot INSERT
// whatever a query builder does with its input.
//
// Which is also why this is checked by *attempting a write and confirming
// it is rejected*, rather than by reading the role's attributes. Trusting
// a checkbox, or pg_roles.rolsuper, or the presence of "readonly" in a
// connection parameter would all be trusting a claim. Only the server's
// refusal is evidence — and it is evidence about the actual role, on the
// actual database, through the actual credentials, which no amount of
// reading metadata can substitute for.
//
// The three outcomes are deliberately distinct:
//
//   - the write is refused  -> nil, the role is read-only
//   - the write succeeds    -> ErrNotReadOnly
//   - anything else         -> ErrCannotVerifyReadOnly
//
// The third is not a pass. A connection that never opened, a timeout, a
// missing table privilege that fails the CREATE for a reason other than
// read-onlyness — none of those prove anything, and treating them as
// success would make this check pass exactly when it is least able to
// tell.
func CheckReadOnly(ctx context.Context, dsn string) error {
	ctx, cancel := context.WithTimeout(ctx, readOnlyProbeTimeout)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("%w: opening the connection: %v", ErrCannotVerifyReadOnly, err)
	}
	defer db.Close()

	// One connection, used for both statements. pg_temp is per-session,
	// so a pool that handed the CREATE and the INSERT to different
	// connections would have the INSERT fail on a missing table — a
	// refusal that looks like proof of read-onlyness and is not.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("%w: connecting: %v", ErrCannotVerifyReadOnly, err)
	}

	// A read that must work, before any write is attempted. Without it, a
	// role with no rights at all would fail the CREATE below and be
	// reported as read-only — which is the right answer by accident, on a
	// connection that cannot serve the feature either.
	if _, err := db.ExecContext(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%w: the connection cannot run a query at all: %v", ErrCannotVerifyReadOnly, err)
	}

	if _, err := db.ExecContext(ctx, probeCreate); err != nil {
		// The CREATE failing is the expected outcome for a role that
		// cannot write, and it is also what a dozen unrelated problems
		// look like. Postgres distinguishes them: 42501 is
		// insufficient_privilege, which is the server saying "this role
		// may not do that". Anything else is reported as unverifiable
		// rather than assumed to be a refusal.
		if isInsufficientPrivilege(err) {
			return nil
		}
		return fmt.Errorf("%w: creating the probe table: %v", ErrCannotVerifyReadOnly, err)
	}

	// The role could create a table. It is not read-only, and the INSERT
	// is not needed to know that — but running it keeps the failure
	// message specific about what succeeded, which is what an operator
	// needs to go and fix the grant.
	if _, err := db.ExecContext(ctx, probeInsert); err != nil {
		return fmt.Errorf("%w: the role may create tables (INSERT failed separately: %v)", ErrNotReadOnly, err)
	}
	return fmt.Errorf("%w: the role both created a table and inserted a row", ErrNotReadOnly)
}

// isInsufficientPrivilege reports whether err is Postgres' own "this role
// may not do that" — SQLSTATE 42501.
//
// Checked by code rather than by matching the message, because the
// message is localized and reworded between major versions while the code
// is not, and this is the branch that decides whether a connection is
// accepted.
func isInsufficientPrivilege(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "42501"
	}
	// lib/pq returns the parsed error for anything the server answers,
	// so a non-pq error here means the statement never reached Postgres.
	// Reported as unverifiable rather than as a refusal, which is what
	// the caller does with a false return.
	return false
}

// PostgresSnapshot implements cryden's ai.QueryableStore over a
// connection that CheckReadOnly has already accepted.
//
// It runs an already-validated QueryIntent. "Already-validated" is not a
// hope: cryden's ai.ExecuteIntent runs validateIntent before it calls
// RunSafeQuery at all, and widget.Ask runs it too — there is no path to
// this method that skips that. What this type adds is that the statement
// it builds is assembled from cryden's own EntityColumns list rather than
// from anything on the intent, so an entity that somehow got past
// validation still cannot put text of its own into the SQL.
type PostgresSnapshot struct {
	db      *sql.DB
	maxRows int
}

// NewPostgresSnapshot opens the read-only connection. It does NOT itself
// check that the role is read-only — that is CheckReadOnly's job and it
// belongs to the settings write, where the operator is present to be told
// about a failure. Opening here is deliberately cheap so that a
// deployment whose stored connection has since gone bad reports a query
// error rather than failing to start.
func NewPostgresSnapshot(dsn string, maxRows int) (*PostgresSnapshot, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("aiprovider: opening the read-only connection: %w", err)
	}
	if maxRows < 1 {
		maxRows = crydenai.DefaultLimit
	}
	if maxRows > crydenai.MaxLimit {
		maxRows = crydenai.MaxLimit
	}
	return &PostgresSnapshot{db: db, maxRows: maxRows}, nil
}

// Close releases the pool.
func (s *PostgresSnapshot) Close() error { return s.db.Close() }

var _ crydenai.QueryableStore = (*PostgresSnapshot)(nil)

// RunSafeQuery executes an intent.
//
// Every value that reaches the SQL text comes from cryden's own
// EntityColumns / AllowedFields maps. Filter *values* — the only part
// that originates with a user — are bind parameters, never interpolated.
// Column and operator names cannot be bound in SQL, which is exactly why
// they are taken from a fixed map on this side rather than trusted from
// the intent: a name that is not in the map is refused, not quoted.
func (s *PostgresSnapshot) RunSafeQuery(ctx context.Context, intent crydenai.QueryIntent) (crydenai.QueryResult, error) {
	columns, ok := crydenai.EntityColumns[intent.Entity]
	if !ok {
		return crydenai.QueryResult{}, fmt.Errorf("aiprovider: unknown entity %q", intent.Entity)
	}

	// The intent's own Limit was already defaulted and clamped by
	// ai.ExecuteIntent; this is the deployment's own ceiling on top of
	// the engine's, so an operator can make the AI surface cheaper than
	// cryden's maximum without changing the engine.
	limit := intent.Limit
	if limit <= 0 || limit > s.maxRows {
		limit = s.maxRows
	}

	var (
		where []string
		args  []any
	)
	for _, filter := range intent.Filters {
		if err := checkFilter(intent.Entity, filter); err != nil {
			return crydenai.QueryResult{}, err
		}
		args = append(args, filterArgument(filter.Operator, filter.Value))
		where = append(where, fmt.Sprintf("%s %s $%d", filter.Field, sqlOperator(filter.Operator), len(args)))
	}

	statement := buildStatement(intent, columns, where, limit)
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return crydenai.QueryResult{}, fmt.Errorf("aiprovider: running the query: %w", err)
	}
	defer rows.Close()

	return scanResult(rows)
}

// checkFilter refuses a filter whose field or operator is not in cryden's
// allowlist for that entity.
//
// Both names are checked here as well as in the engine. That is not
// redundancy for its own sake: SQL cannot bind a column or an operator
// name, so those two are the only parts of this query that are spliced
// into text rather than passed as parameters, and a second check at the
// point of assembly is what makes "the statement can only contain names
// from a fixed map" a property of this function rather than a claim about
// its callers.
func checkFilter(entity string, filter crydenai.QueryFilter) error {
	if !crydenai.AllowedFields[entity][filter.Field] {
		return fmt.Errorf("aiprovider: field %q is not allowed on %q", filter.Field, entity)
	}
	if !crydenai.AllowedOperators[filter.Operator] {
		return fmt.Errorf("aiprovider: operator %q is not allowed", filter.Operator)
	}
	return nil
}

// buildStatement assembles the SELECT. Every piece spliced into the text
// is a name drawn from cryden's maps — see RunSafeQuery — so the only
// thing a caller influences is the shape, never the vocabulary.
func buildStatement(intent crydenai.QueryIntent, columns, where []string, limit int) string {
	var b strings.Builder

	switch intent.Aggregate {
	case "count":
		b.WriteString("SELECT count(*) FROM ")
		b.WriteString(intent.Entity)
	case "group_by":
		b.WriteString("SELECT ")
		b.WriteString(intent.GroupBy)
		b.WriteString(", count(*) FROM ")
		b.WriteString(intent.Entity)
	default:
		b.WriteString("SELECT ")
		b.WriteString(strings.Join(columns, ", "))
		b.WriteString(" FROM ")
		b.WriteString(intent.Entity)
	}

	if len(where) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(where, " AND "))
	}
	if intent.Aggregate == "group_by" {
		b.WriteString(" GROUP BY ")
		b.WriteString(intent.GroupBy)
	}
	fmt.Fprintf(&b, " LIMIT %d", limit)
	return b.String()
}

// sqlOperator maps cryden's operator vocabulary onto SQL. "contains" is
// the one that is not a plain symbol: it becomes a LIKE.
func sqlOperator(operator string) string {
	if operator == "contains" {
		return "LIKE"
	}
	return operator
}

// filterArgument prepares a filter's value for its place in the query.
//
// "contains" is the only operator that needs anything done to its value:
// LIKE's wildcards are part of the pattern, so a caller writing
// "contains: a%" would otherwise get substring semantics they did not ask
// for and probably did not intend. The wildcards are added here, around
// the whole value, so the value is always a literal.
//
// This is not a safety measure — the value is a bind parameter either
// way, so neither form can reach the SQL text. It is about the operator
// meaning what it says.
func filterArgument(operator, value string) string {
	if operator == "contains" {
		// Escaped so a literal % or _ in the question stays literal:
		// the default LIKE escape character is a backslash.
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
		return "%" + escaped + "%"
	}
	return value
}

func scanResult(rows *sql.Rows) (crydenai.QueryResult, error) {
	// The header comes from the query rather than from the entity
	// definition, because an aggregate's columns are not the entity's
	// own — a count returns one column that no entity lists.
	names, err := rows.Columns()
	if err != nil {
		return crydenai.QueryResult{}, err
	}

	result := crydenai.QueryResult{Columns: names, Rows: [][]string{}}
	for rows.Next() {
		cells := make([]any, len(names))
		pointers := make([]any, len(names))
		for i := range cells {
			pointers[i] = &cells[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return crydenai.QueryResult{}, err
		}
		row := make([]string, len(names))
		for i, cell := range cells {
			row[i] = renderCell(cell)
		}
		result.Rows = append(result.Rows, row)
	}
	return result, rows.Err()
}

// renderCell turns a scanned value into the string form ai.QueryResult
// promises. Bytes become a string, a time keeps RFC 3339, and a NULL
// becomes empty rather than the word "NULL" — an empty cell is what a
// table shows and what a model reads as "nothing here".
func renderCell(cell any) string {
	switch value := cell.(type) {
	case nil:
		return ""
	case []byte:
		return string(value)
	case time.Time:
		return value.Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", value)
	}
}
