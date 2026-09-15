package aiprovider

import (
	"errors"
	"strings"
	"testing"

	crydenai "github.com/crydensync/cryden/v2/ai"
)

// The statement builder is where the two spliced names — a column and an
// operator — become SQL text. Everything else in a query is a bind
// parameter. So this is the file that has to be sure about them.
func TestBuildStatementUsesOnlyAllowlistedNames(t *testing.T) {
	columns, ok := crydenai.EntityColumns["users"]
	if !ok {
		t.Fatal("cryden no longer defines EntityColumns for users")
	}

	statement := buildStatement(
		crydenai.QueryIntent{Entity: "users", Aggregate: "", Limit: 25},
		columns,
		nil,
		25,
	)

	want := "SELECT " + strings.Join(columns, ", ") + " FROM users LIMIT 25"
	if statement != want {
		t.Errorf("statement =\n  %s\nwant\n  %s", statement, want)
	}
}

func TestBuildStatementShapesAnAggregate(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		got := buildStatement(crydenai.QueryIntent{Entity: "audit_events", Aggregate: "count", Limit: 5}, nil, nil, 5)
		if got != "SELECT count(*) FROM audit_events LIMIT 5" {
			t.Errorf("statement = %q", got)
		}
	})

	t.Run("group_by", func(t *testing.T) {
		got := buildStatement(
			crydenai.QueryIntent{Entity: "audit_events", Aggregate: "group_by", GroupBy: "type", Limit: 5},
			nil, nil, 5,
		)
		want := "SELECT type, count(*) FROM audit_events GROUP BY type LIMIT 5"
		if got != want {
			t.Errorf("statement = %q, want %q", got, want)
		}
	})
}

func TestBuildStatementBindsFilterValuesRatherThanInlining(t *testing.T) {
	got := buildStatement(
		crydenai.QueryIntent{Entity: "users", Limit: 10},
		nil,
		[]string{"email = $1", "created_at > $2"},
		10,
	)
	if !strings.Contains(got, "WHERE email = $1 AND created_at > $2") {
		t.Errorf("statement = %q, want the filters joined with AND and left as placeholders", got)
	}
}

// A column or operator that is not in cryden's allowlist must be refused
// before it can be spliced into a statement. Asserted with values that
// would be an injection if they ever reached the text.
func TestCheckFilterRefusesAnythingNotAllowlisted(t *testing.T) {
	cases := []struct {
		name   string
		entity string
		filter crydenai.QueryFilter
	}{
		{"unknown field", "users", crydenai.QueryFilter{Field: "password_hash", Operator: "=", Value: "x"}},
		{"injected field", "users", crydenai.QueryFilter{Field: "email; DROP TABLE users", Operator: "=", Value: "x"}},
		{"unknown operator", "users", crydenai.QueryFilter{Field: "email", Operator: "OR 1=1 --", Value: "x"}},
		{"field from another entity", "users", crydenai.QueryFilter{Field: "user_agent", Operator: "=", Value: "x"}},
		{"unknown entity", "secrets", crydenai.QueryFilter{Field: "id", Operator: "=", Value: "x"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkFilter(tc.entity, tc.filter); err == nil {
				t.Errorf("checkFilter(%q, %+v) was allowed, want a refusal", tc.entity, tc.filter)
			}
		})
	}
}

func TestCheckFilterAllowsWhatCrydenAllows(t *testing.T) {
	// Every field cryden allowlists on every entity has to pass here too,
	// or this repo would refuse queries the engine considers safe.
	for entity, fields := range crydenai.AllowedFields {
		for field := range fields {
			for operator := range crydenai.AllowedOperators {
				if err := checkFilter(entity, crydenai.QueryFilter{Field: field, Operator: operator}); err != nil {
					t.Errorf("checkFilter(%q, %s %s) = %v, want nil", entity, field, operator, err)
				}
			}
		}
	}
}

// "contains" means substring, and the wildcards that make it one are
// added here rather than taken from the caller's value.
func TestFilterArgumentWrapsContainsAndEscapesItsWildcards(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"dana", "%dana%"},
		{"", "%%"},
		// A caller's own % must stay a literal percent rather than
		// becoming a wildcard they did not ask for.
		{"100%", `%100\%%`},
		{"a_b", `%a\_b%`},
		{`back\slash`, `%back\\slash%`},
	}
	for _, tc := range cases {
		if got := filterArgument("contains", tc.value); got != tc.want {
			t.Errorf("filterArgument(contains, %q) = %q, want %q", tc.value, got, tc.want)
		}
	}

	// Every other operator passes its value through untouched — an "="
	// that mangled its value would silently match nothing.
	for _, operator := range []string{"=", ">", "<"} {
		if got := filterArgument(operator, "100%"); got != "100%" {
			t.Errorf("filterArgument(%q, ...) = %q, want the value unchanged", operator, got)
		}
	}
}

func TestSqlOperatorMapsOnlyContains(t *testing.T) {
	if got := sqlOperator("contains"); got != "LIKE" {
		t.Errorf("sqlOperator(contains) = %q, want LIKE", got)
	}
	for _, operator := range []string{"=", ">", "<"} {
		if got := sqlOperator(operator); got != operator {
			t.Errorf("sqlOperator(%q) = %q, want it unchanged", operator, got)
		}
	}
}

func TestRenderCell(t *testing.T) {
	cases := []struct {
		name string
		cell any
		want string
	}{
		// NULL is an empty cell. The word "NULL" would be read by a model
		// as the four-character string it looks like.
		{"null", nil, ""},
		{"bytes", []byte("dana@example.com"), "dana@example.com"},
		{"string", "already a string", "already a string"},
		{"int", 42, "42"},
		{"bool", true, "true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderCell(tc.cell); got != tc.want {
				t.Errorf("renderCell(%v) = %q, want %q", tc.cell, got, tc.want)
			}
		})
	}
}

// Only Postgres' own insufficient_privilege is read as "the role is
// read-only". Everything else has to fall through to unverifiable, or a
// connection failure would be accepted as proof.
func TestIsInsufficientPrivilegeAcceptsOnly42501(t *testing.T) {
	if isInsufficientPrivilege(nil) {
		t.Error("a nil error was read as insufficient privilege")
	}
	if isInsufficientPrivilege(errors.New("dial tcp: connection refused")) {
		t.Error("a transport error was read as insufficient privilege")
	}
	if isInsufficientPrivilege(errors.New(`pq: permission denied for table users`)) {
		t.Error("a plain error was read as insufficient privilege — only a parsed SQLSTATE may count")
	}
}

// The probe statements are the evidence this whole check rests on, so
// they must be a write and must not touch anything an operator would have
// to clean up afterwards.
func TestProbeStatementsWriteOnlyToATemporaryTable(t *testing.T) {
	if !strings.HasPrefix(strings.ToUpper(probeCreate), "CREATE TEMP TABLE") {
		t.Errorf("probeCreate = %q, want a TEMP table so a successful probe leaves nothing behind", probeCreate)
	}
	if !strings.HasPrefix(strings.ToUpper(probeInsert), "INSERT") {
		t.Errorf("probeInsert = %q, want a genuine write", probeInsert)
	}
	for _, statement := range []string{probeCreate, probeInsert} {
		if strings.Contains(strings.ToUpper(statement), "PG_CATALOG") || strings.Contains(strings.ToUpper(statement), "PUBLIC.") {
			t.Errorf("probe statement %q touches a real schema", statement)
		}
	}
}
