package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// DefaultDatabaseMaxRows mirrors cryden's ai.MaxLimit. The store clamps to
// the engine's own bounds regardless, so this is what an operator gets
// offered rather than a second limit the engine would honour.
const DefaultDatabaseMaxRows = 50

// ErrInvalidDatabaseProvider means the supplied connection cannot be used
// for the AI query surface.
var ErrInvalidDatabaseProvider = errors.New("settings: invalid database provider configuration")

// DatabaseProviderConfig is the connection the AI query surface runs
// against. It exists as a setting at all because cryden's
// ai.QueryableStore is an interface the host implements, and the
// connection behind it is the host's.
//
// The one requirement that is not negotiable: **this must be a read-only
// role.** cryden says so in the interface's own comment — "The only
// production implementation (store/postgres) MUST use a read-only
// Postgres role for this connection — that's a real credential-level
// guarantee, not just a promise made in code, so a bug in validation
// still can't cause a write." The allowlist is the first line; this is
// the line that holds when the allowlist has a bug.
//
// Validate below can only check the shape. Whether the role is ACTUALLY
// read-only is a fact about a database, not about a string, so it is
// checked by connecting and attempting a write — see
// aiprovider.CheckReadOnly, which the handler runs before storing this.
type DatabaseProviderConfig struct {
	// Label is what a console shows instead of the whole connection
	// string ("the reporting replica"), so an operator can tell two
	// configurations apart without reading a password.
	Label string `json:"label"`
	// DSN is the full connection string, including the credential.
	DSN string `json:"dsn"`
	// MaxRows caps a single AI-driven query. Bounded by Validate.
	MaxRows int `json:"max_rows"`
}

// Validate checks the shape of a configuration about to be stored.
//
// It deliberately does NOT claim to check that the role is read-only —
// nothing here can. See the type's comment: that check needs a live
// connection and happens in the handler.
func (c DatabaseProviderConfig) Validate() error {
	if strings.TrimSpace(c.DSN) == "" {
		return fmt.Errorf("%w: dsn is required", ErrInvalidDatabaseProvider)
	}
	if err := ValidateDSNShape(c.DSN); err != nil {
		return err
	}
	if c.MaxRows < 1 || c.MaxRows > maxDatabaseRows {
		return fmt.Errorf("%w: max_rows must be between 1 and %d, got %d",
			ErrInvalidDatabaseProvider, maxDatabaseRows, c.MaxRows)
	}
	if strings.TrimSpace(c.Label) == "" {
		return fmt.Errorf("%w: label is required — a console listing two database providers needs to tell them apart without showing a password", ErrInvalidDatabaseProvider)
	}
	return nil
}

// maxDatabaseRows bounds MaxRows. cryden clamps any query to its own
// ai.MaxLimit of 500 whatever this says, so a larger value here would be
// a setting that does not do what it appears to; this is the ceiling that
// keeps the two from disagreeing.
const maxDatabaseRows = 500

// ValidateDSNShape checks that dsn is a Postgres connection string this
// repo can hand to lib/pq. It is a shape check and nothing more — it does
// not connect, and it knowingly says nothing about whether the credentials
// work, whether the host exists, or what the role may do.
func ValidateDSNShape(dsn string) error {
	trimmed := strings.TrimSpace(dsn)

	// The keyword/value form ("host=… user=… ") is valid for lib/pq and
	// has no scheme to parse, so it is accepted on the strength of
	// carrying a host and a user rather than being forced through URL
	// parsing it was never written for.
	if !strings.Contains(trimmed, "://") {
		if !strings.Contains(trimmed, "host=") {
			return fmt.Errorf("%w: dsn is neither a postgres:// URL nor a keyword/value string with a host", ErrInvalidDatabaseProvider)
		}
		return nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%w: dsn is not a parseable URL: %v", ErrInvalidDatabaseProvider, err)
	}
	if scheme := parsed.Scheme; scheme != "postgres" && scheme != "postgresql" {
		return fmt.Errorf("%w: dsn scheme is %q, want postgres or postgresql", ErrInvalidDatabaseProvider, scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: dsn names no host", ErrInvalidDatabaseProvider)
	}
	return nil
}

// Redacted returns the copy that is safe to send to a console. The DSN is
// replaced by a description of it rather than by a mask: a masked
// connection string still leaks the host, the database and the role, and
// an operator does not need any of that back to recognise which one is
// stored — the label and the host are enough.
func (c DatabaseProviderConfig) Redacted() RedactedDatabaseProvider {
	return RedactedDatabaseProvider{
		Label:      c.Label,
		MaxRows:    c.MaxRows,
		DSNSet:     c.DSN != "",
		Host:       dsnHost(c.DSN),
		Database:   dsnDatabase(c.DSN),
		Configured: true,
	}
}

// RedactedDatabaseProvider is what GET returns. The DSN is not a field
// here at all, so a handler cannot serialise it by reaching for the wrong
// type.
type RedactedDatabaseProvider struct {
	Label      string `json:"label"`
	MaxRows    int    `json:"max_rows"`
	DSNSet     bool   `json:"dsn_set"`
	Host       string `json:"host"`
	Database   string `json:"database"`
	Configured bool   `json:"configured"`
}

// dsnHost and dsnDatabase pull the two harmless halves out of a
// connection string for display. Best-effort: an unparseable DSN returns
// "" rather than an error, because this is only ever used to decorate a
// response and a display helper that could fail a request would be a
// worse trade than a blank field.
func dsnHost(dsn string) string {
	if dsn == "" {
		return ""
	}
	if !strings.Contains(dsn, "://") {
		for _, field := range strings.Fields(dsn) {
			if after, ok := strings.CutPrefix(field, "host="); ok {
				return after
			}
		}
		return ""
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func dsnDatabase(dsn string) string {
	if dsn == "" {
		return ""
	}
	if !strings.Contains(dsn, "://") {
		for _, field := range strings.Fields(dsn) {
			if after, ok := strings.CutPrefix(field, "dbname="); ok {
				return after
			}
		}
		return ""
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(parsed.Path, "/")
}

// MarshalDatabaseProvider and UnmarshalDatabaseProvider are the
// encode/decode pair for storage, the same shape as the LLM provider's, so
// "JSON, then encrypted" has one spelling per setting.
func MarshalDatabaseProvider(c DatabaseProviderConfig) ([]byte, error) {
	return json.Marshal(c)
}

func UnmarshalDatabaseProvider(plaintext []byte) (DatabaseProviderConfig, error) {
	var c DatabaseProviderConfig
	if err := json.Unmarshal(plaintext, &c); err != nil {
		return DatabaseProviderConfig{}, fmt.Errorf("settings: decoding the stored database provider: %w", err)
	}
	return c, nil
}
