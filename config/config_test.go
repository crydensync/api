package config

import (
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
)

// tieredEnvVars are the vars these tests assert on, cleared before every
// case so a value left in the developer's shell cannot make a
// default-value assertion pass or fail for the wrong reason. Setting one
// to "" is the same as leaving it unset: every loader in this package
// treats empty as absent.
var tieredEnvVars = []string{
	"ANOMALY_DETECTION",
	"ANOMALY_WINDOW_MINUTES",
	"ANOMALY_HISTORY_SIZE",
	"ANOMALY_USER_FAILURE_VELOCITY",
	"ANOMALY_IP_FAILURE_VELOCITY",
	"ANOMALY_MAX_CONCURRENT_SESSIONS",
	"ANOMALY_TOKEN_REUSE_LOOKBACK_MINUTES",
	"CREDENTIAL_STUFFING_WINDOW_MINUTES",
	"CREDENTIAL_STUFFING_TARGET_ACCOUNTS",
	"CREDENTIAL_STUFFING_COOLDOWN_MINUTES",
	"REDIS_URL",
	"RATE_LIMIT_ATTEMPTS",
	"RATE_LIMIT_WINDOW_SECONDS",
	"PASSWORD_HASHER",
	"ARGON2ID_MEMORY_KIB",
	"ARGON2ID_ITERATIONS",
	"ARGON2ID_PARALLELISM",
	"ARGON2ID_SALT_LENGTH",
	"ARGON2ID_KEY_LENGTH",
	"API_KEY_PREFIX",
	"LOG_LEVEL",
	"CLOUD_LOGGING",
	"CLOUD_LOG_REDACTION",
	"CLOUD_LOG_HASH_KEY",
	"EMAIL_TEMPLATE_DIR",
	"WEBHOOK_URL",
	"WEBHOOK_SECRET",
	"WEBHOOK_EVENTS",
	"WEBHOOK_MAX_ATTEMPTS",
	"LOCKOUT_THRESHOLD",
	"LOCKOUT_DURATION_MINUTES",
	"DIGEST_INTERVAL_HOURS",
}

func loadForTest(t *testing.T, env map[string]string) (Config, error) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://user:pw@localhost/db")
	// Cleared as well as set, so this helper describes exactly one thing:
	// a Postgres deployment. Without it a SQLite_PATH set by an earlier
	// call in the same test would survive into the next one and turn it
	// into the mutually-exclusive case by accident. A caller wanting the
	// other backend passes DATABASE_URL:"" and a SQLITE_PATH, which the
	// env map below applies last.
	t.Setenv("SQLITE_PATH", "")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("CORS_ORIGINS", "http://localhost:5173")
	for _, name := range tieredEnvVars {
		t.Setenv(name, "")
	}
	for name, value := range env {
		t.Setenv(name, value)
	}
	return Load()
}

// The thresholds have to come back as the engine's own defaults rather
// than as a struct this repo assembled field by field: cryden reads
// every field of a non-zero thresholds value, so a field left out is a
// silently disabled check, not a defaulted one.
func TestTier2DefaultsComeFromTheEngine(t *testing.T) {
	cfg, err := loadForTest(t, nil)
	if err != nil {
		t.Fatalf("Load() failed with only the required vars set: %v", err)
	}

	if cfg.AnomalyDetection {
		t.Error("anomaly detection is on without ANOMALY_DETECTION being set")
	}
	if cfg.AnomalyThresholds != security.DefaultAnomalyThresholds {
		t.Errorf("AnomalyThresholds = %+v, want the engine's defaults %+v", cfg.AnomalyThresholds, security.DefaultAnomalyThresholds)
	}
	if cfg.CredentialStuffingThresholds != security.DefaultCredentialStuffingThresholds {
		t.Errorf("CredentialStuffingThresholds = %+v, want the engine's defaults %+v", cfg.CredentialStuffingThresholds, security.DefaultCredentialStuffingThresholds)
	}
	if cfg.RedisURL != "" {
		t.Errorf("RedisURL = %q, want empty (in-process limiter)", cfg.RedisURL)
	}
	// The one engine default restated in this repo, deliberately — see
	// the field comments: with REDIS_URL set it is this repo that builds
	// the limiter, and that constructor rejects a zero bound.
	if cfg.RateLimitAttempts != 10 || cfg.RateLimitWindow != time.Minute {
		t.Errorf("rate limit = %d per %s, want 10 per minute", cfg.RateLimitAttempts, cfg.RateLimitWindow)
	}
}

func TestTier2EnvOverridesLeaveOtherKnobsDefaulted(t *testing.T) {
	cfg, err := loadForTest(t, map[string]string{
		"ANOMALY_DETECTION":                   "true",
		"ANOMALY_WINDOW_MINUTES":              "30",
		"ANOMALY_HISTORY_SIZE":                "50",
		"ANOMALY_IP_FAILURE_VELOCITY":         "7",
		"ANOMALY_MAX_CONCURRENT_SESSIONS":     "0",
		"CREDENTIAL_STUFFING_TARGET_ACCOUNTS": "3",
		"REDIS_URL":                           "redis://localhost:6379/0",
		"RATE_LIMIT_ATTEMPTS":                 "25",
		"RATE_LIMIT_WINDOW_SECONDS":           "30",
	})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if !cfg.AnomalyDetection {
		t.Error("ANOMALY_DETECTION=true did not switch detection on")
	}
	if cfg.AnomalyThresholds.Window != 30*time.Minute {
		t.Errorf("Window = %s, want 30m", cfg.AnomalyThresholds.Window)
	}
	if cfg.AnomalyThresholds.HistorySize != 50 {
		t.Errorf("HistorySize = %d, want 50", cfg.AnomalyThresholds.HistorySize)
	}
	if cfg.AnomalyThresholds.IPFailureVelocity != 7 {
		t.Errorf("IPFailureVelocity = %d, want 7", cfg.AnomalyThresholds.IPFailureVelocity)
	}
	// An explicit 0 is a real setting (this check off), not "unset".
	if cfg.AnomalyThresholds.MaxConcurrentSessions != 0 {
		t.Errorf("MaxConcurrentSessions = %d, want the explicit 0", cfg.AnomalyThresholds.MaxConcurrentSessions)
	}
	// Untouched knobs keep the engine default — the whole point of
	// copying the defaults across before applying overrides.
	if cfg.AnomalyThresholds.UserFailureVelocity != security.DefaultAnomalyThresholds.UserFailureVelocity {
		t.Errorf("UserFailureVelocity = %d, want the engine default %d", cfg.AnomalyThresholds.UserFailureVelocity, security.DefaultAnomalyThresholds.UserFailureVelocity)
	}
	if cfg.AnomalyThresholds.TokenReuseLookback != security.DefaultAnomalyThresholds.TokenReuseLookback {
		t.Errorf("TokenReuseLookback = %s, want the engine default %s", cfg.AnomalyThresholds.TokenReuseLookback, security.DefaultAnomalyThresholds.TokenReuseLookback)
	}
	if cfg.CredentialStuffingThresholds.TargetAccounts != 3 {
		t.Errorf("TargetAccounts = %d, want 3", cfg.CredentialStuffingThresholds.TargetAccounts)
	}
	if cfg.CredentialStuffingThresholds.Window != security.DefaultCredentialStuffingThresholds.Window {
		t.Errorf("stuffing Window = %s, want the engine default %s", cfg.CredentialStuffingThresholds.Window, security.DefaultCredentialStuffingThresholds.Window)
	}
	if cfg.RedisURL != "redis://localhost:6379/0" {
		t.Errorf("RedisURL = %q, want the value that was set", cfg.RedisURL)
	}
	if cfg.RateLimitAttempts != 25 || cfg.RateLimitWindow != 30*time.Second {
		t.Errorf("rate limit = %d per %s, want 25 per 30s", cfg.RateLimitAttempts, cfg.RateLimitWindow)
	}
}

func TestTier2MalformedValuesAreStartupErrors(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"non-boolean switch", map[string]string{"ANOMALY_DETECTION": "maybe"}, "ANOMALY_DETECTION must be true or false"},
		{"non-numeric minutes", map[string]string{"ANOMALY_WINDOW_MINUTES": "soon"}, "ANOMALY_WINDOW_MINUTES must be a number of minutes"},
		{"non-numeric seconds", map[string]string{"RATE_LIMIT_WINDOW_SECONDS": "1.5"}, "RATE_LIMIT_WINDOW_SECONDS must be a number of seconds"},
		{"non-numeric count", map[string]string{"CREDENTIAL_STUFFING_TARGET_ACCOUNTS": "many"}, "CREDENTIAL_STUFFING_TARGET_ACCOUNTS must be a number"},
		{"unknown hasher", map[string]string{"PASSWORD_HASHER": "argon"}, "PASSWORD_HASHER must be"},
		{"negative argon2id cost", map[string]string{"ARGON2ID_PARALLELISM": "-1"}, "ARGON2ID_PARALLELISM must be a non-negative whole number"},
		{"oversized argon2id lane count", map[string]string{"ARGON2ID_PARALLELISM": "256"}, "ARGON2ID_PARALLELISM must be a non-negative whole number"},
		{"unknown log level", map[string]string{"LOG_LEVEL": "verbose"}, "unrecognized level name"},
		{"unknown redaction mode", map[string]string{"CLOUD_LOG_REDACTION": "encrypt"}, "CLOUD_LOG_REDACTION must be"},
		{"hash redaction without a key", map[string]string{"CLOUD_LOG_REDACTION": "hash"}, "CLOUD_LOG_HASH_KEY is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadForTest(t, tc.env)
			if err == nil {
				t.Fatalf("%v was accepted, want an error", tc.env)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// The Tier 3 defaults, all of which have to be the engine's own answers
// rather than this repo's guesses: bcrypt is what cryden runs with no
// hasher set, and the argon2id parameters are RFC 9106's option two.
func TestTier3DefaultsComeFromTheEngine(t *testing.T) {
	cfg, err := loadForTest(t, nil)
	if err != nil {
		t.Fatalf("Load() failed with only the required vars set: %v", err)
	}

	if cfg.PasswordHasher != PasswordHasherBcrypt {
		t.Errorf("PasswordHasher = %q, want %q", cfg.PasswordHasher, PasswordHasherBcrypt)
	}
	// Assembled even when bcrypt is in force, so the hash-migration
	// report can say what this deployment WOULD write.
	if cfg.Argon2idParams != security.DefaultArgon2idParams {
		t.Errorf("Argon2idParams = %+v, want the engine's defaults %+v", cfg.Argon2idParams, security.DefaultArgon2idParams)
	}
	if cfg.APIKeyPrefix != "ck" {
		t.Errorf("APIKeyPrefix = %q, want the engine's own default \"ck\"", cfg.APIKeyPrefix)
	}
	if cfg.CloudLogging {
		t.Error("cloud logging is on without CLOUD_LOGGING being set")
	}
	if cfg.LogLevel != logger.LevelInfo {
		t.Errorf("LogLevel = %s, want info", cfg.LogLevel)
	}
	if cfg.CloudLogRedaction != CloudLogRedactionMask {
		t.Errorf("CloudLogRedaction = %q, want %q", cfg.CloudLogRedaction, CloudLogRedactionMask)
	}
	if cfg.EmailTemplateDir != "" {
		t.Errorf("EmailTemplateDir = %q, want empty (built-in sender text)", cfg.EmailTemplateDir)
	}
	// No WEBHOOK_URL means no webhook anything: the off switch is the URL
	// itself, because a secret and an event list with nowhere to deliver to
	// describe nothing.
	if cfg.WebhookURL != "" {
		t.Errorf("WebhookURL = %q, want empty (webhooks dispatched by nobody)", cfg.WebhookURL)
	}
	if len(cfg.WebhookEvents) != 0 {
		t.Errorf("WebhookEvents = %v, want empty so cryden's own default set applies", cfg.WebhookEvents)
	}
	if cfg.WebhookMaxAttempts != 5 {
		t.Errorf("WebhookMaxAttempts = %d, want 5", cfg.WebhookMaxAttempts)
	}
}

// One env var must move exactly one field. This is the same trap the
// anomaly thresholds have: cryden treats a partially-filled params
// struct as a complete custom configuration, so an assembly that
// started from zero would set four knobs to zero and fail validation.
func TestTier3Argon2idOverrideLeavesEveryOtherKnobDefaulted(t *testing.T) {
	cfg, err := loadForTest(t, map[string]string{
		"PASSWORD_HASHER":     PasswordHasherArgon2id,
		"ARGON2ID_ITERATIONS": "5",
	})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg.PasswordHasher != PasswordHasherArgon2id {
		t.Errorf("PasswordHasher = %q, want %q", cfg.PasswordHasher, PasswordHasherArgon2id)
	}
	if cfg.Argon2idParams.Iterations != 5 {
		t.Errorf("Iterations = %d, want 5", cfg.Argon2idParams.Iterations)
	}
	if cfg.Argon2idParams.Memory != security.DefaultArgon2idParams.Memory {
		t.Errorf("Memory = %d, want the engine default %d", cfg.Argon2idParams.Memory, security.DefaultArgon2idParams.Memory)
	}
	if cfg.Argon2idParams.Parallelism != security.DefaultArgon2idParams.Parallelism {
		t.Errorf("Parallelism = %d, want the engine default %d", cfg.Argon2idParams.Parallelism, security.DefaultArgon2idParams.Parallelism)
	}
	if cfg.Argon2idParams.SaltLength != security.DefaultArgon2idParams.SaltLength {
		t.Errorf("SaltLength = %d, want the engine default %d", cfg.Argon2idParams.SaltLength, security.DefaultArgon2idParams.SaltLength)
	}
	if cfg.Argon2idParams.KeyLength != security.DefaultArgon2idParams.KeyLength {
		t.Errorf("KeyLength = %d, want the engine default %d", cfg.Argon2idParams.KeyLength, security.DefaultArgon2idParams.KeyLength)
	}
	// And the assembled set is one cryden will actually accept — the
	// assertion the field-by-field checks above cannot make between them.
	if _, err := security.NewArgon2idHasher(cfg.Argon2idParams); err != nil {
		t.Errorf("the assembled params were rejected by the engine: %v", err)
	}
}

// A wrong LOG_LEVEL must not fall back to anything. ParseLevel's own
// doc comment is explicit that both fallbacks are wrong in one
// direction: debug multiplies a vendor bill, error discards records
// someone was trying to keep.
func TestTier3LogLevelIsParsedNotDefaulted(t *testing.T) {
	cfg, err := loadForTest(t, map[string]string{"LOG_LEVEL": "WARN"})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.LogLevel != logger.LevelWarn {
		t.Errorf("LogLevel = %s, want warn (case-insensitive)", cfg.LogLevel)
	}

	if _, err := loadForTest(t, map[string]string{"LOG_LEVEL": "verbose"}); err == nil {
		t.Error("an unknown LOG_LEVEL was accepted, want a startup failure")
	}
}

// The hash key is required only when something would use it — asking
// every deployment for a secret it has no purpose for is how a second
// required key ends up copy-pasted from JWT_SECRET, which is the exact
// reuse cryden's NewHashingRedactor warns against.
func TestTier3CloudLogHashKeyIsRequiredOnlyForHashRedaction(t *testing.T) {
	cfg, err := loadForTest(t, map[string]string{"CLOUD_LOG_REDACTION": CloudLogRedactionMask})
	if err != nil {
		t.Fatalf("mask redaction without a hash key failed: %v", err)
	}
	if cfg.CloudLogHashKey != "" {
		t.Errorf("CloudLogHashKey = %q, want empty", cfg.CloudLogHashKey)
	}

	cfg, err = loadForTest(t, map[string]string{
		"CLOUD_LOG_REDACTION": CloudLogRedactionHash,
		"CLOUD_LOG_HASH_KEY":  "a-key-of-its-own",
	})
	if err != nil {
		t.Fatalf("hash redaction with a key failed: %v", err)
	}
	if cfg.CloudLogHashKey != "a-key-of-its-own" {
		t.Errorf("CloudLogHashKey = %q, want the value that was set", cfg.CloudLogHashKey)
	}
}

// The event list is a subscription, so whitespace around an entry is a
// typo a person makes by hand and does not mean an event type with a
// space in it — which would match nothing and deliver nothing, silently.
func TestTier3WebhookEventsAreParsedAndTrimmed(t *testing.T) {
	cfg, err := loadForTest(t, map[string]string{
		"WEBHOOK_URL":    "https://hooks.example.com/v1",
		"WEBHOOK_SECRET": "shared-with-the-receiver",
		"WEBHOOK_EVENTS": "account_locked, password_reset ,,  email_verified ",
	})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg.WebhookURL != "https://hooks.example.com/v1" {
		t.Errorf("WebhookURL = %q", cfg.WebhookURL)
	}
	got := make([]string, 0, len(cfg.WebhookEvents))
	for _, e := range cfg.WebhookEvents {
		got = append(got, string(e))
	}
	want := "account_locked,password_reset,email_verified"
	if strings.Join(got, ",") != want {
		t.Errorf("WebhookEvents = %v, want %s (trimmed, empties dropped)", got, want)
	}

	// An empty list is left empty rather than filled in here: cryden is
	// what turns "no events" into DefaultWebhookEvents, and duplicating
	// that list in this repo is how the two would come to disagree.
	cfg, err = loadForTest(t, map[string]string{"WEBHOOK_URL": "https://hooks.example.com/v1"})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if len(cfg.WebhookEvents) != 0 {
		t.Errorf("WebhookEvents = %v with none set, want empty", cfg.WebhookEvents)
	}
}

// A secret, an event list or an attempt budget with no URL is a typo, not
// a deployment: each of them describes how to deliver to somewhere that
// does not exist. This is the same rule cryden applies to
// WebhookEvents-without-Webhooks, and it is enforced here because the
// failure mode is a setting an operator believes is in force.
func TestTier3WebhookSettingsWithoutAURLAreStartupErrors(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"a secret with nowhere to send it": {"WEBHOOK_SECRET": "shared-with-the-receiver"},
		"a subscription to nothing":        {"WEBHOOK_EVENTS": "account_locked"},
		"a retry budget for no deliveries": {"WEBHOOK_MAX_ATTEMPTS": "9"},
		"all three, still no destination":  {"WEBHOOK_SECRET": "s", "WEBHOOK_EVENTS": "account_locked", "WEBHOOK_MAX_ATTEMPTS": "9"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadForTest(t, env)
			if err == nil {
				t.Fatalf("%v was accepted with no WEBHOOK_URL, want an error", env)
			}
			if !strings.Contains(err.Error(), "without WEBHOOK_URL") {
				t.Errorf("error = %q, want it to name WEBHOOK_URL as the missing half", err)
			}
		})
	}

	// The other direction, which is the one that must keep working: a URL
	// on its own is a complete configuration.
	if _, err := loadForTest(t, map[string]string{"WEBHOOK_URL": "https://hooks.example.com/v1"}); err != nil {
		t.Errorf("a WEBHOOK_URL on its own was rejected: %v", err)
	}
}

// Zero attempts would mean a delivery that is queued and never tried, and
// the row would be a permanent pending — so it is refused rather than
// read as "the default".
func TestTier3WebhookMaxAttemptsIsBounded(t *testing.T) {
	cfg, err := loadForTest(t, map[string]string{
		"WEBHOOK_URL":          "https://hooks.example.com/v1",
		"WEBHOOK_MAX_ATTEMPTS": "2",
	})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.WebhookMaxAttempts != 2 {
		t.Errorf("WebhookMaxAttempts = %d, want 2", cfg.WebhookMaxAttempts)
	}

	for value, want := range map[string]string{
		"0":     "must be at least 1",
		"-1":    "must be at least 1",
		"twice": "must be a number",
	} {
		_, err := loadForTest(t, map[string]string{
			"WEBHOOK_URL":          "https://hooks.example.com/v1",
			"WEBHOOK_MAX_ATTEMPTS": value,
		})
		if err == nil {
			t.Fatalf("WEBHOOK_MAX_ATTEMPTS=%s was accepted, want an error", value)
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("WEBHOOK_MAX_ATTEMPTS=%s: error = %q, want it to contain %q", value, err, want)
		}
	}
}

// Tier 6: the backend is chosen by exactly one variable, and Load refuses
// every other combination at startup rather than letting a deployment come
// up pointed at neither or at both.
//
// Both refusals matter for different reasons. Neither set is a deployment
// that would otherwise reach a nil *sql.DB somewhere deep in startup. Both
// set is the dangerous one: DATABASE_URL is what the admin console needs
// and SQLITE_PATH is what the store wiring would read, so silently
// preferring either would run a deployment on the wrong backend while its
// configuration said otherwise.
func TestTier6TheBackendIsSelectedByExactlyOneVariable(t *testing.T) {
	cfg, err := loadForTest(t, map[string]string{
		"DATABASE_URL": "",
		"SQLITE_PATH":  "/var/lib/cryden/api.db",
	})
	if err != nil {
		t.Fatalf("SQLITE_PATH on its own was rejected: %v", err)
	}
	if !cfg.UsesSQLite() {
		t.Error("UsesSQLite() = false with SQLITE_PATH set")
	}
	if cfg.SQLitePath != "/var/lib/cryden/api.db" {
		t.Errorf("SQLitePath = %q, want the value that was set", cfg.SQLitePath)
	}

	// loadForTest sets DATABASE_URL and no SQLITE_PATH: the Postgres
	// deployment every other test in this file already describes.
	cfg, err = loadForTest(t, nil)
	if err != nil {
		t.Fatalf("Load() failed with DATABASE_URL and no SQLITE_PATH: %v", err)
	}
	if cfg.UsesSQLite() {
		t.Error("UsesSQLite() = true on a deployment with no SQLITE_PATH")
	}

	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"neither backend": {
			map[string]string{"DATABASE_URL": ""},
			"one of DATABASE_URL or SQLITE_PATH is required",
		},
		"both backends": {
			map[string]string{"SQLITE_PATH": "/var/lib/cryden/api.db"},
			"mutually exclusive",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadForTest(t, tc.env)
			if err == nil {
				t.Fatalf("%v was accepted, want a startup failure", tc.env)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// UsesSQLite is the single expression of the rule, so it is pinned
// directly: an empty string is "unset", which is what the mutual-exclusion
// check above treats it as, and a Config built by hand rather than by Load
// has to answer the same way.
func TestTier6UsesSQLiteIsTheEmptyCheck(t *testing.T) {
	if (Config{}).UsesSQLite() {
		t.Error("a zero Config reports SQLite")
	}
	if !(Config{SQLitePath: "api.db"}).UsesSQLite() {
		t.Error("a Config with SQLitePath set reports Postgres")
	}
	// A Postgres URL with no path set is the Postgres backend — the case
	// that would break if this ever became "SQLitePath == '' means
	// Postgres OR ..." rather than a plain emptiness check.
	if (Config{DatabaseURL: "postgres://localhost/db"}).UsesSQLite() {
		t.Error("a Config with only DatabaseURL set reports SQLite")
	}
}

// The Tier 4 defaults: cryden's own lockout numbers restated, because the
// engine takes them straight off its config with no defaulting of its own
// and both zero values are wrong in the same direction — a zero threshold
// locks an account on its first failed password, a zero duration locks it
// until an instant already past.
func TestTier4DefaultsComeFromTheEngine(t *testing.T) {
	cfg, err := loadForTest(t, nil)
	if err != nil {
		t.Fatalf("Load() failed with only the required vars set: %v", err)
	}

	if cfg.LockoutThreshold != 5 {
		t.Errorf("LockoutThreshold = %d, want cryden's own default 5", cfg.LockoutThreshold)
	}
	if cfg.LockoutDuration != 15*time.Minute {
		t.Errorf("LockoutDuration = %s, want cryden's own default 15m", cfg.LockoutDuration)
	}
	// Digests are opt-in: no schedule unless one was asked for, so an
	// unconfigured deployment runs no goroutine and writes no rows.
	if cfg.DigestInterval != 0 {
		t.Errorf("DigestInterval = %s, want 0 (no schedule)", cfg.DigestInterval)
	}
}

func TestTier4EnvOverridesLeaveOtherKnobsDefaulted(t *testing.T) {
	cfg, err := loadForTest(t, map[string]string{
		"LOCKOUT_THRESHOLD":        "9",
		"LOCKOUT_DURATION_MINUTES": "45",
		"DIGEST_INTERVAL_HOURS":    "168",
	})
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg.LockoutThreshold != 9 {
		t.Errorf("LockoutThreshold = %d, want 9", cfg.LockoutThreshold)
	}
	if cfg.LockoutDuration != 45*time.Minute {
		t.Errorf("LockoutDuration = %s, want 45m", cfg.LockoutDuration)
	}
	// A week in hours, which is the shape the env var is written in even
	// though everything downstream holds a duration.
	if cfg.DigestInterval != 168*time.Hour {
		t.Errorf("DigestInterval = %s, want 168h", cfg.DigestInterval)
	}
	// Untouched knobs stay on their defaults.
	if cfg.RateLimitAttempts != 10 || cfg.RateLimitWindow != time.Minute {
		t.Errorf("rate limit = %d per %s, want the untouched default 10 per minute", cfg.RateLimitAttempts, cfg.RateLimitWindow)
	}
}

// A lockout threshold below 1 and a negative digest interval are both
// refused rather than read as "off": cryden has no way to switch account
// lockout off, and treating a typo as the default is how a setting an
// operator meant to change silently does nothing.
func TestTier4UnusableKnobValuesAreStartupErrors(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"threshold of zero", map[string]string{"LOCKOUT_THRESHOLD": "0"}, "LOCKOUT_THRESHOLD must be at least 1"},
		{"negative threshold", map[string]string{"LOCKOUT_THRESHOLD": "-1"}, "LOCKOUT_THRESHOLD must be at least 1"},
		{"non-numeric threshold", map[string]string{"LOCKOUT_THRESHOLD": "five"}, "LOCKOUT_THRESHOLD must be a number"},
		{"non-numeric lockout duration", map[string]string{"LOCKOUT_DURATION_MINUTES": "quarter of an hour"}, "LOCKOUT_DURATION_MINUTES must be a number of minutes"},
		{"negative digest interval", map[string]string{"DIGEST_INTERVAL_HOURS": "-1"}, "DIGEST_INTERVAL_HOURS cannot be negative"},
		{"non-numeric digest interval", map[string]string{"DIGEST_INTERVAL_HOURS": "weekly"}, "DIGEST_INTERVAL_HOURS must be a number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadForTest(t, tc.env)
			if err == nil {
				t.Fatalf("%v was accepted, want an error", tc.env)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}
