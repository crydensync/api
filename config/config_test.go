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
}

func loadForTest(t *testing.T, env map[string]string) (Config, error) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://user:pw@localhost/db")
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
