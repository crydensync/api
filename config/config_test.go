package config

import (
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
)

// tier2EnvVars are the vars these tests assert on, cleared before every
// case so a value left in the developer's shell cannot make a
// default-value assertion pass or fail for the wrong reason. Setting one
// to "" is the same as leaving it unset: every loader in this package
// treats empty as absent.
var tier2EnvVars = []string{
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
}

func loadForTest(t *testing.T, env map[string]string) (Config, error) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://user:pw@localhost/db")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("CORS_ORIGINS", "http://localhost:5173")
	for _, name := range tier2EnvVars {
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
