package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2/security"
)

type Config struct {
	DatabaseURL         string
	JWTSecret           string
	Port                string
	CORSOrigins         []string
	AccessTokenTTL      time.Duration
	EdgeRateLimit       int
	EdgeRateLimitWindow time.Duration

	// BaseURL is this api deployment's own public URL, used to build
	// OAuth callback URLs (e.g. BaseURL + "/v1/oauth/google/callback")
	// that get registered with each provider's console.
	BaseURL string

	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string
	GitHubClientSecret string

	MicrosoftClientID     string
	MicrosoftClientSecret string
	DiscordClientID       string
	DiscordClientSecret   string
	GitLabClientID        string
	GitLabClientSecret    string

	// Apple is the one provider that needs more than an ID and a secret:
	// its client "secret" is a short-lived ES256 JWT this repo signs
	// itself, with a key downloaded from Apple's developer console, so
	// the signing material is configuration here rather than a static
	// string. All four must be set for the provider to be available.
	//
	// AppleClientID is the Services ID (e.g. "com.example.web"), not the
	// app bundle ID. ApplePrivateKey is the .p8 file's contents; because
	// a PEM cannot sit on one .env line, literal "\n" sequences are
	// converted to real newlines when this is loaded.
	AppleClientID   string
	AppleTeamID     string
	AppleKeyID      string
	ApplePrivateKey string

	// EncryptionKey encrypts TOTP secrets and WebAuthn ceremony state at
	// rest. Required only if TOTP or WebAuthn is enabled — cryden refuses
	// to construct an engine with either store set and this empty, since a
	// TOTP secret has to be recoverable in plaintext to check a code, so
	// it is encrypted rather than hashed. Treat it with the same care as
	// JWT_SECRET.
	EncryptionKey string

	// TOTPIssuerName is what the user's authenticator app shows next to
	// the account. Cosmetic. Empty means cryden's own default ("Cryden").
	TOTPIssuerName string

	// WebAuthnRPID is the app's real registrable domain — passkeys are
	// cryptographically bound to it, so unlike TOTPIssuerName this is a
	// genuine security parameter, not a label. WebAuthnRPOrigins must
	// list the exact scheme+host+port the browser will send.
	WebAuthnRPID          string
	WebAuthnRPDisplayName string
	WebAuthnRPOrigins     []string

	// AnomalyDetection switches cryden's login anomaly detection and
	// credential-stuffing detection on. They share one store as their
	// on/off switch (see main.go) because they are the same
	// login-attempt history read two ways, and the engine has no partial
	// mode: with no store set neither runs and nothing about login
	// changes. Off unless explicitly enabled, and report-only either way
	// — a flagged attempt records an audit event, it never blocks.
	AnomalyDetection bool

	// AnomalyThresholds and CredentialStuffingThresholds start from the
	// engine's own security.Default* values and are then overridden one
	// env var at a time. That order matters: cryden reads every field of
	// a non-zero thresholds struct, so a struct built from only the env
	// vars that happened to be set would silently zero every knob left
	// out rather than falling back to its default.
	AnomalyThresholds            security.AnomalyThresholds
	CredentialStuffingThresholds security.CredentialStuffingThresholds

	// RedisURL points the engine's own rate limiter — the fine-grained,
	// per-user one covering login, signup and magic-link requests — at a
	// Redis so every replica counts against one window. Empty keeps
	// cryden's in-process limiter, which is correct for exactly one
	// process: three replicas behind a load balancer each keep their own
	// counters, making the effective limit three times what was
	// configured.
	//
	// This does not touch the coarse per-IP edge limiter in
	// httpapi/ratelimit.go, which stays in-process either way.
	RedisURL string

	// RateLimitAttempts and RateLimitWindow are the engine limiter's
	// bounds in either mode. Their defaults are cryden's own (10 per
	// minute) restated here rather than left at zero, because the engine
	// only fills a zero value in for the in-process limiter it builds
	// itself: with RedisURL set it is this repo that calls
	// security.NewRedisRateLimiter, and that constructor rejects a zero
	// bound outright. Leaving them at zero would make REDIS_URL on its
	// own a startup failure, which is not a setting anyone would expect
	// to need company.
	RateLimitAttempts int
	RateLimitWindow   time.Duration
}

// Load reads .env (if present, filling only gaps — real env vars
// always win) then reads the actual environment. No external
// dependency for .env parsing — same minimal-loader approach as csax.
func Load() (Config, error) {
	loadEnvFile(".env")

	cfg := Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		Port:        os.Getenv("PORT"),
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}

	origins := os.Getenv("CORS_ORIGINS")
	if origins == "" {
		return cfg, fmt.Errorf("CORS_ORIGINS is required — comma-separated list of allowed origins, no wildcard")
	}
	for _, o := range strings.Split(origins, ",") {
		cfg.CORSOrigins = append(cfg.CORSOrigins, strings.TrimSpace(o))
	}

	ttlMinutes := os.Getenv("ACCESS_TOKEN_TTL_MINUTES")
	if ttlMinutes == "" {
		cfg.AccessTokenTTL = 15 * time.Minute
	} else {
		n, err := strconv.Atoi(ttlMinutes)
		if err != nil {
			return cfg, fmt.Errorf("ACCESS_TOKEN_TTL_MINUTES must be a number: %w", err)
		}
		cfg.AccessTokenTTL = time.Duration(n) * time.Minute
	}

	if cfg.DatabaseURL == "" {
		return cfg, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.JWTSecret == "" {
		return cfg, fmt.Errorf("JWT_SECRET is required")
	}

	cfg.EdgeRateLimit = 100 // requests per window, per IP — generous, this is a coarse whole-API guard, not the fine-grained login limiter
	cfg.EdgeRateLimitWindow = time.Minute
	if v := os.Getenv("EDGE_RATE_LIMIT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("EDGE_RATE_LIMIT must be a number: %w", err)
		}
		cfg.EdgeRateLimit = n
	}

	// OAuth is deliberately optional at config-load time — a
	// deployment that hasn't set these up yet should still run fine
	// for password-based auth. httpapi.NewRouter only registers the
	// OAuth routes for providers that actually have both a client ID
	// and secret set.
	cfg.BaseURL = strings.TrimRight(os.Getenv("BASE_URL"), "/")
	cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	cfg.GitHubClientID = os.Getenv("GITHUB_CLIENT_ID")
	cfg.GitHubClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
	cfg.MicrosoftClientID = os.Getenv("MICROSOFT_CLIENT_ID")
	cfg.MicrosoftClientSecret = os.Getenv("MICROSOFT_CLIENT_SECRET")
	cfg.DiscordClientID = os.Getenv("DISCORD_CLIENT_ID")
	cfg.DiscordClientSecret = os.Getenv("DISCORD_CLIENT_SECRET")
	cfg.GitLabClientID = os.Getenv("GITLAB_CLIENT_ID")
	cfg.GitLabClientSecret = os.Getenv("GITLAB_CLIENT_SECRET")
	cfg.AppleClientID = os.Getenv("APPLE_CLIENT_ID")
	cfg.AppleTeamID = os.Getenv("APPLE_TEAM_ID")
	cfg.AppleKeyID = os.Getenv("APPLE_KEY_ID")
	// .env files are line-oriented, so a PEM arrives with its newlines
	// written as \n. Only unescape when the value looks like it
	// needs it, so a deployment that already passes a real multiline
	// value through its own secret manager is left alone.
	cfg.ApplePrivateKey = os.Getenv("APPLE_PRIVATE_KEY")
	if strings.Contains(cfg.ApplePrivateKey, `\n`) {
		cfg.ApplePrivateKey = strings.ReplaceAll(cfg.ApplePrivateKey, `\n`, "\n")
	}

	// Second factors are optional too, and for the same reason: a
	// deployment that hasn't set ENCRYPTION_KEY should still run fine for
	// password-only auth. main.go only wires the TOTP/WebAuthn stores when
	// the key is present, and cryden then reports those methods as
	// unavailable (404, same shape as an unconfigured OAuth provider)
	// rather than the server refusing to start.
	cfg.EncryptionKey = os.Getenv("ENCRYPTION_KEY")
	cfg.TOTPIssuerName = os.Getenv("TOTP_ISSUER_NAME")
	cfg.WebAuthnRPID = os.Getenv("WEBAUTHN_RP_ID")
	cfg.WebAuthnRPDisplayName = os.Getenv("WEBAUTHN_RP_DISPLAY_NAME")
	if origins := os.Getenv("WEBAUTHN_RP_ORIGINS"); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			cfg.WebAuthnRPOrigins = append(cfg.WebAuthnRPOrigins, strings.TrimSpace(o))
		}
	}

	// Anomaly detection and credential-stuffing detection — one switch,
	// because they are one store. Both threshold sets begin as the
	// engine's defaults and every knob below only replaces the one it
	// names (see the field comments for why that ordering is not
	// cosmetic).
	var err error
	if cfg.AnomalyDetection, err = envBool("ANOMALY_DETECTION", false); err != nil {
		return cfg, err
	}
	cfg.AnomalyThresholds = security.DefaultAnomalyThresholds
	cfg.CredentialStuffingThresholds = security.DefaultCredentialStuffingThresholds

	if cfg.AnomalyThresholds.Window, err = envMinutes("ANOMALY_WINDOW_MINUTES", cfg.AnomalyThresholds.Window); err != nil {
		return cfg, err
	}
	if cfg.AnomalyThresholds.HistorySize, err = envInt("ANOMALY_HISTORY_SIZE", cfg.AnomalyThresholds.HistorySize); err != nil {
		return cfg, err
	}
	if cfg.AnomalyThresholds.UserFailureVelocity, err = envInt("ANOMALY_USER_FAILURE_VELOCITY", cfg.AnomalyThresholds.UserFailureVelocity); err != nil {
		return cfg, err
	}
	if cfg.AnomalyThresholds.IPFailureVelocity, err = envInt("ANOMALY_IP_FAILURE_VELOCITY", cfg.AnomalyThresholds.IPFailureVelocity); err != nil {
		return cfg, err
	}
	// Zero disables the concurrent-session check specifically, the same
	// off switch every other AnomalyThresholds knob has.
	if cfg.AnomalyThresholds.MaxConcurrentSessions, err = envInt("ANOMALY_MAX_CONCURRENT_SESSIONS", cfg.AnomalyThresholds.MaxConcurrentSessions); err != nil {
		return cfg, err
	}
	if cfg.AnomalyThresholds.TokenReuseLookback, err = envMinutes("ANOMALY_TOKEN_REUSE_LOOKBACK_MINUTES", cfg.AnomalyThresholds.TokenReuseLookback); err != nil {
		return cfg, err
	}
	if cfg.CredentialStuffingThresholds.Window, err = envMinutes("CREDENTIAL_STUFFING_WINDOW_MINUTES", cfg.CredentialStuffingThresholds.Window); err != nil {
		return cfg, err
	}
	if cfg.CredentialStuffingThresholds.TargetAccounts, err = envInt("CREDENTIAL_STUFFING_TARGET_ACCOUNTS", cfg.CredentialStuffingThresholds.TargetAccounts); err != nil {
		return cfg, err
	}
	if cfg.CredentialStuffingThresholds.Cooldown, err = envMinutes("CREDENTIAL_STUFFING_COOLDOWN_MINUTES", cfg.CredentialStuffingThresholds.Cooldown); err != nil {
		return cfg, err
	}

	// Engine rate limiter. REDIS_URL is the only thing that decides where
	// the counters live (see the field comments for why the bounds
	// default to cryden's own numbers instead of zero); a URL main.go
	// cannot parse is a startup failure rather than a setting that was
	// quietly ignored.
	cfg.RedisURL = os.Getenv("REDIS_URL")
	if cfg.RateLimitAttempts, err = envInt("RATE_LIMIT_ATTEMPTS", 10); err != nil {
		return cfg, err
	}
	if cfg.RateLimitWindow, err = envSeconds("RATE_LIMIT_WINDOW_SECONDS", time.Minute); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// envInt reads an optional integer env var, falling back to def when it
// is unset or empty.
func envInt(name string, def int) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number: %w", name, err)
	}
	return n, nil
}

// envBool reads an optional boolean env var, falling back to def when it
// is unset or empty. Accepted spellings are strconv.ParseBool's —
// 1/0, t/f, true/false, T/F, TRUE/FALSE, True/False — so there is
// exactly one set of rules to remember rather than a second dialect
// defined here.
func envBool(name string, def bool) (bool, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false: %w", name, err)
	}
	return b, nil
}

func envMinutes(name string, def time.Duration) (time.Duration, error) {
	return envDurationIn(name, time.Minute, "minutes", def)
}

func envSeconds(name string, def time.Duration) (time.Duration, error) {
	return envDurationIn(name, time.Second, "seconds", def)
}

// envDurationIn reads an optional duration env var written as a whole
// number of unit (time.Minute or time.Second — the two granularities any
// knob here needs), falling back to def when it is unset or empty. A
// value of zero is passed through deliberately: it is a real "switch
// this check off" setting for several thresholds, and policing ranges
// here would mean a second copy of each knob's own valid range.
func envDurationIn(name string, unit time.Duration, unitName string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number of %s: %w", name, unitName, err)
	}
	return time.Duration(n) * unit, nil
}

func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if _, alreadySet := os.LookupEnv(key); !alreadySet {
			os.Setenv(key, val)
		}
	}
}
