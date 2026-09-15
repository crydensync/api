package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2/logger"
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

	// PasswordHasher selects which algorithm NEW password hashes are
	// written with — PasswordHasherBcrypt (the engine's default) or
	// PasswordHasherArgon2id. Switching is safe at any time and needs no
	// migration: cryden wraps whichever hasher it holds in a MultiHasher
	// that picks the verifier from each stored hash's own format, so
	// existing bcrypt hashes keep verifying and are rewritten one
	// successful login at a time. That gradual rewrite is what
	// GET /v1/admin/security/hash-migration reports on.
	//
	// An unrecognized value is a startup failure rather than a silent
	// fall back to bcrypt: someone who typed "argon" meant to turn
	// Argon2id on, and quietly leaving them on the weaker algorithm is
	// the one failure mode this setting must not have.
	PasswordHasher string

	// Argon2idParams is the cost configuration for that hasher. Like the
	// anomaly thresholds above, it starts as cryden's own
	// security.DefaultArgon2idParams and each ARGON2ID_* env var replaces
	// only the field it names — cryden reads a partially-filled params
	// struct as a real custom configuration used as-is, so a struct
	// assembled from only the env vars that happened to be set would
	// silently zero the rest and fail validation on a deployment that
	// meant to change one knob.
	//
	// Populated whether or not PasswordHasher selects argon2id, so
	// GET /v1/admin/security/hash-migration can report what the
	// deployment would write without reconstructing it separately.
	Argon2idParams security.Argon2idParams

	// APIKeyPrefix is the non-secret label every generated API key
	// starts with, as in "ck_9f3a1c02...". The point of the convention is
	// that a key leaked into a commit is greppable, so set it to
	// something recognisable as yours. cryden rejects whitespace and
	// underscores (the underscore separates the label from the secret),
	// and ignores it entirely unless the API key store is wired — which
	// main.go always does.
	APIKeyPrefix string

	// LogLevel is the threshold the cloud sink drops records below,
	// leaving the local copy untouched. Parsed by logger.ParseLevel,
	// whose error is the point: a typo defaulted to debug quietly
	// multiplies a vendor's bill.
	LogLevel logger.Level

	// CloudLogging turns the cloud sink on. Off by default, and off means
	// Config.Logger stays nil and the engine keeps its own console
	// default — there is nothing to configure for a deployment that ships
	// no logs anywhere.
	CloudLogging bool

	// CloudLogRedaction picks how personal data is stripped from the copy
	// leaving the building: CloudLogRedactionMask replaces it with a
	// fixed marker, CloudLogRedactionHash replaces it with a keyed digest
	// so the same address still reads as the same address across records
	// — "one IP, forty accounts" is exactly the shape credential
	// stuffing has, which a mask destroys. Hash mode needs
	// CloudLogHashKey.
	CloudLogRedaction string

	// CloudLogHashKey is the HMAC key for hash-mode redaction. It must be
	// the same on every replica or one address hashes two ways and the
	// correlation the mode exists for is gone — and it should be a value
	// of its own rather than a reuse of JWT_SECRET or ENCRYPTION_KEY.
	// cryden's NewHashingRedactor asks for that separation explicitly:
	// this key is handed to the component whose entire job is to hand its
	// output to a third party.
	CloudLogHashKey string

	// EmailTemplateDir is a directory holding message templates this repo
	// renders instead of its console senders' built-in lines. cryden
	// deliberately owns no template configuration at all — a message body
	// is a host app's copy, not the engine's — so this is entirely this
	// repo's. Empty keeps the console senders' hard-coded text
	// byte-for-byte; a dir that is set but unreadable or missing a
	// template is a startup failure, the same class of typo as an
	// unparseable REDIS_URL.
	EmailTemplateDir string
}

// PasswordHasher values. Bcrypt is the engine's own default and what an
// unset PASSWORD_HASHER leaves in place.
const (
	PasswordHasherBcrypt   = "bcrypt"
	PasswordHasherArgon2id = "argon2id"
)

// CloudLogRedaction values, matching cryden's two Redactor constructors.
const (
	CloudLogRedactionMask = "mask"
	CloudLogRedactionHash = "hash"
)

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

	// Password hashing. Bcrypt is the engine's default, so the only thing
	// this repo has to do for it is not pass a hasher — but the argon2id
	// parameters are assembled either way, because the hash-migration
	// report describes what the deployment is configured to write and
	// should not have to rebuild that answer from a second place.
	cfg.PasswordHasher = os.Getenv("PASSWORD_HASHER")
	switch cfg.PasswordHasher {
	case "":
		cfg.PasswordHasher = PasswordHasherBcrypt
	case PasswordHasherBcrypt, PasswordHasherArgon2id:
	default:
		return cfg, fmt.Errorf("PASSWORD_HASHER must be %q or %q, got %q",
			PasswordHasherBcrypt, PasswordHasherArgon2id, cfg.PasswordHasher)
	}

	// Defaults first, then one override per env var — see the field
	// comment for why a partially-filled struct would be a real problem
	// here rather than a harmless one.
	cfg.Argon2idParams = security.DefaultArgon2idParams
	if cfg.Argon2idParams.Memory, err = envUint32("ARGON2ID_MEMORY_KIB", cfg.Argon2idParams.Memory); err != nil {
		return cfg, err
	}
	if cfg.Argon2idParams.Iterations, err = envUint32("ARGON2ID_ITERATIONS", cfg.Argon2idParams.Iterations); err != nil {
		return cfg, err
	}
	if cfg.Argon2idParams.Parallelism, err = envUint8("ARGON2ID_PARALLELISM", cfg.Argon2idParams.Parallelism); err != nil {
		return cfg, err
	}
	if cfg.Argon2idParams.SaltLength, err = envUint32("ARGON2ID_SALT_LENGTH", cfg.Argon2idParams.SaltLength); err != nil {
		return cfg, err
	}
	if cfg.Argon2idParams.KeyLength, err = envUint32("ARGON2ID_KEY_LENGTH", cfg.Argon2idParams.KeyLength); err != nil {
		return cfg, err
	}

	// The engine applies "ck" as its own default, so writing it here too
	// is not redundant: the hash-migration report and the console both
	// want to show the prefix actually in force, and reading it back off
	// a config struct is the only way to get that without duplicating
	// cryden's default in a second place.
	cfg.APIKeyPrefix = os.Getenv("API_KEY_PREFIX")
	if cfg.APIKeyPrefix == "" {
		cfg.APIKeyPrefix = "ck"
	}

	// Cloud logging. LOG_LEVEL is parsed rather than defaulted on error:
	// see ParseLevel's own doc comment — a typo silently filed at debug
	// multiplies a vendor bill, and one silently filed at error throws
	// away the records someone was trying to keep.
	if cfg.LogLevel, err = logger.ParseLevel(envString("LOG_LEVEL", "info")); err != nil {
		return cfg, err
	}
	if cfg.CloudLogging, err = envBool("CLOUD_LOGGING", false); err != nil {
		return cfg, err
	}
	cfg.CloudLogRedaction = envString("CLOUD_LOG_REDACTION", CloudLogRedactionMask)
	switch cfg.CloudLogRedaction {
	case CloudLogRedactionMask, CloudLogRedactionHash:
	default:
		return cfg, fmt.Errorf("CLOUD_LOG_REDACTION must be %q or %q, got %q",
			CloudLogRedactionMask, CloudLogRedactionHash, cfg.CloudLogRedaction)
	}
	cfg.CloudLogHashKey = os.Getenv("CLOUD_LOG_HASH_KEY")
	// Required only when it would actually be used. Asking every
	// deployment for a second secret it has no purpose for is how a
	// required-when-unused setting ends up copy-pasted from JWT_SECRET,
	// which is the specific thing the key separation exists to prevent.
	if cfg.CloudLogRedaction == CloudLogRedactionHash && cfg.CloudLogHashKey == "" {
		return cfg, fmt.Errorf("CLOUD_LOG_HASH_KEY is required when CLOUD_LOG_REDACTION is %q", CloudLogRedactionHash)
	}

	// Email templates. Optional: unset keeps the console senders' own
	// text. main.go is what reports a directory that is set but broken.
	cfg.EmailTemplateDir = os.Getenv("EMAIL_TEMPLATE_DIR")

	return cfg, nil
}

// envString reads an optional string env var, falling back to def when it
// is unset or empty. An empty value counts as unset rather than as a
// setting of its own: every string knob here has a working default, so
// "set it to nothing" is never how a deployment means to say something.
func envString(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// envUint32 and envUint8 read an optional unsigned env var, falling back
// to def when it is unset or empty. They exist rather than an int-and-cast
// because Argon2id's cost parameters are unsigned all the way down: a
// negative value cast to uint8 does not fail, it wraps to 255 lanes, and
// the hasher would then take a deployment's typo as a configuration. So a
// minus sign is a startup failure here, which is the only place it can
// still be caught saying what it meant.
//
// The width is ParseUint's bitSize, which rejects an out-of-range value
// with its own "value out of range" — so the error names the variable and
// then says precisely what was wrong with it, without a second copy of
// each bound to keep in step.
func envUint32(name string, def uint32) (uint32, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative whole number: %w", name, err)
	}
	return uint32(n), nil
}

func envUint8(name string, def uint8) (uint8, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative whole number: %w", name, err)
	}
	return uint8(n), nil
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
