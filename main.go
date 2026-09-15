package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/postgres"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/httpapi"
	"github.com/crydensync/api/operator"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to open DB connection: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatalf("failed to ping DB: %v", err)
	}

	operators := operator.NewStore(db)

	engineCfg := cryden.Config{
		JWTSecret:       cfg.JWTSecret,
		Users:           postgres.NewUserStore(db),
		Sessions:        postgres.NewSessionStore(db),
		Audit:           postgres.NewAuditStore(db),
		Verifications:   postgres.NewVerificationStore(db),
		EmailSender:     &consoleEmailSender{},                         // dev stand-in — see email_sender.go
		MagicLinkSender: &consoleMagicLinkSender{BaseURL: cfg.BaseURL}, // dev stand-in — see email_sender.go
		AccessTokenTTL:  cfg.AccessTokenTTL,
		OAuth:           postgres.NewOAuthStore(db),

		// Attaches a "role" claim for console operators only — an
		// ordinary end user's token gets no extra claims at all, not
		// even role="user". See operator/store.go for why this is a
		// separate table rather than anything on cryden's own User.
		AccessTokenClaims: token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
			role, isOperator, err := operators.RoleFor(ctx, userID)
			if err != nil {
				return nil, err
			}
			if !isOperator {
				return nil, nil
			}
			return map[string]any{"role": role}, nil
		}),
	}

	// Second factors are all-or-nothing on ENCRYPTION_KEY: cryden refuses
	// to build an engine with a TOTP or WebAuthn store set and no
	// encryption key, and a half-configured deployment would be worse than
	// one that simply reports those methods as unavailable. Unavailable is
	// reported per-request (404, same shape as an unconfigured OAuth
	// provider), never as a refusal to start.
	if cfg.EncryptionKey != "" {
		engineCfg.EncryptionKey = cfg.EncryptionKey
		engineCfg.TOTPIssuerName = cfg.TOTPIssuerName
		engineCfg.TOTP = postgres.NewTOTPStore(db)
		// Recovery codes are a fallback for whichever second factor is
		// enrolled, so they are only wired in when one can exist.
		engineCfg.RecoveryCodes = postgres.NewRecoveryCodeStore(db)

		if cfg.WebAuthnRPID != "" && cfg.WebAuthnRPDisplayName != "" && len(cfg.WebAuthnRPOrigins) > 0 {
			engineCfg.WebAuthn = postgres.NewWebAuthnStore(db)
			engineCfg.WebAuthnRPID = cfg.WebAuthnRPID
			engineCfg.WebAuthnRPDisplayName = cfg.WebAuthnRPDisplayName
			engineCfg.WebAuthnRPOrigins = cfg.WebAuthnRPOrigins
		} else if cfg.WebAuthnRPID != "" || cfg.WebAuthnRPDisplayName != "" || len(cfg.WebAuthnRPOrigins) > 0 {
			// Partial WebAuthn config is a deployment mistake worth
			// saying out loud: passkeys stay off until all three are
			// set, rather than half-working in a way that only ever
			// shows up as a ceremony failure in the browser.
			log.Printf("WARNING: WebAuthn disabled — passkeys need WEBAUTHN_RP_ID, WEBAUTHN_RP_DISPLAY_NAME and WEBAUTHN_RP_ORIGINS all set")
		}
	}

	// Login anomaly detection and credential-stuffing detection share one
	// store as their on/off switch — they are the same login-attempt
	// history read two ways — and are off unless explicitly enabled. Both
	// are report-only in the engine: a flagged attempt records an audit
	// event and nothing else, no login is ever blocked or delayed by
	// them.
	if cfg.AnomalyDetection {
		engineCfg.Anomalies = postgres.NewAnomalyStore(db)
		engineCfg.AnomalyThresholds = cfg.AnomalyThresholds
		engineCfg.CredentialStuffingThresholds = cfg.CredentialStuffingThresholds
	}

	// The engine's own rate limiter — login, signup, magic-link — is
	// in-process by default. REDIS_URL swaps in the shared one so several
	// replicas count against a single window instead of each keeping its
	// own. Nothing dials Redis here: like every store, the limiter is
	// injected already constructed and the client is owned by this
	// process, exactly like the database handle above. An unreachable
	// Redis therefore shows up as a denied (failing-closed) rate-limit
	// check on the calls that use it rather than as a startup failure —
	// cryden's own documented trade-off for the shared limiter.
	engineCfg.RateLimitAttempts = cfg.RateLimitAttempts
	engineCfg.RateLimitWindow = cfg.RateLimitWindow
	if cfg.RedisURL != "" {
		redisOpts, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			log.Fatalf("invalid REDIS_URL: %v", err)
		}
		limiter, err := security.NewRedisRateLimiter(redis.NewClient(redisOpts), cfg.RateLimitAttempts, cfg.RateLimitWindow)
		if err != nil {
			log.Fatalf("failed to build the Redis rate limiter: %v", err)
		}
		engineCfg.RateLimiter = limiter
		log.Printf("engine rate limiting is Redis-backed")
	}

	engine, err := cryden.New(engineCfg)
	if err != nil {
		log.Fatalf("failed to construct cryden engine: %v", err)
	}

	router := httpapi.NewRouter(engine, db, cfg)
	limiter := httpapi.NewEdgeRateLimiter(cfg.EdgeRateLimit, cfg.EdgeRateLimitWindow)
	handler := httpapi.WithCORS(cfg.CORSOrigins, httpapi.WithEdgeRateLimit(limiter, router))

	log.Printf("api listening on :%s (CORS origins: %v)", cfg.Port, cfg.CORSOrigins)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, handler))
}
