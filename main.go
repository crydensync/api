package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/admin"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/postgres"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/digest"
	"github.com/crydensync/api/httpapi"
	"github.com/crydensync/api/operator"
	"github.com/crydensync/api/shiplog"
	"github.com/crydensync/api/templates"
	"github.com/crydensync/api/usermeta"
	"github.com/crydensync/api/webhook"
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

	// Hoisted into locals rather than constructed inline in the config
	// literal below, because the router needs these same two instances:
	// GET /v1/admin/security/hash-migration counts what the engine wrote,
	// and counting a different store object — or a second connection pool
	// with its own snapshot — is how that report would quietly disagree
	// with the engine it is reporting on.
	users := postgres.NewUserStore(db)
	audit := postgres.NewAuditStore(db)

	// Per-user metadata: this repo's own table, merged into the access
	// token's claims below. See usermeta's package doc for why the
	// reserved-key rule lives in the store rather than in the handler.
	metadata := usermeta.NewStore(db)

	// Webhook delivery log: this repo's own table, and the queue the
	// sender writes to. Declared as the interface rather than as
	// *webhook.PostgresStore so that leaving WEBHOOK_URL unset leaves it
	// genuinely nil — a typed nil inside a non-nil interface is a value
	// that passes every nil-interface check and then panics on use, and
	// the router's handlers guard on exactly that check.
	var webhookStore webhook.Store
	var webhookWake chan struct{}
	if cfg.WebhookURL != "" {
		webhookStore = webhook.NewStore(db)
		// Capacity 1, used purely as a nudge: the sender's job is to make
		// the row and return, so a full channel must drop the hint rather
		// than block. The worker's poll interval is the safety net for a
		// hint dropped here.
		webhookWake = make(chan struct{}, 1)
	}

	// Email templates are optional and entirely this repo's: cryden owns
	// no message copy. An unset EMAIL_TEMPLATE_DIR leaves both senders
	// printing their own built-in line, byte for byte as before.
	var emailTemplates *templates.Set
	if cfg.EmailTemplateDir != "" {
		emailTemplates, err = templates.Load(cfg.EmailTemplateDir)
		if err != nil {
			log.Fatalf("invalid EMAIL_TEMPLATE_DIR: %v", err)
		}
		log.Printf("email templates loaded from %s", cfg.EmailTemplateDir)
	}

	// Digest history: this repo's own table, written only by the scheduler
	// below. Declared as the interface rather than as *digest.PostgresStore
	// for the same reason webhookStore is — a typed nil in a non-nil
	// interface passes every nil check and then panics on use, and the
	// router's handler guards on exactly that check.
	var digestStore digest.Store
	if cfg.DigestInterval > 0 {
		digestStore = digest.NewStore(db)
	}

	engineCfg := cryden.Config{
		JWTSecret:       cfg.JWTSecret,
		Users:           users,
		Sessions:        postgres.NewSessionStore(db),
		Audit:           audit,
		Verifications:   postgres.NewVerificationStore(db),
		EmailSender:     &consoleEmailSender{Templates: emailTemplates},                           // dev stand-in — see email_sender.go
		MagicLinkSender: &consoleMagicLinkSender{BaseURL: cfg.BaseURL, Templates: emailTemplates}, // dev stand-in — see email_sender.go
		AccessTokenTTL:  cfg.AccessTokenTTL,
		OAuth:           postgres.NewOAuthStore(db),

		// API keys are always wired: a machine credential is part of the
		// API surface this repo offers, not a second factor a deployment
		// opts into. The prefix is the non-secret label that makes a key
		// leaked into a commit greppable.
		APIKeys:      postgres.NewAPIKeyStore(db),
		APIKeyPrefix: cfg.APIKeyPrefix,

		// The claims every access token carries for its user: "role" for
		// console operators, plus every metadata key the admin console has
		// mapped. usermeta.ClaimsProvider owns the merge — including the
		// rule that "role" is refused as a metadata key, which is exactly
		// why it lives in a package a test can reach rather than in a
		// closure here.
		//
		// This runs on EVERY login and every refresh — roughly once per
		// ACCESS_TOKEN_TTL per active session — and costs two queries.
		// That is the price of claims that are current rather than
		// frozen at signup, and it is why the engine calls a claims
		// provider on the hot path only when a host asks it to.
		AccessTokenClaims: usermeta.ClaimsProvider(metadata, operators),
	}

	// Password hashing. Leaving Hasher unset is what selects bcrypt — the
	// engine builds its own default from BcryptCost. Selecting argon2id
	// here is the whole switch: cryden wraps whichever hasher it holds in
	// a MultiHasher that reads the verifier off each stored hash, so
	// changing this rewrites hashes one successful login at a time and
	// never invalidates a credential.
	if cfg.PasswordHasher == config.PasswordHasherArgon2id {
		hasher, err := security.NewArgon2idHasher(cfg.Argon2idParams)
		if err != nil {
			log.Fatalf("invalid Argon2id parameters: %v", err)
		}
		engineCfg.Hasher = hasher
		log.Printf("new password hashes are written with Argon2id (memory %d KiB, iterations %d, parallelism %d)",
			cfg.Argon2idParams.Memory, cfg.Argon2idParams.Iterations, cfg.Argon2idParams.Parallelism)
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

	// Webhooks, set here rather than in the literal above for the same
	// reason the hasher is: assigning a nil *webhook.Sender into a
	// notify.WebhookSender field would make it non-nil as far as cryden
	// can tell, and cryden reads a non-nil sender with no events as a
	// request for DefaultWebhookEvents. So the field is only ever touched
	// when there is an endpoint to deliver to.
	//
	// Setting these two fields IS the dispatch wiring: cryden wraps
	// Config.Audit in its own webhookRecorder, so there is no registry to
	// populate. Leaving WebhookEvents empty is the deliberate default —
	// cryden then uses DefaultWebhookEvents, which names the sixteen
	// events worth waking someone for and excludes
	// login_success/login_failed/token_rotated, the three that fire
	// constantly and say nothing.
	if webhookStore != nil {
		engineCfg.Webhooks = &webhook.Sender{Store: webhookStore, Wake: webhookWake}
		engineCfg.WebhookEvents = cfg.WebhookEvents
	}

	// Cloud logging. Off by default, and off means Config.Logger stays nil
	// and the engine keeps its own console default — there is nothing to
	// configure for a deployment that ships no logs anywhere.
	//
	// The composition is the one cryden's own logger package doc
	// prescribes, and the nesting is the whole point: the console logger
	// gets every record at full detail, while the shipped copy passes
	// through the level filter and the redactor first, so only it loses
	// the IP address that makes an incident debuggable. Wrapping the
	// fan-out in the redactor instead would strip both copies.
	var shippedLog shiplog.Store
	if cfg.CloudLogging {
		shipped := shiplog.NewLogger(shiplog.NewStore(db))
		shipped.Errors = log.Default()
		shippedLog = shipped.Store

		var redacted logger.Logger
		if cfg.CloudLogRedaction == config.CloudLogRedactionHash {
			// Keyed rather than a bare digest, and keyed with a value of
			// its own: the whole IPv4 space is 2^32 values, so an unkeyed
			// hash of an address is a lookup table away from being the
			// address. cryden's NewHashingRedactor asks for key
			// separation explicitly, and config.Load is what enforces
			// that the key is present.
			var err error
			if redacted, err = logger.NewHashingRedactor(shipped, cfg.CloudLogHashKey); err != nil {
				log.Fatalf("invalid cloud log redaction: %v", err)
			}
		} else {
			redacted = logger.NewMaskingRedactor(shipped)
		}

		engineCfg.Logger = logger.NewMultiLogger(
			logger.NewConsoleJSONLogger(),
			logger.NewLevelFilter(redacted, cfg.LogLevel),
		)
		log.Printf("cloud logging enabled: records at %s and above are redacted (%s) and recorded in shipped_log_events",
			cfg.LogLevel, cfg.CloudLogRedaction)
	}

	engine, err := cryden.New(engineCfg)
	if err != nil {
		log.Fatalf("failed to construct cryden engine: %v", err)
	}

	// The delivery worker. Started only when there is somewhere to
	// deliver to, so an unconfigured deployment runs no goroutine at all.
	//
	// Run takes context.Background() because this repo has no graceful
	// shutdown anywhere yet — main.go ends at log.Fatal(ListenAndServe),
	// which exits the process and every goroutine with it. Introducing a
	// real shutdown touches every component and is its own change; noted
	// in PROGRESS.md as still owed rather than smuggled in here.
	if webhookStore != nil {
		worker := webhook.NewWorker(webhookStore, cfg.WebhookURL, cfg.WebhookSecret)
		worker.MaxAttempts = cfg.WebhookMaxAttempts
		worker.Wake = webhookWake
		worker.Log = log.Default()
		go worker.Run(context.Background())

		events := len(cfg.WebhookEvents)
		if events == 0 {
			events = len(cryden.DefaultWebhookEvents())
		}
		log.Printf("webhook deliveries enabled: %d event types, up to %d attempts each", events, cfg.WebhookMaxAttempts)
	}

	// The digest schedule. Started only when DIGEST_INTERVAL_HOURS asked
	// for one, so an unconfigured deployment runs no goroutine and writes
	// no rows — the same shape as the webhook worker above.
	//
	// The builder closes over the engine rather than this package taking
	// one: the report itself is cryden's (DigestSince), and digest's job is
	// only to record what it produced. The window is computed here and
	// passed in, so the row states the exact interval the engine was asked
	// to count over rather than one reconstructed from the text afterwards.
	//
	// Run takes context.Background() for the same reason the worker does:
	// this repo still has no graceful shutdown, and that is noted in
	// PROGRESS.md as owed rather than smuggled in behind a second
	// goroutine.
	if digestStore != nil {
		scheduler := &digest.Scheduler{
			Store:    digestStore,
			Interval: cfg.DigestInterval,
			Log:      log.Default(),
			Build: func(ctx context.Context) (digest.Entry, error) {
				since := time.Now().Add(-admin.DefaultDigestWindow)
				text, err := cryden.DigestSince(ctx, engine, since)
				if err != nil {
					return digest.Entry{}, err
				}
				return digest.Entry{
					WindowStart: since.UTC(),
					WindowEnd:   time.Now().UTC(),
					Text:        text,
				}, nil
			},
		}
		go scheduler.Run(context.Background())
		log.Printf("scheduled digests enabled: one every %s", cfg.DigestInterval)
	}

	router := httpapi.NewRouter(httpapi.Deps{
		Engine: engine,
		DB:     db,
		Config: cfg,
		Audit:  audit,
		Users:  users,
		Meta:   metadata,
		Hooks:  webhookStore,

		Shipped: shippedLog,

		Digests: digestStore,
	})
	limiter := httpapi.NewEdgeRateLimiter(cfg.EdgeRateLimit, cfg.EdgeRateLimitWindow)
	handler := httpapi.WithCORS(cfg.CORSOrigins, httpapi.WithEdgeRateLimit(limiter, router))

	log.Printf("api listening on :%s (CORS origins: %v)", cfg.Port, cfg.CORSOrigins)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, handler))
}
