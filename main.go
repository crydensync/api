package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	// The SQLite driver, and only ever reachable when SQLITE_PATH is set.
	// modernc.org/sqlite is pure Go, so this costs a Postgres deployment
	// binary size and nothing else — no cgo, no C toolchain. cryden's
	// store/sqlite deliberately imports no driver of its own and leaves
	// the choice to the host; this is where this host makes it.
	_ "modernc.org/sqlite"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/admin"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/postgres"
	"github.com/crydensync/cryden/v2/store/sqlite"
	"github.com/crydensync/cryden/v2/token"

	"github.com/crydensync/api/anomalyreview"
	"github.com/crydensync/api/askai"
	"github.com/crydensync/api/config"
	"github.com/crydensync/api/digest"
	"github.com/crydensync/api/httpapi"
	"github.com/crydensync/api/operator"
	"github.com/crydensync/api/settings"
	"github.com/crydensync/api/shiplog"
	"github.com/crydensync/api/templates"
	"github.com/crydensync/api/usermeta"
	"github.com/crydensync/api/webhook"
)

// usage is what an unrecognised argument prints. It names the two things
// the binary does rather than listing flags, because there are no flags:
// `migrate` takes only --baseline and the server takes only env vars.
const usage = `usage: api [command]

  (no command)   run the server, applying any pending migrations first
                 unless SKIP_AUTO_MIGRATE=true
  migrate        apply any pending migrations and exit, starting no server
                 --baseline  record every embedded migration as already
                             applied, running none of them. For a Postgres
                             database that has this schema but no
                             schema_migrations table — see migrate.go`

func main() {
	// Dispatch before config.Load, deliberately. `api --help` on a machine
	// with no .env should print usage, not a complaint about JWT_SECRET,
	// and `api migrate` with a typo'd command should not half-load a
	// config first.
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fmt.Println(usage)
		return
	}

	switch {
	case len(args) == 0, len(args) == 1 && args[0] == "serve":
		serve()
	case args[0] == "migrate":
		runMigrate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", args[0], usage)
		os.Exit(2)
	}
}

// runMigrate is `api migrate`: bring the schema up to date, say what
// happened, exit. No server, no router, no engine — this is the command a
// SKIP_AUTO_MIGRATE deployment runs as its controlled deploy step, so it
// must not be able to start accepting traffic even by accident.
func runMigrate(args []string) {
	baselineOnly := false
	for _, a := range args {
		switch a {
		case "--baseline":
			baselineOnly = true
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %q for `migrate`\n\n%s\n", a, usage)
			os.Exit(2)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	db, err := openDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	var msg string
	if baselineOnly {
		msg, err = baseline(ctx, db, cfg.UsesSQLite())
	} else {
		msg, err = migrate(ctx, db, cfg.UsesSQLite())
	}
	if err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Printf("migrate: %s", msg)
}

// openDatabase opens and pings the configured backend. Shared by the
// server and `api migrate` so the two cannot drift into connecting
// differently — a migration applied over a connection with different
// pragmas is not the same migration.
func openDatabase(cfg config.Config) (*sql.DB, error) {
	// config.Load has already refused both-or-neither, so exactly one of
	// DATABASE_URL and SQLITE_PATH is set here.
	driver, dsn := "postgres", cfg.DatabaseURL
	if cfg.UsesSQLite() {
		driver, dsn = "sqlite", sqliteDSN(cfg.SQLitePath)
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open DB connection: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping DB: %w", err)
	}
	return db, nil
}

func serve() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	db, err := openDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}
	// Deliberately not `defer db.Close()`. Closing the database is the last
	// step of the teardown at the end of serve, for two reasons: a defer
	// would close it before the background workers have stopped writing
	// through it, and the log.Fatalf on the failure path calls os.Exit,
	// which runs no defers at all — so a defer here would silently not
	// happen in exactly the case where an unclean exit is most likely. On
	// SQLite that close is also the WAL checkpoint; see the teardown.

	// Migrations before any store is constructed, because every store
	// assumes its tables exist. The order matters more than it looks: a
	// deployment that skips this and finds a missing table later fails at
	// the first query that touches it, which is a confusing 500 rather
	// than a clear startup error.
	if cfg.SkipAutoMigrate {
		log.Printf("SKIP_AUTO_MIGRATE is set: starting without applying migrations. Run `api migrate` as a separate step — see README's note on migrations")
	} else {
		msg, err := migrate(context.Background(), db, cfg.UsesSQLite())
		if err != nil {
			log.Fatalf("migration failed: %v", err)
		}
		log.Printf("migrate: %s", msg)
	}

	if cfg.UsesSQLite() {
		// Both pragmas change behaviour this repo documents, and both
		// are set in the DSN above, so a failure here means the DSN and
		// this comment have drifted apart. Fatal rather than logged: a
		// silent foreign_keys=0 would drop the ON DELETE clauses the
		// schema depends on, and a silent busy_timeout=0 would turn a
		// concurrent write into an immediate SQLITE_BUSY.
		//
		// Checked even when SKIP_AUTO_MIGRATE is set: this is a property
		// of the connection, not of the schema, so it is as true for a
		// deployment that migrates separately as for one that does not.
		if err := sqlite.CheckPragmas(context.Background(), db); err != nil {
			log.Fatalf("sqlite connection pragmas are wrong: %v", err)
		}
		log.Printf("sqlite backend: %s (pragmas checked)", cfg.SQLitePath)

		// RequireAdmin's 501 is what actually keeps the admin console off a
		// SQLite deployment; these are the env vars an operator would
		// otherwise set and wonder about. Named rather than silently
		// ignored, because "I set WEBHOOK_URL and nothing happens" is a
		// worse morning than a warning at boot.
		var inert []string
		if cfg.SettingsEncryptionKey != "" {
			inert = append(inert, "SETTINGS_ENCRYPTION_KEY")
		}
		if cfg.WebhookURL != "" {
			inert = append(inert, "WEBHOOK_URL")
		}
		if cfg.CloudLogging {
			inert = append(inert, "CLOUD_LOGGING")
		}
		if cfg.DigestInterval > 0 {
			inert = append(inert, "DIGEST_INTERVAL_HOURS")
		}
		if cfg.EncryptionKey != "" {
			// The one variable here that is NOT inert: second factors are
			// cryden's own tables and work on SQLite. Named so the warning
			// below cannot be misread as covering it.
			log.Printf("sqlite backend: ENCRYPTION_KEY is set, so TOTP and passkeys remain available")
		}
		if len(inert) > 0 {
			log.Printf("WARNING: sqlite backend — %s configured but inert: the tables behind them are Postgres-only (see README)",
				strings.Join(inert, ", "))
		}
	}

	st := openStores(cfg, db)

	// The context every long-running thing in this process hangs off, and
	// the reason it exists: this server is expected to be stopped by a
	// signal — Ctrl-C in development, SIGTERM from systemd, Kubernetes or
	// `docker stop` in a deployment — and all three mean "finish what you
	// are doing and exit", not "die now".
	//
	// stopSignals cancels this context as well as unregistering the
	// handler, which is what the teardown at the bottom of main relies on:
	// on the signal path the workers have already seen the cancellation,
	// and on the listener-failure path nothing else would have told them.
	appCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	// The background workers, tracked so the teardown can wait for them
	// before closing the database handle they write through. Without the
	// Wait, "the workers have stopped" would be a hope rather than a fact,
	// and a delivery landing after db.Close() logs a confusing error.
	var workers sync.WaitGroup

	// Hoisted into locals rather than constructed inline in the config
	// literal below, because the router needs these same instances:
	// GET /v1/admin/security/hash-migration counts what the engine wrote,
	// and GET /v1/admin/users/{userID} reports a live session count — a
	// count from a second store object would describe sessions the engine
	// is not the one revoking.
	//
	// operators, metadata and reviews are this repo's own Postgres-only
	// tables; see openStores. On SQLite they are nil, which is safe
	// because every route that reads them sits behind RequireAdmin and
	// answers 501 there.
	operators, metadata, reviews := st.operators, st.metadata, st.reviews
	users, audit, sessions := st.users, st.audit, st.sessions

	// Webhook delivery log: this repo's own table, and the queue the
	// sender writes to. Declared as the interface rather than as
	// *webhook.PostgresStore so that leaving WEBHOOK_URL unset leaves it
	// genuinely nil — a typed nil inside a non-nil interface is a value
	// that passes every nil-interface check and then panics on use, and
	// the router's handlers guard on exactly that check.
	var webhookStore webhook.Store
	var webhookWake chan struct{}
	if cfg.WebhookURL != "" && !cfg.UsesSQLite() {
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
	if cfg.DigestInterval > 0 && !cfg.UsesSQLite() {
		digestStore = digest.NewStore(db)
	}

	// The AI settings: which LLM provider and which read-only database back
	// the AI-assisted admin features. Postgres-only, because the table
	// behind it is this repo's own (migrations/013). A SQLite deployment
	// gets no Secrets at all rather than one over a missing table — a nil
	// *Secrets is safe, since Configured() checks for nil and every
	// /v1/admin/settings/* route is behind RequireAdmin's 501 — and
	// askai.New(nil) answers 404 not_configured for the same reason.
	//
	// Otherwise always constructed: NewSecrets treats an unset
	// SETTINGS_ENCRYPTION_KEY as "this feature is off" rather than as a
	// startup failure, and the handlers then answer 404 not_configured,
	// matching how every other optional feature in this api behaves. Only
	// the key being *malformed* is fatal, and that is a configuration
	// mistake worth refusing to boot on.
	var settingsSecrets *settings.Secrets
	if !cfg.UsesSQLite() {
		settingsSecrets, err = settings.NewSecrets(settings.NewStore(db), cfg.SettingsEncryptionKey)
		if err != nil {
			log.Fatalf("invalid SETTINGS_ENCRYPTION_KEY: %v", err)
		}
		if settingsSecrets.Configured() {
			log.Printf("AI settings endpoints enabled (llm-provider, database-provider)")
		}
	}

	engineCfg := cryden.Config{
		JWTSecret:       cfg.JWTSecret,
		Users:           users,
		Sessions:        sessions,
		Audit:           audit,
		Verifications:   st.verifications,
		EmailSender:     &consoleEmailSender{Templates: emailTemplates},                           // dev stand-in — see email_sender.go
		MagicLinkSender: &consoleMagicLinkSender{BaseURL: cfg.BaseURL, Templates: emailTemplates}, // dev stand-in — see email_sender.go
		AccessTokenTTL:  cfg.AccessTokenTTL,
		OAuth:           st.oauth,

		// API keys are always wired: a machine credential is part of the
		// API surface this repo offers, not a second factor a deployment
		// opts into. The prefix is the non-secret label that makes a key
		// leaked into a commit greppable.
		APIKeys:      st.apiKeys,
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
		AccessTokenClaims: claimsProvider(operators, metadata),
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
		// From st, not constructed here: these are engine stores like every
		// other one, so they come from whichever backend openStores picked.
		// Building postgres.NewTOTPStore here instead would hand the engine
		// a store issuing $1 placeholders against a SQLite file — which
		// fails at the first query rather than at startup.
		engineCfg.TOTP = st.totp
		// Recovery codes are a fallback for whichever second factor is
		// enrolled, so they are only wired in when one can exist.
		engineCfg.RecoveryCodes = st.recovery

		if cfg.WebAuthnRPID != "" && cfg.WebAuthnRPDisplayName != "" && len(cfg.WebAuthnRPOrigins) > 0 {
			engineCfg.WebAuthn = st.webauthn
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
		engineCfg.Anomalies = st.anomalies
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

	// Account lockout, passed through rather than left implicit. cryden
	// reads these straight off its config with no defaulting of its own,
	// and the zero values are both wrong in the same direction: a zero
	// threshold locks an account on its first failed password, and a zero
	// duration locks it until an instant already past — which is to say
	// never. config.Load defaults them to cryden's own numbers (5 failures,
	// 15 minutes) so the engine runs what this deployment believes it runs,
	// and so GET /v1/admin/config-tuning describes settings that are
	// actually in force.
	engineCfg.LockoutThreshold = cfg.LockoutThreshold
	engineCfg.LockoutDuration = cfg.LockoutDuration
	// Declared here rather than inside the block below because the teardown
	// at the end of main closes it, and it is only non-nil when REDIS_URL
	// asked for it.
	var redisClient *redis.Client
	if cfg.RedisURL != "" {
		redisOpts, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			log.Fatalf("invalid REDIS_URL: %v", err)
		}
		// Hoisted out of the constructor call below so the teardown can
		// close it. The client is this process's, not cryden's — the
		// limiter is handed a client that is already connected and only
		// ever talks to it through the Scripter interface — so closing it
		// is this repo's job and nothing else would do it.
		redisClient = redis.NewClient(redisOpts)
		limiter, err := security.NewRedisRateLimiter(redisClient, cfg.RateLimitAttempts, cfg.RateLimitWindow)
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
	if cfg.CloudLogging && !cfg.UsesSQLite() {
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
	// Run takes appCtx, so a shutdown stops it at the same moment it stops
	// accepting requests rather than after the drain: the two are
	// independent, and holding a delivery back until the HTTP side has
	// finished would only delay the exit. A delivery cut off mid-flight is
	// what the stale reclaim exists for — see RunOnce's own note.
	if webhookStore != nil {
		worker := webhook.NewWorker(webhookStore, cfg.WebhookURL, cfg.WebhookSecret)
		worker.MaxAttempts = cfg.WebhookMaxAttempts
		worker.Wake = webhookWake
		worker.Log = log.Default()
		// WaitGroup.Go (Go 1.25) rather than Add plus a goroutine: the
		// counter and the goroutine are one statement, so the pairing that
		// has to stay balanced cannot drift.
		workers.Go(func() { worker.Run(appCtx) })

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
	// Run takes appCtx for the same reason the worker does. A digest cut
	// off mid-build records nothing and is retried at the next interval,
	// which is the right outcome — half a window written to the history
	// would be worse than no row.
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
		workers.Go(func() { scheduler.Run(appCtx) })
		log.Printf("scheduled digests enabled: one every %s", cfg.DigestInterval)
	}

	// Hoisted out of the Deps literal below because the teardown closes it:
	// the cached provider pair holds a second database connection (the
	// read-only one behind the AI query surface), and nothing else would
	// release it. See Service.Close.
	askAI := askai.New(settingsSecrets)

	router := httpapi.NewRouter(httpapi.Deps{
		Engine: engine,
		DB:     db,
		Config: cfg,
		Audit:  audit,
		Users:  users,
		Meta:   metadata,
		Hooks:  webhookStore,

		Sessions: sessions,

		Shipped: shippedLog,

		Digests: digestStore,

		Settings: settingsSecrets,

		Reviews: reviews,

		// Built over the same Secrets the settings endpoints write
		// through, so a provider saved in the console is the one the
		// widget's next question uses. Always constructed, even with no
		// encryption key: it reads the settings on each question rather
		// than being wired once at startup, so there is nothing to
		// re-wire when an operator saves a change — it answers 404
		// not_configured until then, like every other unconfigured
		// feature here.
		AskAI: askAI,
	})
	limiter := httpapi.NewEdgeRateLimiter(cfg.EdgeRateLimit, cfg.EdgeRateLimitWindow)
	handler := httpapi.WithCORS(cfg.CORSOrigins, httpapi.WithEdgeRateLimit(limiter, router))

	// The listener is opened before the server starts serving so a port
	// already in use is a startup failure that says so, rather than an
	// error out of Serve after the line below has claimed the API is up.
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", srv.Addr, err)
	}

	// Serve in a goroutine, buffered so it can never block on a receiver
	// that has already moved on — on the signal path nothing reads this
	// channel until the drain has finished.
	listenerErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			// Shutdown or Close was called, which is the normal way out
			// of Serve rather than a failure to report.
			err = nil
		}
		listenerErr <- err
	}()

	log.Printf("api listening on :%s (CORS origins: %v)", cfg.Port, cfg.CORSOrigins)

	var serveErr error
	select {
	case serveErr = <-listenerErr:
		// The listener stopped on its own — a closed socket, a descriptor
		// limit. Nothing asked it to stop, so there is nothing to drain.
		log.Printf("server stopped serving: %v", serveErr)
	case <-appCtx.Done():
		log.Printf("shutdown signal received: draining in-flight requests (up to %s)", shutdownDrainTimeout)
		serveErr = drain(srv, shutdownDrainTimeout)
		// Serve has returned by now on every path Shutdown can take, so
		// this is where a listener that failed *during* the drain reports
		// itself — and the buffered channel is why it could not have been
		// dropped in the gap. A clean drain leaves nil here and keeps
		// serveErr nil.
		if err := <-listenerErr; serveErr == nil {
			serveErr = err
		}
	}

	// ---- teardown ----
	//
	// Reached on both paths above, and written once rather than deferred
	// so that the order is visible and deliberate. The order is: stop the
	// workers, release everything holding a connection to something else,
	// then close the database last.
	//
	// stopSignals cancels appCtx, which is what stops the workers on the
	// listener-failure path; on the signal path they saw it already. Either
	// way it happens before anything they write through is closed, and the
	// Wait is what makes that a fact rather than a likelihood.
	stopSignals()
	workers.Wait()

	// The AI query surface's own read-only connection pool. Errors are
	// logged rather than fatal: by this point the process is leaving, and
	// a pool that will not close is not a reason to skip the rest.
	if err := askAI.Close(); err != nil {
		log.Printf("closing the ask-ai providers: %v", err)
	}
	if redisClient != nil {
		if err := redisClient.Close(); err != nil {
			log.Printf("closing the Redis client: %v", err)
		}
	}

	// Last, and the reason this is not the deferred call it used to be:
	// closing the database is what checkpoints the WAL on SQLite, and the
	// os.Exit in log.Fatalf below would skip a defer. On a SQLite
	// deployment this call is the difference between a schema that is in
	// api.db and a schema that is only in api.db-wal.
	if err := db.Close(); err != nil {
		log.Printf("closing the database: %v", err)
	}

	if serveErr != nil {
		log.Fatalf("server: %v", serveErr)
	}
	log.Printf("shutdown complete")
}

// sqliteDSN builds the connection string for SQLITE_PATH.
//
// The three pragmas are load-bearing rather than decorative, and this is
// the only place they can be set: SQLite pragmas are per-connection while
// *sql.DB is a pool, so a DSN is what applies them to every connection
// the pool opens. cryden's store/sqlite documents all three and its
// CheckPragmas reports the first two at startup, which is why this
// function and that check are only useful together.
//
//   - foreign_keys(1) — OFF by default, and it is what makes the schema's
//     ON DELETE clauses run at all.
//   - busy_timeout(5000) — 0 by default, which turns a second concurrent
//     writer into an immediate SQLITE_BUSY instead of a short wait. Five
//     seconds is cryden's own documented example value.
//   - journal_mode(WAL) — lets readers proceed during a write. Unlike the
//     other two it persists in the file, so setting it here is for
//     clarity as much as effect.
//
// The parameter syntax is modernc's (`_pragma=name(value)`); mattn's
// driver spells the same three differently, so this literal and the blank
// import in the import block are a pair — changing one without the other
// gives a DSN that parses and silently sets nothing.
func sqliteDSN(path string) string {
	return "file:" + path + "?" + strings.Join([]string{
		"_pragma=foreign_keys(1)",
		"_pragma=busy_timeout(5000)",
		"_pragma=journal_mode(WAL)",
	}, "&")
}

// claimsProvider returns the token-claims provider for this deployment, or
// nil on a backend that has none.
//
// It exists so the nil case is decided in one place instead of at the call
// site, because the call site cannot express it: usermeta.ClaimsProvider
// takes an interface, and handing it a nil *PostgresStore gives it a
// non-nil interface holding a nil pointer — which passes its own nil check
// and then panics on the first query. That is a panic on every login and
// every refresh, not a degraded feature.
//
// A SQLite deployment is the nil case (both stores are Postgres-only; see
// openStores) and returning nil is the correct answer rather than a
// workaround: cryden already treats a nil provider as "this host attaches
// no extra claims", and on SQLite there is nothing to attach — no operators
// table, so no "role" claim for anyone, and no metadata table, so no mapped
// keys. The consequence is worth stating because it is the same fact as
// AdminOnly's 501 seen from the other end: a SQLite deployment issues
// tokens that no admin route would accept anyway.
func claimsProvider(operators *operator.Store, metadata *usermeta.PostgresStore) token.ClaimsProvider {
	if operators == nil && metadata == nil {
		return nil
	}
	return usermeta.ClaimsProvider(metadata, operators)
}

// stores is every engine store for whichever backend this deployment runs
// on, plus the repo-owned ones that exist only on Postgres.
type stores struct {
	users         store.UserStore
	sessions      store.SessionStore
	audit         store.AuditStore
	verifications store.VerificationStore
	oauth         store.OAuthStore
	totp          store.TOTPStore
	webauthn      store.WebAuthnCredentialStore
	recovery      store.RecoveryCodeStore
	apiKeys       store.APIKeyStore
	anomalies     store.AnomalyStore

	// Postgres-only. These three back this repo's own tables —
	// operators, user_metadata and reviewed_anomalies — which Tier 6
	// scoped out of SQLite deliberately rather than by omission: the
	// admin console is a Postgres feature, and building its table set a
	// second time for a backend whose users almost certainly do not run
	// it is maintenance for nothing. Nil on SQLite, where no route can
	// reach them because they are all behind RequireAdmin's 501.
	operators *operator.Store
	metadata  *usermeta.PostgresStore
	reviews   *anomalyreview.PostgresStore
}

// openStores constructs the engine's stores for the configured backend.
//
// The two arms construct the same set of interfaces from the same
// *sql.DB, which is what makes this a switch rather than two code paths:
// cryden's store/sqlite implements every store interface store/postgres
// does, so nothing downstream of here knows or cares which ran. The one
// thing that is genuinely backend-specific is the Postgres-only block
// above, and that is a scope decision this repo made rather than a
// capability cryden lacks.
func openStores(cfg config.Config, db *sql.DB) stores {
	if cfg.UsesSQLite() {
		return stores{
			users:         sqlite.NewUserStore(db),
			sessions:      sqlite.NewSessionStore(db),
			audit:         sqlite.NewAuditStore(db),
			verifications: sqlite.NewVerificationStore(db),
			oauth:         sqlite.NewOAuthStore(db),
			totp:          sqlite.NewTOTPStore(db),
			webauthn:      sqlite.NewWebAuthnStore(db),
			recovery:      sqlite.NewRecoveryCodeStore(db),
			apiKeys:       sqlite.NewAPIKeyStore(db),
			anomalies:     sqlite.NewAnomalyStore(db),
		}
	}
	return stores{
		users:         postgres.NewUserStore(db),
		sessions:      postgres.NewSessionStore(db),
		audit:         postgres.NewAuditStore(db),
		verifications: postgres.NewVerificationStore(db),
		oauth:         postgres.NewOAuthStore(db),
		totp:          postgres.NewTOTPStore(db),
		webauthn:      postgres.NewWebAuthnStore(db),
		recovery:      postgres.NewRecoveryCodeStore(db),
		apiKeys:       postgres.NewAPIKeyStore(db),
		anomalies:     postgres.NewAnomalyStore(db),

		operators: operator.NewStore(db),
		metadata:  usermeta.NewStore(db),
		reviews:   anomalyreview.NewStore(db),
	}
}
