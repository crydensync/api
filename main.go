package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	_ "github.com/lib/pq"

	"github.com/crydensync/cryden/v2"
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

	engine, err := cryden.New(cryden.Config{
		JWTSecret:      cfg.JWTSecret,
		Users:          postgres.NewUserStore(db),
		Sessions:       postgres.NewSessionStore(db),
		Audit:          postgres.NewAuditStore(db),
		Verifications:  postgres.NewVerificationStore(db),
		EmailSender:    &consoleEmailSender{}, // dev stand-in — see email_sender.go
		AccessTokenTTL: cfg.AccessTokenTTL,
		OAuth:          postgres.NewOAuthStore(db),

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
	})
	if err != nil {
		log.Fatalf("failed to construct cryden engine: %v", err)
	}

	router := httpapi.NewRouter(engine, db, cfg)
	limiter := httpapi.NewEdgeRateLimiter(cfg.EdgeRateLimit, cfg.EdgeRateLimitWindow)
	handler := httpapi.WithCORS(cfg.CORSOrigins, httpapi.WithEdgeRateLimit(limiter, router))

	log.Printf("api listening on :%s (CORS origins: %v)", cfg.Port, cfg.CORSOrigins)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, handler))
}
