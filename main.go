package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/lib/pq"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/postgres"

	"github.com/crydensync/api/config"
	"github.com/crydensync/api/httpapi"
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

	engine, err := cryden.New(cryden.Config{
		JWTSecret:      cfg.JWTSecret,
		Users:          postgres.NewUserStore(db),
		Sessions:       postgres.NewSessionStore(db),
		Audit:          postgres.NewAuditStore(db),
		Verifications:  postgres.NewVerificationStore(db),
		EmailSender:    &consoleEmailSender{}, // dev stand-in — see email_sender.go
		AccessTokenTTL: cfg.AccessTokenTTL,
	})
	if err != nil {
		log.Fatalf("failed to construct cryden engine: %v", err)
	}

	router := httpapi.NewRouter(engine, db)
	limiter := httpapi.NewEdgeRateLimiter(cfg.EdgeRateLimit, cfg.EdgeRateLimitWindow)
	handler := httpapi.WithCORS(cfg.CORSOrigins, httpapi.WithEdgeRateLimit(limiter, router))

	log.Printf("api listening on :%s (CORS origins: %v)", cfg.Port, cfg.CORSOrigins)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, handler))
}
