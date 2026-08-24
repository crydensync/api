package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
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

	return cfg, nil
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
