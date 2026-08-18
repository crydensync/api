package httpapi

import (
	"net/http"
	"sync"
	"time"
)

// EdgeRateLimiter is a coarse, per-IP request limiter applied to
// EVERY request, on top of (not instead of) the engine's own
// per-user login/signup rate limiting. The engine's limiter protects
// specific auth operations from credential-stuffing; this one
// protects the whole API surface from being hammered generally.
//
// Same honest limitation as the engine's InMemoryRateLimiter: this is
// in-memory, per-process. It resets on restart and does NOT share
// state across multiple instances behind a load balancer — fine for
// a single-instance deployment, not sufficient once you scale
// horizontally. A Redis-backed version is the natural upgrade path
// later, not built here.
type EdgeRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string]*windowCounter
}

type windowCounter struct {
	count     int
	windowEnd time.Time
}

func NewEdgeRateLimiter(limit int, window time.Duration) *EdgeRateLimiter {
	return &EdgeRateLimiter{
		limit:    limit,
		window:   window,
		counters: make(map[string]*windowCounter),
	}
}

func (l *EdgeRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	c, ok := l.counters[key]
	if !ok || now.After(c.windowEnd) {
		l.counters[key] = &windowCounter{count: 1, windowEnd: now.Add(l.window)}
		return true
	}
	if c.count >= l.limit {
		return false
	}
	c.count++
	return true
}

// WithEdgeRateLimit wraps a handler, rejecting requests over the
// per-IP limit with 429. CORS preflight (OPTIONS) requests are not
// counted — browsers send these automatically and shouldn't consume
// a caller's real request budget.
func WithEdgeRateLimit(limiter *EdgeRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !limiter.allow(CallerIP(r)) {
			writeErr(w, errEdgeRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}
