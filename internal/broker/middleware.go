package broker

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ctxKey is an unexported type for context keys to avoid collisions.
type ctxKey int

const (
	// ctxUID is the context key for the authenticated peer UID.
	ctxUID ctxKey = iota
)

// ContextUID extracts the peer UID from the request context.
// Returns 0 and false if not present.
func ContextUID(r *http.Request) (uint32, bool) {
	uid, ok := r.Context().Value(ctxUID).(uint32)
	return uid, ok
}

// withUID returns a new context with the UID attached.
func withUID(ctx context.Context, uid uint32) context.Context {
	return context.WithValue(ctx, ctxUID, uid)
}

// rateLimiter implements a per-UID sliding window rate limiter.
type rateLimiter struct {
	mu              sync.Mutex
	windows         map[uint32]*slidingWindow
	maxRequests     int
	windowDuration  time.Duration
}

// slidingWindow tracks request timestamps within the current window.
type slidingWindow struct {
	timestamps []time.Time
}

// newRateLimiter creates a rate limiter with the given limits.
// If maxRequests <= 0, rate limiting is effectively disabled.
func newRateLimiter(maxRequests int, windowSeconds int) *rateLimiter {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	return &rateLimiter{
		windows:        make(map[uint32]*slidingWindow),
		maxRequests:    maxRequests,
		windowDuration: time.Duration(windowSeconds) * time.Second,
	}
}

// Allow checks whether a request from the given UID should be allowed.
// Returns true if allowed, false if rate limited. When denied, retryAfter
// indicates how many seconds until a slot opens up.
func (rl *rateLimiter) Allow(uid uint32) (allowed bool, retryAfter time.Duration) {
	if rl.maxRequests <= 0 {
		return true, 0
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.windowDuration)

	w, ok := rl.windows[uid]
	if !ok {
		w = &slidingWindow{}
		rl.windows[uid] = w
	}

	// Prune timestamps older than the window.
	pruned := w.timestamps[:0]
	for _, ts := range w.timestamps {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	w.timestamps = pruned

	if len(w.timestamps) >= rl.maxRequests {
		// Calculate when the oldest request in the window will expire.
		oldest := w.timestamps[0]
		retryAfter = oldest.Add(rl.windowDuration).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter
	}

	w.timestamps = append(w.timestamps, now)
	return true, 0
}

// RateLimitMiddleware wraps an http.Handler and enforces per-UID rate limits.
// It requires the UID to already be set in the request context (via ConnContext).
func RateLimitMiddleware(rl *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := ContextUID(r)
		if !ok {
			http.Error(w, `{"error":"unable to identify caller"}`, http.StatusUnauthorized)
			return
		}

		allowed, retryAfter := rl.Allow(uid)
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"error":"rate limit exceeded","retry_after_seconds":%d}`, int(retryAfter.Seconds()))
			return
		}

		next.ServeHTTP(w, r)
	})
}
