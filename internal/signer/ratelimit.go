package signer

import (
	"sync"
	"time"
)

// SignerRateLimiter enforces per-window signing limits.
type SignerRateLimiter struct {
	mu           sync.Mutex
	maxPerWindow int
	windowSize   time.Duration
	requests     []time.Time
}

// NewSignerRateLimiter creates a rate limiter.
// maxPerWindow=0 means no limit.
func NewSignerRateLimiter(maxPerWindow int, windowSize time.Duration) *SignerRateLimiter {
	return &SignerRateLimiter{
		maxPerWindow: maxPerWindow,
		windowSize:   windowSize,
		requests:     make([]time.Time, 0, maxPerWindow),
	}
}

// Allow checks if a signing request is allowed.
// Returns true if within limits, false if rate-limited.
func (rl *SignerRateLimiter) Allow() bool {
	if rl.maxPerWindow <= 0 {
		return true // no limit configured
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.windowSize)

	// Prune expired entries
	valid := rl.requests[:0]
	for _, t := range rl.requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	rl.requests = valid

	if len(rl.requests) >= rl.maxPerWindow {
		return false
	}

	rl.requests = append(rl.requests, now)
	return true
}

// Count returns current request count in the window.
func (rl *SignerRateLimiter) Count() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.windowSize)
	count := 0
	for _, t := range rl.requests {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}
