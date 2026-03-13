package broker

import (
	"fmt"
	"sync"
	"time"
)

// RevocationMap implements epoch-based token revocation.
// When a task is revoked, its ID is recorded with a timestamp.
// Any token whose iat (issued-at) is before the watermark for any
// task in its lineage is considered revoked.
//
// This approach has several advantages over JTI blocklists:
//   - Cascading: revoking a parent auto-invalidates all children
//   - Memory: one entry per revoked task, not per token
//   - Self-cleaning: entries expire after max task TTL passes
type RevocationMap struct {
	mu         sync.RWMutex
	watermarks map[string]time.Time // task ID → revoked-at timestamp
	maxTTL     time.Duration        // maximum possible task TTL (for GC)
	stopCh     chan struct{}
}

// NewRevocationMap creates a new RevocationMap and starts a background GC
// goroutine that runs every 60 seconds, removing watermarks older than maxTaskTTL.
func NewRevocationMap(maxTaskTTL time.Duration) *RevocationMap {
	r := &RevocationMap{
		watermarks: make(map[string]time.Time),
		maxTTL:     maxTaskTTL,
		stopCh:     make(chan struct{}),
	}
	go r.gcLoop()
	return r
}

// Stop halts the background GC goroutine.
func (r *RevocationMap) Stop() {
	select {
	case <-r.stopCh:
		// Already stopped.
	default:
		close(r.stopCh)
	}
}

// Revoke records a revocation watermark for a task ID at the current time.
func (r *RevocationMap) Revoke(taskID string) {
	r.RevokeAt(taskID, time.Now())
}

// RevokeAt records a revocation watermark for a task ID at a specific time.
// This is primarily useful for testing.
func (r *RevocationMap) RevokeAt(taskID string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.watermarks[taskID] = at
}

// CheckLineage walks the token's lineage array and returns an error if any
// ancestor has a watermark newer than the token's issued-at time.
// Returns nil if the token is not revoked.
// This is O(depth) — typically < 5 map lookups.
func (r *RevocationMap) CheckLineage(lineage []string, issuedAt time.Time) error {
	if len(lineage) == 0 {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, taskID := range lineage {
		if watermark, ok := r.watermarks[taskID]; ok {
			if !issuedAt.After(watermark) {
				return fmt.Errorf("task %s was revoked at %s (token issued at %s)",
					taskID, watermark.Format(time.RFC3339Nano), issuedAt.Format(time.RFC3339Nano))
			}
		}
	}
	return nil
}

// IsRevoked returns true if the given task ID has a revocation watermark.
func (r *RevocationMap) IsRevoked(taskID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.watermarks[taskID]
	return ok
}

// Count returns the number of active watermarks.
func (r *RevocationMap) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.watermarks)
}

// gc removes watermarks older than maxTTL. A watermark can be safely removed
// once watermark_time + maxTTL has passed, because any token issued before the
// watermark has already expired by then.
func (r *RevocationMap) gc() {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-r.maxTTL)
	for taskID, watermark := range r.watermarks {
		if watermark.Before(cutoff) {
			delete(r.watermarks, taskID)
		}
	}
}

// gcLoop runs the GC every 60 seconds until Stop is called.
func (r *RevocationMap) gcLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.gc()
		case <-r.stopCh:
			return
		}
	}
}
