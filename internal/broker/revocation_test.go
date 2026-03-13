package broker

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestRevocationMap(maxTTL time.Duration) *RevocationMap {
	r := &RevocationMap{
		watermarks: make(map[string]time.Time),
		maxTTL:     maxTTL,
		stopCh:     make(chan struct{}),
	}
	// Do NOT start the GC goroutine in tests -- we call gc() manually.
	return r
}

func TestRevocationBasicRevokeAndCheck(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	revokedAt := time.Now()
	r.RevokeAt("task-1", revokedAt)

	// Token issued before the watermark should be revoked.
	issuedBefore := revokedAt.Add(-1 * time.Second)
	err := r.CheckLineage([]string{"task-1"}, issuedBefore)
	if err == nil {
		t.Fatal("expected revocation error for token issued before watermark")
	}
}

func TestRevocationTokenIssuedAtWatermarkExact(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	revokedAt := time.Now()
	r.RevokeAt("task-1", revokedAt)

	// Token issued at exact same time as watermark should be revoked (not after).
	err := r.CheckLineage([]string{"task-1"}, revokedAt)
	if err == nil {
		t.Fatal("expected revocation error for token issued at exact watermark time")
	}
}

func TestRevocationTokenIssuedAfterWatermark(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	revokedAt := time.Now()
	r.RevokeAt("task-1", revokedAt)

	// Token issued after the watermark should be valid.
	issuedAfter := revokedAt.Add(1 * time.Second)
	err := r.CheckLineage([]string{"task-1"}, issuedAfter)
	if err != nil {
		t.Fatalf("expected valid token issued after watermark, got: %v", err)
	}
}

func TestRevocationLineageWalkParentRevoked(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	parentRevoked := time.Now()
	r.RevokeAt("parent-task", parentRevoked)

	// Child token with parent in lineage, issued before parent watermark.
	childIssued := parentRevoked.Add(-500 * time.Millisecond)
	err := r.CheckLineage([]string{"parent-task", "child-task"}, childIssued)
	if err == nil {
		t.Fatal("expected revocation due to parent watermark")
	}
}

func TestRevocationLineageWalkUnrelatedTask(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	r.RevokeAt("unrelated-task", time.Now())

	// A token with a different lineage should not be affected.
	err := r.CheckLineage([]string{"my-parent", "my-task"}, time.Now().Add(-1*time.Second))
	if err != nil {
		t.Fatalf("unrelated revocation should not affect different lineage: %v", err)
	}
}

func TestRevocationCascading(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	rootRevoked := time.Now()
	r.RevokeAt("root-task", rootRevoked)

	// All children with root in their lineage should be revoked.
	childIssued := rootRevoked.Add(-100 * time.Millisecond)

	children := [][]string{
		{"root-task", "child-1"},
		{"root-task", "child-2", "grandchild-1"},
		{"root-task", "child-3", "grandchild-2", "great-grandchild-1"},
	}

	for _, lineage := range children {
		err := r.CheckLineage(lineage, childIssued)
		if err == nil {
			t.Fatalf("expected cascading revocation for lineage %v", lineage)
		}
	}
}

func TestRevocationGCRemovesExpiredWatermarks(t *testing.T) {
	maxTTL := 1 * time.Hour
	r := newTestRevocationMap(maxTTL)
	defer r.Stop()

	// Add a watermark that is older than maxTTL.
	oldTime := time.Now().Add(-2 * time.Hour)
	r.RevokeAt("old-task", oldTime)

	// Add a recent watermark.
	r.RevokeAt("recent-task", time.Now())

	if r.Count() != 2 {
		t.Fatalf("expected 2 watermarks before GC, got %d", r.Count())
	}

	r.gc()

	if r.Count() != 1 {
		t.Fatalf("expected 1 watermark after GC, got %d", r.Count())
	}

	if r.IsRevoked("old-task") {
		t.Fatal("old-task should have been GC'd")
	}
	if !r.IsRevoked("recent-task") {
		t.Fatal("recent-task should still exist")
	}
}

func TestRevocationGCPreservesRecentWatermarks(t *testing.T) {
	maxTTL := 1 * time.Hour
	r := newTestRevocationMap(maxTTL)
	defer r.Stop()

	// Add watermarks within the maxTTL window.
	r.RevokeAt("task-a", time.Now().Add(-30*time.Minute))
	r.RevokeAt("task-b", time.Now().Add(-10*time.Minute))
	r.RevokeAt("task-c", time.Now())

	r.gc()

	if r.Count() != 3 {
		t.Fatalf("expected 3 watermarks preserved after GC, got %d", r.Count())
	}
}

func TestRevocationConcurrentAccess(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	var wg sync.WaitGroup
	const goroutines = 50
	const opsPerGoroutine = 100

	// Half the goroutines revoke tasks.
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				taskID := fmt.Sprintf("task-%d-%d", id, j)
				r.Revoke(taskID)
			}
		}(i)
	}

	// Other half check lineages.
	for i := goroutines / 2; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				lineage := []string{fmt.Sprintf("task-%d-%d", id%5, j)}
				_ = r.CheckLineage(lineage, time.Now())
				_ = r.IsRevoked(fmt.Sprintf("task-%d-%d", id%5, j))
				_ = r.Count()
			}
		}(i)
	}

	wg.Wait()
	// If we got here without a race condition, the test passes.
}

func TestRevocationEmptyLineage(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	r.Revoke("some-task")

	err := r.CheckLineage(nil, time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("empty lineage should always be valid: %v", err)
	}

	err = r.CheckLineage([]string{}, time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("empty slice lineage should always be valid: %v", err)
	}
}

func TestRevocationCountAccuracy(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	if r.Count() != 0 {
		t.Fatalf("expected 0 watermarks initially, got %d", r.Count())
	}

	r.Revoke("task-1")
	if r.Count() != 1 {
		t.Fatalf("expected 1 watermark after one revoke, got %d", r.Count())
	}

	r.Revoke("task-2")
	r.Revoke("task-3")
	if r.Count() != 3 {
		t.Fatalf("expected 3 watermarks, got %d", r.Count())
	}

	// Re-revoking the same task should not increase count.
	r.Revoke("task-1")
	if r.Count() != 3 {
		t.Fatalf("expected 3 watermarks after re-revoke, got %d", r.Count())
	}
}

func TestRevocationIsRevokedReturnsFalseForUnknown(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	if r.IsRevoked("nonexistent") {
		t.Fatal("expected false for nonexistent task")
	}
}

func TestRevocationRevokeOverwritesWatermark(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	first := time.Now().Add(-10 * time.Minute)
	second := time.Now()

	r.RevokeAt("task-1", first)

	// Token issued between first and second watermark should be revoked.
	between := first.Add(5 * time.Minute)
	err := r.CheckLineage([]string{"task-1"}, between)
	if err != nil {
		t.Fatalf("token issued after first watermark should be valid: %v", err)
	}

	// Re-revoke at a later time.
	r.RevokeAt("task-1", second)

	// Now the same token should be revoked.
	err = r.CheckLineage([]string{"task-1"}, between)
	if err == nil {
		t.Fatal("expected revocation after watermark was updated to later time")
	}
}

func TestRevocationMultipleAncestorsInLineage(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	defer r.Stop()

	now := time.Now()

	// Revoke the middle ancestor, not the root.
	r.RevokeAt("middle-task", now)

	// Token with root → middle → leaf lineage, issued before middle watermark.
	issuedBefore := now.Add(-1 * time.Second)
	err := r.CheckLineage([]string{"root-task", "middle-task", "leaf-task"}, issuedBefore)
	if err == nil {
		t.Fatal("expected revocation due to middle ancestor watermark")
	}
}

func TestRevocationStopIdempotent(t *testing.T) {
	r := newTestRevocationMap(1 * time.Hour)
	// Calling Stop multiple times should not panic.
	r.Stop()
	r.Stop()
	r.Stop()
}

func TestRevocationGCAllExpired(t *testing.T) {
	maxTTL := 1 * time.Hour
	r := newTestRevocationMap(maxTTL)
	defer r.Stop()

	// Add several watermarks all older than maxTTL.
	old := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 10; i++ {
		r.RevokeAt(fmt.Sprintf("task-%d", i), old)
	}

	if r.Count() != 10 {
		t.Fatalf("expected 10 watermarks, got %d", r.Count())
	}

	r.gc()

	if r.Count() != 0 {
		t.Fatalf("expected 0 watermarks after GC of all expired, got %d", r.Count())
	}
}
