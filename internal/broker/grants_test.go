package broker

import (
	"sync"
	"testing"
	"time"
)

func newTestGrantStore() *GrantStore {
	gs := &GrantStore{
		grants:            make(map[string]*AccessGrant),
		stopCh:            make(chan struct{}),
		DefaultServiceTTL: 5 * time.Minute,
		DefaultMCPTTL:     5 * time.Minute,
		Mode:              GrantModeTTL,
	}
	// Do NOT start the cleanup goroutine in tests -- we call cleanExpired manually.
	return gs
}

func TestGrantIssueAndFields(t *testing.T) {
	tests := []struct {
		name      string
		grantType GrantType
		agent     string
		target    string
		ttl       time.Duration
		details   map[string]string
	}{
		{
			name:      "ssh_cert grant with custom TTL",
			grantType: GrantTypeSSHCert,
			agent:     "agent-a",
			target:    "host1",
			ttl:       10 * time.Minute,
			details:   map[string]string{"role": "admin"},
		},
		{
			name:      "service grant with default TTL",
			grantType: GrantTypeService,
			agent:     "agent-b",
			target:    "grafana",
			ttl:       0, // should use DefaultServiceTTL
			details:   nil,
		},
		{
			name:      "mcp grant with default TTL",
			grantType: GrantTypeMCP,
			agent:     "agent-c",
			target:    "demo-tools",
			ttl:       0, // should use DefaultMCPTTL
			details:   map[string]string{"tool": "roll_dice"},
		},
		{
			name:      "ssh_cert with zero TTL gets 5m default",
			grantType: GrantTypeSSHCert,
			agent:     "agent-d",
			target:    "host2",
			ttl:       0,
			details:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gs := newTestGrantStore()
			defer gs.Stop()

			before := time.Now()
			g := gs.Issue(tc.grantType, tc.agent, tc.target, tc.ttl, tc.details)
			after := time.Now()

			if g == nil {
				t.Fatal("Issue returned nil")
			}
			if g.Type != tc.grantType {
				t.Errorf("Type: got %q, want %q", g.Type, tc.grantType)
			}
			if g.Agent != tc.agent {
				t.Errorf("Agent: got %q, want %q", g.Agent, tc.agent)
			}
			if g.Target != tc.target {
				t.Errorf("Target: got %q, want %q", g.Target, tc.target)
			}
			if g.Status != "active" {
				t.Errorf("Status: got %q, want %q", g.Status, "active")
			}
			if len(g.ID) != 32 {
				t.Errorf("ID length: got %d, want 32 (16 hex bytes)", len(g.ID))
			}
			if g.IssuedAt.Before(before) || g.IssuedAt.After(after) {
				t.Errorf("IssuedAt %v not between %v and %v", g.IssuedAt, before, after)
			}

			// Check TTL.
			expectedTTL := tc.ttl
			if expectedTTL <= 0 {
				switch tc.grantType {
				case GrantTypeService:
					expectedTTL = gs.DefaultServiceTTL
				case GrantTypeMCP:
					expectedTTL = gs.DefaultMCPTTL
				default:
					expectedTTL = 5 * time.Minute
				}
			}
			expectedExpiry := g.IssuedAt.Add(expectedTTL)
			if !g.ExpiresAt.Equal(expectedExpiry) {
				t.Errorf("ExpiresAt: got %v, want %v (TTL %v)", g.ExpiresAt, expectedExpiry, expectedTTL)
			}

			// Check details.
			if tc.details != nil {
				for k, v := range tc.details {
					if g.Details[k] != v {
						t.Errorf("Details[%q]: got %q, want %q", k, g.Details[k], v)
					}
				}
			}
		})
	}
}

func TestGrantIDUniqueness(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		g := gs.Issue(GrantTypeService, "agent", "target-unique", 1*time.Hour, nil)
		if ids[g.ID] {
			t.Fatalf("duplicate grant ID on iteration %d: %s", i, g.ID)
		}
		ids[g.ID] = true
		// Revoke so the next Issue creates a new one (not dedup).
		gs.Revoke(g.ID)
	}
	if len(ids) != 100 {
		t.Errorf("expected 100 unique IDs, got %d", len(ids))
	}
}

func TestGrantDeduplication(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	g1 := gs.Issue(GrantTypeService, "agent-a", "grafana", 10*time.Minute, nil)
	g2 := gs.Issue(GrantTypeService, "agent-a", "grafana", 10*time.Minute, nil)

	if g1.ID != g2.ID {
		t.Errorf("duplicate issue should return same grant: got IDs %s and %s", g1.ID, g2.ID)
	}

	// Different type should NOT dedup.
	g3 := gs.Issue(GrantTypeMCP, "agent-a", "grafana", 10*time.Minute, nil)
	if g3.ID == g1.ID {
		t.Error("different grant type should create new grant")
	}

	// Different agent should NOT dedup.
	g4 := gs.Issue(GrantTypeService, "agent-b", "grafana", 10*time.Minute, nil)
	if g4.ID == g1.ID {
		t.Error("different agent should create new grant")
	}

	// Different target should NOT dedup.
	g5 := gs.Issue(GrantTypeService, "agent-a", "portainer", 10*time.Minute, nil)
	if g5.ID == g1.ID {
		t.Error("different target should create new grant")
	}
}

func TestGrantTTLExpiry(t *testing.T) {
	// We cannot easily manipulate time in this code, so we create a grant
	// with ExpiresAt already in the past by directly manipulating the store.
	gs := newTestGrantStore()
	defer gs.Stop()

	// Issue a grant, then backdate its expiry.
	g := gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)
	gID := g.ID

	// Manually expire it.
	gs.mu.Lock()
	gs.grants[gID].ExpiresAt = time.Now().Add(-1 * time.Second)
	gs.mu.Unlock()

	// Validate should return nil for the expired grant.
	v := gs.Validate(GrantTypeService, "agent-a", "svc1")
	if v != nil {
		t.Error("Validate should return nil for expired grant")
	}

	// ListActive should not include it.
	active := gs.ListActive()
	for _, a := range active {
		if a.ID == gID {
			t.Error("ListActive should not include expired grant")
		}
	}

	// ListByAgent should not include it.
	byAgent := gs.ListByAgent("agent-a")
	for _, a := range byAgent {
		if a.ID == gID {
			t.Error("ListByAgent should not include expired grant")
		}
	}

	// ActiveCount should be 0.
	if gs.ActiveCount() != 0 {
		t.Errorf("ActiveCount: got %d, want 0", gs.ActiveCount())
	}

	// Issue for same agent+type+target should create NEW grant (old one expired).
	g2 := gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)
	if g2.ID == gID {
		t.Error("Issue should create new grant when existing one expired")
	}
}

func TestGrantRevoke(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*GrantStore) string // returns grant ID to revoke
		wantOK     bool
		wantReason string
	}{
		{
			name: "revoke active grant",
			setup: func(gs *GrantStore) string {
				g := gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)
				return g.ID
			},
			wantOK:     true,
			wantReason: "",
		},
		{
			name: "revoke already-revoked grant",
			setup: func(gs *GrantStore) string {
				g := gs.Issue(GrantTypeService, "agent-a", "svc2", 10*time.Minute, nil)
				gs.Revoke(g.ID)
				return g.ID
			},
			wantOK:     false,
			wantReason: "grant already revoked",
		},
		{
			name: "revoke non-existent grant",
			setup: func(gs *GrantStore) string {
				return "nonexistent-id-0000000000000000"
			},
			wantOK:     false,
			wantReason: "grant not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gs := newTestGrantStore()
			defer gs.Stop()

			id := tc.setup(gs)
			ok, reason := gs.Revoke(id)

			if ok != tc.wantOK {
				t.Errorf("Revoke ok: got %v, want %v", ok, tc.wantOK)
			}
			if reason != tc.wantReason {
				t.Errorf("Revoke reason: got %q, want %q", reason, tc.wantReason)
			}

			// If revoke succeeded, verify state.
			if tc.wantOK {
				g, found := gs.Get(id)
				if !found {
					t.Fatal("Get after revoke should find the grant")
				}
				if g.Status != "revoked" {
					t.Errorf("Status after revoke: got %q, want %q", g.Status, "revoked")
				}
				// Validate should return nil for revoked grant.
				v := gs.Validate(GrantTypeService, "agent-a", "svc1")
				if v != nil {
					t.Error("Validate should return nil for revoked grant")
				}
			}
		})
	}
}

func TestGrantGet(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	g := gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)

	// Get existing grant.
	got, ok := gs.Get(g.ID)
	if !ok {
		t.Fatal("Get should find existing grant")
	}
	if got.ID != g.ID {
		t.Errorf("Get ID: got %s, want %s", got.ID, g.ID)
	}

	// Get returns a copy -- mutating it should not affect the store.
	got.Status = "mutated"
	original, _ := gs.Get(g.ID)
	if original.Status == "mutated" {
		t.Error("Get should return a copy, not the original pointer")
	}

	// Get non-existent.
	_, ok = gs.Get("does-not-exist")
	if ok {
		t.Error("Get should return false for non-existent ID")
	}
}

func TestGrantListActive(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	// Issue 3 active grants.
	g1 := gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)
	gs.Issue(GrantTypeService, "agent-a", "svc2", 10*time.Minute, nil)
	gs.Issue(GrantTypeMCP, "agent-b", "remote1", 10*time.Minute, nil)

	// Revoke one.
	gs.Revoke(g1.ID)

	active := gs.ListActive()
	if len(active) != 2 {
		t.Errorf("ListActive count: got %d, want 2", len(active))
	}

	// Ensure revoked is not included.
	for _, a := range active {
		if a.ID == g1.ID {
			t.Error("ListActive should not include revoked grant")
		}
	}
}

func TestGrantListByAgent(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)
	gs.Issue(GrantTypeService, "agent-a", "svc2", 10*time.Minute, nil)
	gs.Issue(GrantTypeMCP, "agent-a", "remote1", 10*time.Minute, nil)
	gs.Issue(GrantTypeService, "agent-b", "svc1", 10*time.Minute, nil)

	byA := gs.ListByAgent("agent-a")
	if len(byA) != 3 {
		t.Errorf("ListByAgent(agent-a): got %d, want 3", len(byA))
	}

	byB := gs.ListByAgent("agent-b")
	if len(byB) != 1 {
		t.Errorf("ListByAgent(agent-b): got %d, want 1", len(byB))
	}

	byC := gs.ListByAgent("agent-c")
	if len(byC) != 0 {
		t.Errorf("ListByAgent(agent-c): got %d, want 0", len(byC))
	}
}

func TestGrantListAll(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	g1 := gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)
	gs.Issue(GrantTypeService, "agent-b", "svc2", 10*time.Minute, nil)

	// Revoke one.
	gs.Revoke(g1.ID)

	all := gs.ListAll()
	if len(all) != 2 {
		t.Errorf("ListAll: got %d, want 2 (includes revoked)", len(all))
	}
}

func TestGrantActiveCount(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	if gs.ActiveCount() != 0 {
		t.Errorf("ActiveCount on empty store: got %d, want 0", gs.ActiveCount())
	}

	g1 := gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)
	gs.Issue(GrantTypeService, "agent-a", "svc2", 10*time.Minute, nil)
	gs.Issue(GrantTypeMCP, "agent-b", "remote1", 10*time.Minute, nil)

	if gs.ActiveCount() != 3 {
		t.Errorf("ActiveCount: got %d, want 3", gs.ActiveCount())
	}

	gs.Revoke(g1.ID)
	if gs.ActiveCount() != 2 {
		t.Errorf("ActiveCount after revoke: got %d, want 2", gs.ActiveCount())
	}
}

func TestGrantCleanExpired(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	g1 := gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)
	g2 := gs.Issue(GrantTypeService, "agent-a", "svc2", 10*time.Minute, nil)
	g3 := gs.Issue(GrantTypeService, "agent-b", "svc3", 10*time.Minute, nil)

	// Backdate g1 to expired but within grace period (less than 10 min ago).
	gs.mu.Lock()
	gs.grants[g1.ID].ExpiresAt = time.Now().Add(-5 * time.Minute)
	gs.grants[g1.ID].Status = "active" // will be marked expired by cleanup
	gs.mu.Unlock()

	// Backdate g2 to expired beyond grace period (more than 10 min ago).
	gs.mu.Lock()
	gs.grants[g2.ID].ExpiresAt = time.Now().Add(-15 * time.Minute)
	gs.grants[g2.ID].Status = "expired"
	gs.mu.Unlock()

	// g3 stays active.

	gs.cleanExpired()

	// g1 should be marked expired but still in store (within grace period).
	got1, ok1 := gs.Get(g1.ID)
	if !ok1 {
		t.Error("g1 should still be in store (within grace period)")
	} else if got1.Status != "expired" {
		t.Errorf("g1 status: got %q, want %q", got1.Status, "expired")
	}

	// g2 should be deleted (beyond grace period).
	_, ok2 := gs.Get(g2.ID)
	if ok2 {
		t.Error("g2 should be deleted (beyond grace period)")
	}

	// g3 should still be active.
	got3, ok3 := gs.Get(g3.ID)
	if !ok3 {
		t.Fatal("g3 should still be in store")
	}
	if got3.Status != "active" {
		t.Errorf("g3 status: got %q, want %q", got3.Status, "active")
	}
}

func TestGrantValidate(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)

	tests := []struct {
		name      string
		grantType GrantType
		agent     string
		target    string
		wantNil   bool
	}{
		{"exact match", GrantTypeService, "agent-a", "svc1", false},
		{"wrong type", GrantTypeMCP, "agent-a", "svc1", true},
		{"wrong agent", GrantTypeService, "agent-x", "svc1", true},
		{"wrong target", GrantTypeService, "agent-a", "svc-x", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := gs.Validate(tc.grantType, tc.agent, tc.target)
			if tc.wantNil && got != nil {
				t.Error("Validate should return nil")
			}
			if !tc.wantNil && got == nil {
				t.Error("Validate should return a grant")
			}
		})
	}
}

func TestGrantDifferentTypes(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	types := []GrantType{GrantTypeSSHCert, GrantTypeService, GrantTypeMCP}
	ids := make(map[string]GrantType)

	for _, gt := range types {
		g := gs.Issue(gt, "agent-a", "target1", 10*time.Minute, nil)
		ids[g.ID] = gt
	}

	if len(ids) != 3 {
		t.Errorf("expected 3 separate grants for different types, got %d", len(ids))
	}

	if gs.ActiveCount() != 3 {
		t.Errorf("ActiveCount: got %d, want 3", gs.ActiveCount())
	}

	// Validate each type independently.
	for _, gt := range types {
		v := gs.Validate(gt, "agent-a", "target1")
		if v == nil {
			t.Errorf("Validate(%s) should succeed", gt)
		}
	}
}

func TestGrantConcurrency(t *testing.T) {
	gs := newTestGrantStore()
	defer gs.Stop()

	var wg sync.WaitGroup

	// 10 goroutines issuing grants concurrently.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(_idx int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				g := gs.Issue(GrantTypeService, "agent-concurrent", "svc-concurrent", 10*time.Minute, nil)
				if g == nil {
					t.Error("Issue returned nil during concurrent access")
				}
			}
		}(i)
	}

	// 5 goroutines reading concurrently.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				gs.ListActive()
				gs.ListByAgent("agent-concurrent")
				gs.ActiveCount()
			}
		}()
	}

	wg.Wait()

	// Should not panic or deadlock.
	t.Logf("Concurrency test completed. Active grants: %d", gs.ActiveCount())
}

func TestGrantModeConstants(t *testing.T) {
	if GrantModeTTL != "ttl" {
		t.Errorf("GrantModeTTL: got %q, want %q", GrantModeTTL, "ttl")
	}
	if GrantModePassthrough != "passthrough" {
		t.Errorf("GrantModePassthrough: got %q, want %q", GrantModePassthrough, "passthrough")
	}
}

func TestGrantStoreStop(t *testing.T) {
	// NewGrantStore starts a cleanup goroutine -- verify Stop does not panic.
	gs := NewGrantStore()
	gs.Issue(GrantTypeService, "agent-a", "svc1", 10*time.Minute, nil)
	gs.Stop()
	// Verify the store is still usable after stop (methods work, just no auto-cleanup).
	if gs.ActiveCount() != 1 {
		t.Errorf("ActiveCount after Stop: got %d, want 1", gs.ActiveCount())
	}
}
