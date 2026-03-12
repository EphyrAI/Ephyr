package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestPolicy is a richer policy fixture that covers more edge cases than
// the testPolicy constant used by the original engine_test.go.
const newTestPolicy = `
global:
  max_active_certs: 5
  default_ttl: "5m"
  max_ttl: "30m"
  rate_limit:
    requests_per_window: 3
    window_seconds: 60

agents:
  alice:
    uid: 2000
    max_concurrent_certs: 2
    description: "primary agent"
  bob:
    uid: 2001
    max_concurrent_certs: 1
    description: "secondary agent"
  charlie:
    uid: 2002
    max_concurrent_certs: 3
    description: "ops agent"

roles:
  read:
    principal: "agent-read"
    description: "read-only"
  operator:
    principal: "agent-op"
    description: "operator"
  admin:
    principal: "agent-admin"
    description: "admin"

targets:
  web:
    host: "10.0.0.10"
    port: 22
    vlan: 100
    allowed_roles: [read, operator]
    max_ttl: "10m"
    auto_approve: true
  db:
    host: "10.0.0.20"
    port: 22
    vlan: 100
    allowed_roles: [read]
    max_ttl: "15m"
    auto_approve: false
  staging:
    host: "10.0.0.30"
    port: 22
    vlan: 200
    allowed_roles: [read, operator, admin]
    max_ttl: "25m"
    auto_approve: true
`

func writeNewTestPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	path := writeNewTestPolicy(t, newTestPolicy)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	return NewEngine(loader, rc)
}

// ---------------------------------------------------------------------------
// Table-driven Evaluate tests
// ---------------------------------------------------------------------------

func TestEvaluate_Comprehensive(t *testing.T) {
	eng := newTestEngine(t)

	tests := []struct {
		name            string
		req             EvalRequest
		wantDecision    Decision
		wantPrincipal   string
		wantMaxDur      time.Duration // 0 = don't check
		wantReasonSub   string        // substring check
	}{
		// --- Agent existence ---
		{
			name:          "known agent approved",
			req:           EvalRequest{AgentUID: 2000, TargetName: "web", RoleName: "read", Duration: 3 * time.Minute},
			wantDecision:  Approve,
			wantPrincipal: "agent-read",
			wantMaxDur:    3 * time.Minute,
		},
		{
			name:          "unknown agent denied",
			req:           EvalRequest{AgentUID: 9999, TargetName: "web", RoleName: "read", Duration: 3 * time.Minute},
			wantDecision:  Deny,
			wantReasonSub: "unknown agent UID",
		},

		// --- Target existence ---
		{
			name:          "unknown target denied",
			req:           EvalRequest{AgentUID: 2000, TargetName: "ghost", RoleName: "read", Duration: 3 * time.Minute},
			wantDecision:  Deny,
			wantReasonSub: "unknown target",
		},

		// --- Role allowed / not allowed ---
		{
			name:          "role allowed on target",
			req:           EvalRequest{AgentUID: 2000, TargetName: "web", RoleName: "operator", Duration: 3 * time.Minute},
			wantDecision:  Approve,
			wantPrincipal: "agent-op",
		},
		{
			name:          "role not allowed on target",
			req:           EvalRequest{AgentUID: 2000, TargetName: "db", RoleName: "operator", Duration: 3 * time.Minute},
			wantDecision:  Deny,
			wantReasonSub: "not allowed on target",
		},
		{
			name:          "role not defined in policy",
			req:           EvalRequest{AgentUID: 2000, TargetName: "web", RoleName: "superadmin", Duration: 3 * time.Minute},
			wantDecision:  Deny,
			wantReasonSub: "not allowed on target",
		},
		{
			name:          "admin role on target that allows it",
			req:           EvalRequest{AgentUID: 2000, TargetName: "staging", RoleName: "admin", Duration: 3 * time.Minute},
			wantDecision:  Approve,
			wantPrincipal: "agent-admin",
		},

		// --- Duration clamping ---
		{
			name:         "duration within target max",
			req:          EvalRequest{AgentUID: 2000, TargetName: "web", RoleName: "read", Duration: 8 * time.Minute},
			wantDecision: Approve,
			wantMaxDur:   8 * time.Minute,
		},
		{
			name:         "duration clamped to target max",
			req:          EvalRequest{AgentUID: 2000, TargetName: "web", RoleName: "read", Duration: 20 * time.Minute},
			wantDecision: Approve,
			wantMaxDur:   10 * time.Minute, // web.max_ttl = 10m
		},
		{
			name:         "duration clamped to global max when target allows more",
			req:          EvalRequest{AgentUID: 2000, TargetName: "staging", RoleName: "read", Duration: 60 * time.Minute},
			wantDecision: Approve,
			wantMaxDur:   25 * time.Minute, // staging.max_ttl = 25m < global 30m
		},
		{
			name:         "zero duration uses global default then clamped to target",
			req:          EvalRequest{AgentUID: 2000, TargetName: "web", RoleName: "read", Duration: 0},
			wantDecision: Approve,
			wantMaxDur:   5 * time.Minute, // default 5m < web 10m
		},
		{
			name:         "negative duration uses global default",
			req:          EvalRequest{AgentUID: 2000, TargetName: "web", RoleName: "read", Duration: -5 * time.Minute},
			wantDecision: Approve,
			wantMaxDur:   5 * time.Minute,
		},

		// --- Auto-approve vs pending ---
		{
			name:          "auto-approve true target",
			req:           EvalRequest{AgentUID: 2000, TargetName: "web", RoleName: "read", Duration: 3 * time.Minute},
			wantDecision:  Approve,
			wantReasonSub: "auto-approved",
		},
		{
			name:          "auto-approve false target goes pending",
			req:           EvalRequest{AgentUID: 2000, TargetName: "db", RoleName: "read", Duration: 3 * time.Minute},
			wantDecision:  Pending,
			wantReasonSub: "manual approval",
		},

		// --- Multiple agents ---
		{
			name:          "second agent can also access same target",
			req:           EvalRequest{AgentUID: 2001, TargetName: "web", RoleName: "read", Duration: 3 * time.Minute},
			wantDecision:  Approve,
			wantPrincipal: "agent-read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh engine for each subtest to avoid cert tracking interference.
			eng := newTestEngine(t)
			res := eng.Evaluate(tt.req)

			if res.Decision != tt.wantDecision {
				t.Errorf("decision: got %s, want %s (reason: %s)", res.Decision, tt.wantDecision, res.Reason)
			}
			if tt.wantPrincipal != "" && res.Principal != tt.wantPrincipal {
				t.Errorf("principal: got %q, want %q", res.Principal, tt.wantPrincipal)
			}
			if tt.wantMaxDur != 0 && res.ClampedDuration != tt.wantMaxDur {
				t.Errorf("clamped duration: got %s, want %s", res.ClampedDuration, tt.wantMaxDur)
			}
			if tt.wantReasonSub != "" && !stringContains(res.Reason, tt.wantReasonSub) {
				t.Errorf("reason %q does not contain %q", res.Reason, tt.wantReasonSub)
			}
		})
	}
	_ = eng // ensure outer engine is used for compilation
}

// ---------------------------------------------------------------------------
// Concurrent cert limit enforcement
// ---------------------------------------------------------------------------

func TestEvaluate_ConcurrentCertLimit(t *testing.T) {
	tests := []struct {
		name         string
		agentUID     int
		maxCerts     int // from policy: alice=2, bob=1, charlie=3
		preTrack     int // how many certs to pre-track
		wantDecision Decision
	}{
		{
			name:         "alice below limit",
			agentUID:     2000,
			maxCerts:     2,
			preTrack:     1,
			wantDecision: Approve,
		},
		{
			name:         "alice at limit denied",
			agentUID:     2000,
			maxCerts:     2,
			preTrack:     2,
			wantDecision: Deny,
		},
		{
			name:         "bob at limit of 1 denied",
			agentUID:     2001,
			maxCerts:     1,
			preTrack:     1,
			wantDecision: Deny,
		},
		{
			name:         "charlie below limit of 3",
			agentUID:     2002,
			maxCerts:     3,
			preTrack:     2,
			wantDecision: Approve,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTestEngine(t)

			// Pre-track certs on different targets/roles to avoid dup auto-revoke.
			targets := []struct{ target, role string }{
				{"web", "read"},
				{"web", "operator"},
				{"staging", "read"},
			}
			for i := 0; i < tt.preTrack; i++ {
				eng.TrackCert(uint64(100+i), tt.agentUID, targets[i].target, targets[i].role,
					time.Now().Add(10*time.Minute))
			}

			res := eng.Evaluate(EvalRequest{
				AgentUID:   tt.agentUID,
				TargetName: "staging",
				RoleName:   "operator",
				Duration:   3 * time.Minute,
			})

			if res.Decision != tt.wantDecision {
				t.Errorf("decision: got %s, want %s (reason: %s)", res.Decision, tt.wantDecision, res.Reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Duplicate cert auto-revoke
// ---------------------------------------------------------------------------

func TestEvaluate_DuplicateCertAutoRevoke(t *testing.T) {
	eng := newTestEngine(t)

	// Track a cert for alice:web:read.
	eng.TrackCert(100, 2000, "web", "read", time.Now().Add(10*time.Minute))
	if eng.ActiveCertsForAgent(2000) != 1 {
		t.Fatalf("expected 1 active cert, got %d", eng.ActiveCertsForAgent(2000))
	}

	// Request the same agent+target+role combination. The engine should
	// auto-revoke the old cert and approve the new request.
	res := eng.Evaluate(EvalRequest{
		AgentUID:   2000,
		TargetName: "web",
		RoleName:   "read",
		Duration:   3 * time.Minute,
	})

	if res.Decision != Approve {
		t.Errorf("expected Approve after auto-revoke, got %s: %s", res.Decision, res.Reason)
	}

	// The old cert should have been removed, count should be 0 (new one not yet tracked).
	if eng.ActiveCertsForAgent(2000) != 0 {
		t.Errorf("expected 0 active certs after auto-revoke (pre-track), got %d", eng.ActiveCertsForAgent(2000))
	}
}

func TestEvaluate_DuplicateCertAutoRevokeFreesSlot(t *testing.T) {
	eng := newTestEngine(t)

	// Fill alice to her max (2 certs).
	eng.TrackCert(100, 2000, "web", "read", time.Now().Add(10*time.Minute))
	eng.TrackCert(101, 2000, "web", "operator", time.Now().Add(10*time.Minute))

	if eng.ActiveCertsForAgent(2000) != 2 {
		t.Fatalf("expected 2 active certs, got %d", eng.ActiveCertsForAgent(2000))
	}

	// Request a cert with same sig as serial 100 (web:read).
	// Step 5 checks concurrency (2 >= 2 → denied) BEFORE step 6 can auto-revoke.
	res := eng.Evaluate(EvalRequest{
		AgentUID:   2000,
		TargetName: "web",
		RoleName:   "read",
		Duration:   3 * time.Minute,
	})

	// The concurrency check happens before dup check, so this should be denied.
	if res.Decision != Deny {
		t.Errorf("expected Deny (concurrency check before dup), got %s: %s", res.Decision, res.Reason)
	}
}

// ---------------------------------------------------------------------------
// Global cert limit
// ---------------------------------------------------------------------------

func TestEvaluate_GlobalCertLimit(t *testing.T) {
	eng := newTestEngine(t)

	// Global limit is 5. Fill with certs from different agents.
	eng.TrackCert(1, 2000, "web", "read", time.Now().Add(10*time.Minute))
	eng.TrackCert(2, 2000, "web", "operator", time.Now().Add(10*time.Minute))
	eng.TrackCert(3, 2001, "web", "read", time.Now().Add(10*time.Minute))
	eng.TrackCert(4, 2002, "web", "read", time.Now().Add(10*time.Minute))
	eng.TrackCert(5, 2002, "web", "operator", time.Now().Add(10*time.Minute))

	if eng.ActiveCertsTotal() != 5 {
		t.Fatalf("expected 5 total certs, got %d", eng.ActiveCertsTotal())
	}

	// Charlie still has capacity (3 max, 2 used) but global is full.
	res := eng.Evaluate(EvalRequest{
		AgentUID:   2002,
		TargetName: "staging",
		RoleName:   "read",
		Duration:   3 * time.Minute,
	})
	if res.Decision != Deny {
		t.Errorf("expected Deny at global limit, got %s: %s", res.Decision, res.Reason)
	}
	if !stringContains(res.Reason, "global active cert limit") {
		t.Errorf("reason should mention global limit, got: %s", res.Reason)
	}
}

// ---------------------------------------------------------------------------
// Expired cert cleanup during Evaluate
// ---------------------------------------------------------------------------

func TestEvaluate_ExpiredCertsCleanedBeforeEval(t *testing.T) {
	eng := newTestEngine(t)

	// Fill alice to her limit with expired certs.
	eng.TrackCert(100, 2000, "web", "read", time.Now().Add(-1*time.Second))
	eng.TrackCert(101, 2000, "web", "operator", time.Now().Add(-1*time.Second))

	// Evaluate calls CleanExpired first, so the expired certs should be gone.
	res := eng.Evaluate(EvalRequest{
		AgentUID:   2000,
		TargetName: "staging",
		RoleName:   "read",
		Duration:   3 * time.Minute,
	})
	if res.Decision != Approve {
		t.Errorf("expected Approve after expired cleanup, got %s: %s", res.Decision, res.Reason)
	}
}

// ---------------------------------------------------------------------------
// TrackCert and RemoveCert
// ---------------------------------------------------------------------------

func TestTrackCert_And_RemoveCert(t *testing.T) {
	eng := newTestEngine(t)

	eng.TrackCert(1, 2000, "web", "read", time.Now().Add(10*time.Minute))
	eng.TrackCert(2, 2000, "db", "read", time.Now().Add(10*time.Minute))
	eng.TrackCert(3, 2001, "web", "read", time.Now().Add(10*time.Minute))

	if eng.ActiveCertsForAgent(2000) != 2 {
		t.Errorf("alice: got %d, want 2", eng.ActiveCertsForAgent(2000))
	}
	if eng.ActiveCertsForAgent(2001) != 1 {
		t.Errorf("bob: got %d, want 1", eng.ActiveCertsForAgent(2001))
	}
	if eng.ActiveCertsTotal() != 3 {
		t.Errorf("total: got %d, want 3", eng.ActiveCertsTotal())
	}

	// Remove a cert.
	eng.RemoveCert(1)
	if eng.ActiveCertsForAgent(2000) != 1 {
		t.Errorf("alice after remove: got %d, want 1", eng.ActiveCertsForAgent(2000))
	}
	if eng.ActiveCertsTotal() != 2 {
		t.Errorf("total after remove: got %d, want 2", eng.ActiveCertsTotal())
	}

	// Remove nonexistent cert is a no-op.
	eng.RemoveCert(999)
	if eng.ActiveCertsTotal() != 2 {
		t.Errorf("total after noop remove: got %d, want 2", eng.ActiveCertsTotal())
	}

	// Remove all of alice's certs.
	eng.RemoveCert(2)
	if eng.ActiveCertsForAgent(2000) != 0 {
		t.Errorf("alice fully removed: got %d, want 0", eng.ActiveCertsForAgent(2000))
	}
}

// ---------------------------------------------------------------------------
// CleanExpired detailed
// ---------------------------------------------------------------------------

func TestCleanExpired_Detailed(t *testing.T) {
	eng := newTestEngine(t)

	// Mix of expired and valid certs.
	eng.TrackCert(1, 2000, "web", "read", time.Now().Add(-10*time.Second))    // expired
	eng.TrackCert(2, 2000, "web", "operator", time.Now().Add(10*time.Minute)) // valid
	eng.TrackCert(3, 2001, "web", "read", time.Now().Add(-5*time.Second))     // expired
	eng.TrackCert(4, 2002, "staging", "admin", time.Now().Add(5*time.Minute)) // valid

	removed := eng.CleanExpired()
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
	if eng.ActiveCertsTotal() != 2 {
		t.Errorf("expected 2 remaining, got %d", eng.ActiveCertsTotal())
	}
	if eng.ActiveCertsForAgent(2000) != 1 {
		t.Errorf("alice: expected 1, got %d", eng.ActiveCertsForAgent(2000))
	}
	if eng.ActiveCertsForAgent(2001) != 0 {
		t.Errorf("bob: expected 0, got %d", eng.ActiveCertsForAgent(2001))
	}
}

// ---------------------------------------------------------------------------
// Duration clamping to global max
// ---------------------------------------------------------------------------

func TestEvaluate_DurationClampedToGlobalMax(t *testing.T) {
	// Use a policy where target max_ttl equals global max_ttl.
	policyYAML := `
global:
  max_active_certs: 5
  default_ttl: "5m"
  max_ttl: "20m"
agents:
  test:
    uid: 3000
    max_concurrent_certs: 3
roles:
  read:
    principal: "agent-read"
targets:
  server:
    host: "10.0.0.1"
    allowed_roles: [read]
    auto_approve: true
`
	// Target has no max_ttl so it defaults to global max (20m).
	path := writeNewTestPolicy(t, policyYAML)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(loader, rc)

	res := eng.Evaluate(EvalRequest{
		AgentUID:   3000,
		TargetName: "server",
		RoleName:   "read",
		Duration:   60 * time.Minute,
	})

	if res.Decision != Approve {
		t.Fatalf("expected Approve, got %s: %s", res.Decision, res.Reason)
	}
	if res.ClampedDuration != 20*time.Minute {
		t.Errorf("expected clamped to global 20m, got %s", res.ClampedDuration)
	}
}

// ---------------------------------------------------------------------------
// Multiple agents with different limits
// ---------------------------------------------------------------------------

func TestEvaluate_MultipleAgentsIndependentLimits(t *testing.T) {
	eng := newTestEngine(t)

	// Fill bob's limit (1).
	eng.TrackCert(1, 2001, "web", "read", time.Now().Add(10*time.Minute))

	// Bob should be denied.
	res := eng.Evaluate(EvalRequest{
		AgentUID:   2001,
		TargetName: "staging",
		RoleName:   "read",
		Duration:   3 * time.Minute,
	})
	if res.Decision != Deny {
		t.Errorf("bob should be denied at limit, got %s", res.Decision)
	}

	// Alice should still be approved (independent limit).
	res = eng.Evaluate(EvalRequest{
		AgentUID:   2000,
		TargetName: "web",
		RoleName:   "read",
		Duration:   3 * time.Minute,
	})
	if res.Decision != Approve {
		t.Errorf("alice should be approved, got %s: %s", res.Decision, res.Reason)
	}
}

// ---------------------------------------------------------------------------
// Helper used across new tests
// ---------------------------------------------------------------------------

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Decision.String()
// ---------------------------------------------------------------------------

func TestDecisionString(t *testing.T) {
	tests := []struct {
		d    Decision
		want string
	}{
		{Approve, "APPROVE"},
		{Deny, "DENY"},
		{Pending, "PENDING"},
		{Decision(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.d.String(); got != tt.want {
				t.Errorf("Decision(%d).String() = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// certSig helper
// ---------------------------------------------------------------------------

func TestCertSig(t *testing.T) {
	sig := certSig(1000, "web", "read")
	want := "1000:web:read"
	if sig != want {
		t.Errorf("certSig(1000, web, read) = %q, want %q", sig, want)
	}

	// Different inputs produce different sigs.
	sig2 := certSig(1000, "web", "operator")
	if sig == sig2 {
		t.Error("different role should produce different sig")
	}
}

// ---------------------------------------------------------------------------
// findAgentByUID helper
// ---------------------------------------------------------------------------

func TestFindAgentByUID(t *testing.T) {
	agents := map[string]AgentPolicy{
		"alice": {UID: 1000},
		"bob":   {UID: 2000},
	}

	tests := []struct {
		uid      int
		wantName string
		wantOK   bool
	}{
		{1000, "alice", true},
		{2000, "bob", true},
		{9999, "", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("uid_%d", tt.uid), func(t *testing.T) {
			name, _, ok := findAgentByUID(agents, tt.uid)
			if ok != tt.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tt.wantOK)
			}
			if tt.wantOK && name != tt.wantName {
				t.Errorf("name: got %q, want %q", name, tt.wantName)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// roleAllowed helper
// ---------------------------------------------------------------------------

func TestRoleAllowed(t *testing.T) {
	allowed := []string{"read", "operator"}
	tests := []struct {
		role string
		want bool
	}{
		{"read", true},
		{"operator", true},
		{"admin", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			if got := roleAllowed(allowed, tt.role); got != tt.want {
				t.Errorf("roleAllowed(%v, %q) = %v, want %v", allowed, tt.role, got, tt.want)
			}
		})
	}
}
