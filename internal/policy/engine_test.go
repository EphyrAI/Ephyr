package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

const testPolicy = `
global:
  max_active_certs: 3
  default_ttl: "5m"
  max_ttl: "30m"
  rate_limit:
    requests_per_window: 10
    window_seconds: 60

agents:
  testbot:
    uid: 1000
    max_concurrent_certs: 2
    description: "test agent"

roles:
  read:
    principal: "agent-read"
    description: "read-only"
  operator:
    principal: "agent-op"
    description: "operator"

targets:
  server-a:
    host: "10.0.0.1"
    port: 22
    vlan: 100
    allowed_roles: [read, operator]
    max_ttl: "10m"
    auto_approve: true
  server-b:
    host: "10.0.0.2"
    port: 22
    vlan: 200
    allowed_roles: [read]
    max_ttl: "15m"
    auto_approve: false
`

func TestLoadAndEvaluate(t *testing.T) {
	path := writeTestPolicy(t, testPolicy)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	eng := NewEngine(loader, rc)

	// Approve: known agent, valid target, valid role, auto_approve=true.
	res := eng.Evaluate(EvalRequest{
		AgentUID:   1000,
		TargetName: "server-a",
		RoleName:   "read",
		Duration:   3 * time.Minute,
	})
	if res.Decision != Approve {
		t.Errorf("expected Approve, got %s: %s", res.Decision, res.Reason)
	}
	if res.ClampedDuration != 3*time.Minute {
		t.Errorf("expected 3m, got %s", res.ClampedDuration)
	}
	if res.Principal != "agent-read" {
		t.Errorf("expected principal agent-read, got %s", res.Principal)
	}

	// Pending: auto_approve=false on server-b.
	res = eng.Evaluate(EvalRequest{
		AgentUID:   1000,
		TargetName: "server-b",
		RoleName:   "read",
		Duration:   5 * time.Minute,
	})
	if res.Decision != Pending {
		t.Errorf("expected Pending, got %s: %s", res.Decision, res.Reason)
	}

	// Deny: unknown agent.
	res = eng.Evaluate(EvalRequest{
		AgentUID:   9999,
		TargetName: "server-a",
		RoleName:   "read",
		Duration:   5 * time.Minute,
	})
	if res.Decision != Deny {
		t.Errorf("expected Deny for unknown agent, got %s", res.Decision)
	}

	// Deny: unknown target.
	res = eng.Evaluate(EvalRequest{
		AgentUID:   1000,
		TargetName: "nonexistent",
		RoleName:   "read",
		Duration:   5 * time.Minute,
	})
	if res.Decision != Deny {
		t.Errorf("expected Deny for unknown target, got %s", res.Decision)
	}

	// Deny: role not allowed on target.
	res = eng.Evaluate(EvalRequest{
		AgentUID:   1000,
		TargetName: "server-b",
		RoleName:   "operator",
		Duration:   5 * time.Minute,
	})
	if res.Decision != Deny {
		t.Errorf("expected Deny for disallowed role, got %s: %s", res.Decision, res.Reason)
	}

	// Duration clamping: request 20m but target max is 10m.
	res = eng.Evaluate(EvalRequest{
		AgentUID:   1000,
		TargetName: "server-a",
		RoleName:   "read",
		Duration:   20 * time.Minute,
	})
	if res.ClampedDuration != 10*time.Minute {
		t.Errorf("expected clamped to 10m, got %s", res.ClampedDuration)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	path := writeTestPolicy(t, testPolicy)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(loader, rc)

	// Track 2 certs (the agent's limit).
	eng.TrackCert(1, 1000, "server-a", "read", time.Now().Add(10*time.Minute))
	eng.TrackCert(2, 1000, "server-b", "read", time.Now().Add(10*time.Minute))

	if eng.ActiveCertsForAgent(1000) != 2 {
		t.Errorf("expected 2 active certs, got %d", eng.ActiveCertsForAgent(1000))
	}

	// Third request should be denied (max_concurrent_certs=2).
	res := eng.Evaluate(EvalRequest{
		AgentUID:   1000,
		TargetName: "server-a",
		RoleName:   "operator",
		Duration:   5 * time.Minute,
	})
	if res.Decision != Deny {
		t.Errorf("expected Deny at concurrency limit, got %s", res.Decision)
	}

	// Remove one cert, should work again.
	eng.RemoveCert(1)
	if eng.ActiveCertsForAgent(1000) != 1 {
		t.Errorf("expected 1 active cert after removal, got %d", eng.ActiveCertsForAgent(1000))
	}

	res = eng.Evaluate(EvalRequest{
		AgentUID:   1000,
		TargetName: "server-a",
		RoleName:   "operator",
		Duration:   5 * time.Minute,
	})
	if res.Decision != Approve {
		t.Errorf("expected Approve after removal, got %s: %s", res.Decision, res.Reason)
	}
}

func TestDuplicateCertDenied(t *testing.T) {
	path := writeTestPolicy(t, testPolicy)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(loader, rc)

	eng.TrackCert(1, 1000, "server-a", "read", time.Now().Add(10*time.Minute))

	res := eng.Evaluate(EvalRequest{
		AgentUID:   1000,
		TargetName: "server-a",
		RoleName:   "read",
		Duration:   5 * time.Minute,
	})
	if res.Decision != Deny {
		t.Errorf("expected Deny for duplicate cert, got %s: %s", res.Decision, res.Reason)
	}
}

func TestGlobalCertLimit(t *testing.T) {
	path := writeTestPolicy(t, testPolicy)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(loader, rc)

	// Fill up to global limit (3).
	eng.TrackCert(1, 1000, "server-a", "read", time.Now().Add(10*time.Minute))
	eng.TrackCert(2, 1000, "server-a", "operator", time.Now().Add(10*time.Minute))
	eng.TrackCert(3, 1000, "server-b", "read", time.Now().Add(10*time.Minute))

	if eng.ActiveCertsTotal() != 3 {
		t.Errorf("expected 3 total certs, got %d", eng.ActiveCertsTotal())
	}
}

func TestCleanExpired(t *testing.T) {
	path := writeTestPolicy(t, testPolicy)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(loader, rc)

	eng.TrackCert(1, 1000, "server-a", "read", time.Now().Add(-1*time.Second))
	eng.TrackCert(2, 1000, "server-b", "read", time.Now().Add(10*time.Minute))

	removed := eng.CleanExpired()
	if removed != 1 {
		t.Errorf("expected 1 expired cert removed, got %d", removed)
	}
	if eng.ActiveCertsTotal() != 1 {
		t.Errorf("expected 1 remaining cert, got %d", eng.ActiveCertsTotal())
	}
}

func TestHotReload(t *testing.T) {
	path := writeTestPolicy(t, testPolicy)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(loader, rc)

	// Verify initial state.
	cfg := eng.Config()
	if cfg.Raw.Global.MaxActiveCerts != 3 {
		t.Fatalf("expected initial max_active_certs=3, got %d", cfg.Raw.Global.MaxActiveCerts)
	}

	// Rewrite the file with a different value.
	updated := `
global:
  max_active_certs: 50
  default_ttl: "5m"
  max_ttl: "30m"
agents:
  testbot:
    uid: 1000
    max_concurrent_certs: 5
roles:
  read:
    principal: "agent-read"
targets:
  server-a:
    host: "10.0.0.1"
    port: 22
    vlan: 100
    allowed_roles: [read]
    max_ttl: "10m"
    auto_approve: true
`
	if err := os.WriteFile(path, []byte(updated), 0644); err != nil {
		t.Fatal(err)
	}

	if err := eng.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	cfg = eng.Config()
	if cfg.Raw.Global.MaxActiveCerts != 50 {
		t.Errorf("expected reloaded max_active_certs=50, got %d", cfg.Raw.Global.MaxActiveCerts)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		yaml   string
		errSub string
	}{
		{
			name: "undefined role in target",
			yaml: `
global: {max_active_certs: 1, default_ttl: "5m", max_ttl: "30m"}
agents: {a: {uid: 1}}
roles: {read: {principal: "r"}}
targets: {s: {host: "1.2.3.4", allowed_roles: [admin]}}
`,
			errSub: "undefined role",
		},
		{
			name: "duplicate UID",
			yaml: `
global: {max_active_certs: 1, default_ttl: "5m", max_ttl: "30m"}
agents: {a: {uid: 1}, b: {uid: 1}}
roles: {read: {principal: "r"}}
targets: {s: {host: "1.2.3.4", allowed_roles: [read]}}
`,
			errSub: "duplicate UID",
		},
		{
			name: "duplicate target host",
			yaml: `
global: {max_active_certs: 1, default_ttl: "5m", max_ttl: "30m"}
agents: {a: {uid: 1}}
roles: {read: {principal: "r"}}
targets:
  s1: {host: "1.2.3.4", port: 22, allowed_roles: [read]}
  s2: {host: "1.2.3.4", port: 22, allowed_roles: [read]}
`,
			errSub: "duplicate target host",
		},
		{
			name: "bad duration",
			yaml: `
global: {max_active_certs: 1, default_ttl: "notaduration", max_ttl: "30m"}
agents: {a: {uid: 1}}
roles: {read: {principal: "r"}}
targets: {s: {host: "1.2.3.4", allowed_roles: [read]}}
`,
			errSub: "invalid global default_ttl",
		},
		{
			name: "target max_ttl exceeds global",
			yaml: `
global: {max_active_certs: 1, default_ttl: "5m", max_ttl: "10m"}
agents: {a: {uid: 1}}
roles: {read: {principal: "r"}}
targets: {s: {host: "1.2.3.4", allowed_roles: [read], max_ttl: "20m"}}
`,
			errSub: "exceeds global max_ttl",
		},
		{
			name: "no agents",
			yaml: `
global: {max_active_certs: 1, default_ttl: "5m", max_ttl: "30m"}
agents: {}
roles: {read: {principal: "r"}}
targets: {s: {host: "1.2.3.4", allowed_roles: [read]}}
`,
			errSub: "no agents defined",
		},
		{
			name: "empty principal",
			yaml: `
global: {max_active_certs: 1, default_ttl: "5m", max_ttl: "30m"}
agents: {a: {uid: 1}}
roles: {read: {principal: ""}}
targets: {s: {host: "1.2.3.4", allowed_roles: [read]}}
`,
			errSub: "empty principal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTestPolicy(t, tt.yaml)
			_, _, err := LoadFromFile(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !containsSub(err.Error(), tt.errSub) {
				t.Errorf("expected error containing %q, got: %v", tt.errSub, err)
			}
		})
	}
}

func containsSub(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || findSub(s, sub))
}

func findSub(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestDefaultTTLUsedWhenZero(t *testing.T) {
	path := writeTestPolicy(t, testPolicy)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(loader, rc)

	res := eng.Evaluate(EvalRequest{
		AgentUID:   1000,
		TargetName: "server-a",
		RoleName:   "read",
		Duration:   0,
	})
	if res.Decision != Approve {
		t.Fatalf("expected Approve, got %s: %s", res.Decision, res.Reason)
	}
	if res.ClampedDuration != 5*time.Minute {
		t.Errorf("expected default 5m when Duration=0, got %s", res.ClampedDuration)
	}
}
