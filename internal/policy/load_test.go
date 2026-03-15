package policy

import (
	"testing"
)

func TestLoadPolicy(t *testing.T) {
	_, rc, err := LoadFromFile("testdata/policy.yaml")
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	if len(rc.Raw.Agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(rc.Raw.Agents))
	}
	if len(rc.Raw.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(rc.Raw.Targets))
	}
	if len(rc.Raw.Roles) != 3 {
		t.Errorf("expected 3 roles, got %d", len(rc.Raw.Roles))
	}

	// Verify demo agent.
	demo, ok := rc.Raw.Agents["demo-agent"]
	if !ok {
		t.Fatal("agent 'demo-agent' not found")
	}
	if demo.UID != 1000 {
		t.Errorf("demo-agent UID: expected 1000, got %d", demo.UID)
	}

	// Verify target max_ttl resolution.
	if rc.TargetMaxTTLs["webserver"].Minutes() != 10 {
		t.Errorf("webserver max_ttl: expected 15m, got %s", rc.TargetMaxTTLs["webserver"])
	}
	if rc.TargetMaxTTLs["database"].Minutes() != 10 {
		t.Errorf("database max_ttl: expected 10m, got %s", rc.TargetMaxTTLs["database"])
	}

	t.Logf("Policy loaded: %d agents, %d targets, %d roles",
		len(rc.Raw.Agents), len(rc.Raw.Targets), len(rc.Raw.Roles))
}
