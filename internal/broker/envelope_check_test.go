package broker

import (
	"strings"
	"testing"

	"github.com/ben-spanswick/ephyr/internal/token"
)

// helper to build an MCPAgent with the given envelope.
func agentWithEnvelope(env token.Envelope) *MCPAgent {
	return &MCPAgent{
		Name:  "test-agent",
		Roles: []string{"read", "operator"},
		TaskClaims: &token.TaskClaims{
			Envelope: env,
		},
	}
}

// helper for a legacy-mode agent (no task token).
func legacyAgent() *MCPAgent {
	return &MCPAgent{
		Name:  "legacy-agent",
		Roles: []string{"read", "operator"},
	}
}

// --- enforceExecEnvelope tests ---

func TestEnforceExecEnvelope_NilTaskClaims(t *testing.T) {
	agent := legacyAgent()
	if err := enforceExecEnvelope(agent, "dockerhost", "operator"); err != nil {
		t.Errorf("expected nil for legacy agent, got: %v", err)
	}
}

func TestEnforceExecEnvelope_Permitted(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Targets: []string{"dockerhost", "hugoblog"},
		Roles:   []string{"read", "operator"},
	})
	if err := enforceExecEnvelope(agent, "dockerhost", "operator"); err != nil {
		t.Errorf("expected nil for permitted target+role, got: %v", err)
	}
}

func TestEnforceExecEnvelope_WildcardPermitsAll(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Targets: []string{"*"},
		Roles:   []string{"*"},
	})
	if err := enforceExecEnvelope(agent, "anything", "admin"); err != nil {
		t.Errorf("expected nil for wildcard envelope, got: %v", err)
	}
}

func TestEnforceExecEnvelope_DeniedTarget(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Targets: []string{"hugoblog"},
		Roles:   []string{"read", "operator"},
	})
	err := enforceExecEnvelope(agent, "dockerhost", "read")
	if err == nil {
		t.Fatal("expected error for denied target, got nil")
	}
	if !strings.Contains(err.Error(), "target") || !strings.Contains(err.Error(), "dockerhost") {
		t.Errorf("error should mention target and name, got: %v", err)
	}
}

func TestEnforceExecEnvelope_DeniedRole(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Targets: []string{"dockerhost"},
		Roles:   []string{"read"},
	})
	err := enforceExecEnvelope(agent, "dockerhost", "admin")
	if err == nil {
		t.Fatal("expected error for denied role, got nil")
	}
	if !strings.Contains(err.Error(), "role") || !strings.Contains(err.Error(), "admin") {
		t.Errorf("error should mention role and name, got: %v", err)
	}
}

// --- enforceProxyEnvelope tests ---

func TestEnforceProxyEnvelope_NilTaskClaims(t *testing.T) {
	agent := legacyAgent()
	if err := enforceProxyEnvelope(agent, "grafana", "GET"); err != nil {
		t.Errorf("expected nil for legacy agent, got: %v", err)
	}
}

func TestEnforceProxyEnvelope_Permitted(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Services: []string{"grafana", "portainer"},
		Methods:  []string{"GET", "POST"},
	})
	if err := enforceProxyEnvelope(agent, "grafana", "GET"); err != nil {
		t.Errorf("expected nil for permitted service+method, got: %v", err)
	}
}

func TestEnforceProxyEnvelope_WildcardPermitsAll(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Services: []string{"*"},
		Methods:  []string{"*"},
	})
	if err := enforceProxyEnvelope(agent, "anything", "DELETE"); err != nil {
		t.Errorf("expected nil for wildcard envelope, got: %v", err)
	}
}

func TestEnforceProxyEnvelope_DeniedService(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Services: []string{"grafana"},
		Methods:  []string{"GET"},
	})
	err := enforceProxyEnvelope(agent, "portainer", "GET")
	if err == nil {
		t.Fatal("expected error for denied service, got nil")
	}
	if !strings.Contains(err.Error(), "service") || !strings.Contains(err.Error(), "portainer") {
		t.Errorf("error should mention service and name, got: %v", err)
	}
}

func TestEnforceProxyEnvelope_DeniedMethod(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Services: []string{"grafana"},
		Methods:  []string{"GET"},
	})
	err := enforceProxyEnvelope(agent, "grafana", "DELETE")
	if err == nil {
		t.Fatal("expected error for denied method, got nil")
	}
	if !strings.Contains(err.Error(), "method") || !strings.Contains(err.Error(), "DELETE") {
		t.Errorf("error should mention method and name, got: %v", err)
	}
}

// --- enforceFederationEnvelope tests ---

func TestEnforceFederationEnvelope_NilTaskClaims(t *testing.T) {
	agent := legacyAgent()
	if err := enforceFederationEnvelope(agent, "demo-tools"); err != nil {
		t.Errorf("expected nil for legacy agent, got: %v", err)
	}
}

func TestEnforceFederationEnvelope_Permitted(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Remotes: []string{"demo-tools", "prod-api"},
	})
	if err := enforceFederationEnvelope(agent, "demo-tools"); err != nil {
		t.Errorf("expected nil for permitted remote, got: %v", err)
	}
}

func TestEnforceFederationEnvelope_WildcardPermitsAll(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Remotes: []string{"*"},
	})
	if err := enforceFederationEnvelope(agent, "any-remote"); err != nil {
		t.Errorf("expected nil for wildcard envelope, got: %v", err)
	}
}

func TestEnforceFederationEnvelope_DeniedRemote(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{
		Remotes: []string{"demo-tools"},
	})
	err := enforceFederationEnvelope(agent, "prod-api")
	if err == nil {
		t.Fatal("expected error for denied remote, got nil")
	}
	if !strings.Contains(err.Error(), "remote") || !strings.Contains(err.Error(), "prod-api") {
		t.Errorf("error should mention remote and name, got: %v", err)
	}
}

// --- Edge cases ---

func TestEnforceExecEnvelope_EmptyEnvelope(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{})
	err := enforceExecEnvelope(agent, "dockerhost", "read")
	if err == nil {
		t.Fatal("expected error for empty envelope, got nil")
	}
}

func TestEnforceProxyEnvelope_EmptyEnvelope(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{})
	err := enforceProxyEnvelope(agent, "grafana", "GET")
	if err == nil {
		t.Fatal("expected error for empty envelope, got nil")
	}
}

func TestEnforceFederationEnvelope_EmptyEnvelope(t *testing.T) {
	agent := agentWithEnvelope(token.Envelope{})
	err := enforceFederationEnvelope(agent, "demo-tools")
	if err == nil {
		t.Fatal("expected error for empty envelope, got nil")
	}
}
