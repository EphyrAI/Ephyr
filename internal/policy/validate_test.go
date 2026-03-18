package policy

import (
	"testing"
)

// validBaseConfig returns a minimal valid Config for testing.
func validBaseConfig() *Config {
	return &Config{
		Global: GlobalPolicy{
			MaxActiveCerts: 10,
			DefaultTTL:     "5m",
			MaxTTL:         "30m",
			RateLimit: RateLimitConfig{
				RequestsPerWindow: 10,
				WindowSeconds:     60,
			},
		},
		Roles: map[string]RoleDefinition{
			"read":     {Principal: "agent-read", Description: "Read-only"},
			"operator": {Principal: "agent-op", Description: "Operator"},
		},
		Targets: map[string]TargetPolicy{
			"webserver": {
				Host:         "10.0.1.10",
				Port:         22,
				AllowedRoles: []string{"read", "operator"},
				MaxTTL:       "10m",
				AutoApprove:  true,
			},
		},
		Agents: map[string]AgentPolicy{
			"test-agent": {
				UID:                1000,
				MaxConcurrentCerts: 3,
				APIKeyHash:         "$2y$10$abc123def456ghi789jklmnopqrstuvwxyz",
			},
		},
	}
}

func TestValidatePolicy_ValidConfig(t *testing.T) {
	cfg := validBaseConfig()
	rpt := ValidatePolicy(cfg)

	if rpt.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", rpt.Errors)
		for _, r := range rpt.Results {
			if r.Severity == SeverityError {
				t.Logf("  [%s] %s: %s", r.Code, r.Section, r.Message)
			}
		}
	}
	if rpt.ExitCode() == 2 {
		t.Errorf("expected exit code != 2, got %d", rpt.ExitCode())
	}
}

func TestValidatePolicy_MissingRole(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Targets["webserver"] = TargetPolicy{
		Host:         "10.0.1.10",
		Port:         22,
		AllowedRoles: []string{"read", "superadmin"}, // superadmin is not defined
		MaxTTL:       "10m",
	}

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E3" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E3 (undefined role) error, not found")
	}
	if rpt.Errors == 0 {
		t.Error("expected at least 1 error")
	}
}

func TestValidatePolicy_UndefinedTemplate(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Agents["test-agent"] = AgentPolicy{
		UID:      1000,
		Inherits: []string{"nonexistent-template"},
	}

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E2" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E2 (undefined template) error, not found")
	}
	if rpt.Errors == 0 {
		t.Error("expected at least 1 error")
	}
}

func TestValidatePolicy_WildcardSSH(t *testing.T) {
	cfg := validBaseConfig()
	agent := cfg.Agents["test-agent"]
	agent.SSH = map[string]AgentTargetAccess{
		"*": {Roles: []string{"read"}},
	}
	cfg.Agents["test-agent"] = agent

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "W3" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected W3 (wildcard SSH) warning, not found")
	}
	if rpt.Warnings == 0 {
		t.Error("expected at least 1 warning")
	}
}

func TestValidatePolicy_WildcardSSHViaTemplate(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Templates = map[string]TemplatePolicy{
		"full-ops": {
			SSH: map[string]AgentTargetAccess{
				"*": {Roles: []string{"read", "operator"}},
			},
		},
	}
	agent := cfg.Agents["test-agent"]
	agent.Inherits = []string{"full-ops"}
	cfg.Agents["test-agent"] = agent

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "W3" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected W3 (wildcard SSH via template) warning, not found")
	}
}

func TestValidatePolicy_NoHostKey(t *testing.T) {
	cfg := validBaseConfig()
	// The base config has no host_key or host_key_fingerprint on webserver.

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "W2" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected W2 (no host_key) warning, not found")
	}
}

func TestValidatePolicy_InvalidBcrypt(t *testing.T) {
	cfg := validBaseConfig()
	agent := cfg.Agents["test-agent"]
	agent.APIKeyHash = "not-a-bcrypt-hash"
	cfg.Agents["test-agent"] = agent

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E12" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E12 (invalid bcrypt) error, not found")
	}
	if rpt.Errors == 0 {
		t.Error("expected at least 1 error")
	}
}

func TestValidatePolicy_NoAgents(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Agents = nil

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E1 (no agents) error, not found")
	}
}

func TestValidatePolicy_EmptyHost(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Targets["broken"] = TargetPolicy{
		Host:         "",
		Port:         22,
		AllowedRoles: []string{"read"},
	}

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E5" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E5 (empty host) error, not found")
	}
}

func TestValidatePolicy_EmptyPrincipal(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Roles["broken"] = RoleDefinition{Principal: ""}

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E4" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E4 (empty principal) error, not found")
	}
}

func TestValidatePolicy_InvalidTTL(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Global.DefaultTTL = "notaduration"

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E6" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E6 (invalid TTL) error, not found")
	}
}

func TestValidatePolicy_DefaultExceedsMax(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Global.DefaultTTL = "1h"
	cfg.Global.MaxTTL = "30m"

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E7" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E7 (default_ttl exceeds max_ttl) error, not found")
	}
}

func TestValidatePolicy_TargetMaxExceedsGlobal(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Targets["webserver"] = TargetPolicy{
		Host:         "10.0.1.10",
		Port:         22,
		AllowedRoles: []string{"read"},
		MaxTTL:       "2h",
	}

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E8" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E8 (target max_ttl exceeds global) error, not found")
	}
}

func TestValidatePolicy_PortOutOfRange(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Targets["webserver"] = TargetPolicy{
		Host:         "10.0.1.10",
		Port:         99999,
		AllowedRoles: []string{"read"},
	}

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E9" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E9 (port out of range) error, not found")
	}
}

func TestValidatePolicy_HostKeyStrictNoKey(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Global.HostKeyStrict = true

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E10" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E10 (host_key_strict without key) error, not found")
	}
}

func TestValidatePolicy_BadFingerprint(t *testing.T) {
	cfg := validBaseConfig()
	target := cfg.Targets["webserver"]
	target.HostKeyFingerprint = "MD5:notsha256"
	cfg.Targets["webserver"] = target

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E11" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E11 (bad fingerprint prefix) error, not found")
	}
}

func TestValidatePolicy_RootUID(t *testing.T) {
	cfg := validBaseConfig()
	agent := cfg.Agents["test-agent"]
	agent.UID = 0
	cfg.Agents["test-agent"] = agent

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "W6" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected W6 (UID 0) warning, not found")
	}
}

func TestValidatePolicy_UnusedRole(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Roles["admin"] = RoleDefinition{Principal: "agent-admin"}
	// admin is not referenced by any target

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "W7" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected W7 (unused role) warning, not found")
	}
}

func TestValidatePolicy_NoAPIKeyHash(t *testing.T) {
	cfg := validBaseConfig()
	agent := cfg.Agents["test-agent"]
	agent.APIKeyHash = ""
	cfg.Agents["test-agent"] = agent

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "W8" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected W8 (no api_key_hash) warning, not found")
	}
}

func TestValidatePolicy_WildcardServices(t *testing.T) {
	cfg := validBaseConfig()
	agent := cfg.Agents["test-agent"]
	agent.Services = map[string]ServiceAccess{
		"*": {Methods: []string{"GET"}},
	}
	cfg.Agents["test-agent"] = agent

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "W4" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected W4 (wildcard services) warning, not found")
	}
}

func TestValidatePolicy_WildcardRemotes(t *testing.T) {
	cfg := validBaseConfig()
	agent := cfg.Agents["test-agent"]
	agent.Remotes = map[string]RemoteAccess{
		"*": {},
	}
	cfg.Agents["test-agent"] = agent

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "W5" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected W5 (wildcard remotes) warning, not found")
	}
}

func TestValidatePolicy_NoTargets(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Targets = nil

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "W1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected W1 (no targets) warning, not found")
	}
}

func TestValidatePolicy_ExitCodes(t *testing.T) {
	// Clean config: exit 0
	cfg := validBaseConfig()
	// Add host key to avoid W2
	target := cfg.Targets["webserver"]
	target.HostKeyFingerprint = "SHA256:abc123"
	cfg.Targets["webserver"] = target

	rpt := ValidatePolicy(cfg)
	if rpt.ExitCode() != 0 {
		t.Errorf("clean config: expected exit 0, got %d", rpt.ExitCode())
		for _, r := range rpt.Results {
			if r.Severity != SeverityOK {
				t.Logf("  [%s] %s: %s", r.Code, r.Section, r.Message)
			}
		}
	}

	// Warnings only: exit 1
	cfg2 := validBaseConfig()
	// Base config has no host_key -> W2 warning
	rpt2 := ValidatePolicy(cfg2)
	if rpt2.ExitCode() != 1 {
		t.Errorf("warnings-only config: expected exit 1, got %d", rpt2.ExitCode())
	}

	// Errors: exit 2
	cfg3 := validBaseConfig()
	cfg3.Agents = nil
	rpt3 := ValidatePolicy(cfg3)
	if rpt3.ExitCode() != 2 {
		t.Errorf("error config: expected exit 2, got %d", rpt3.ExitCode())
	}
}

func TestValidatePolicy_DuplicateUID(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Agents["other-agent"] = AgentPolicy{
		UID:        1000, // same UID as test-agent
		APIKeyHash: "$2y$10$xyz",
	}

	rpt := ValidatePolicy(cfg)

	found := false
	for _, r := range rpt.Results {
		if r.Code == "E13" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected E13 (duplicate UID) error, not found")
	}
}
