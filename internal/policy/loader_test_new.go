package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helper
// ---------------------------------------------------------------------------

func writeLoaderTestPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Valid YAML loading
// ---------------------------------------------------------------------------

func TestLoader_ValidMinimalConfig(t *testing.T) {
	yaml := `
global:
  max_active_certs: 5
  default_ttl: "3m"
  max_ttl: "15m"
agents:
  bot:
    uid: 1000
    max_concurrent_certs: 2
roles:
  read:
    principal: "agent-read"
targets:
  server:
    host: "10.0.0.1"
    port: 22
    allowed_roles: [read]
    max_ttl: "10m"
    auto_approve: true
`
	path := writeLoaderTestPolicy(t, yaml)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if loader == nil {
		t.Fatal("loader is nil")
	}
	if rc == nil {
		t.Fatal("resolved config is nil")
	}

	// Verify parsed values.
	if rc.GlobalDefaultTTL.Minutes() != 3 {
		t.Errorf("default TTL: got %s, want 3m", rc.GlobalDefaultTTL)
	}
	if rc.GlobalMaxTTL.Minutes() != 15 {
		t.Errorf("max TTL: got %s, want 15m", rc.GlobalMaxTTL)
	}
	if rc.TargetMaxTTLs["server"].Minutes() != 10 {
		t.Errorf("server max TTL: got %s, want 10m", rc.TargetMaxTTLs["server"])
	}
	if len(rc.Raw.Agents) != 1 {
		t.Errorf("agents: got %d, want 1", len(rc.Raw.Agents))
	}
	if len(rc.Raw.Targets) != 1 {
		t.Errorf("targets: got %d, want 1", len(rc.Raw.Targets))
	}
	if len(rc.Raw.Roles) != 1 {
		t.Errorf("roles: got %d, want 1", len(rc.Raw.Roles))
	}
}

func TestLoader_DefaultsApplied(t *testing.T) {
	// Minimal config relying on defaults.
	yaml := `
agents:
  bot:
    uid: 1000
roles:
  read:
    principal: "agent-read"
targets:
  server:
    host: "10.0.0.1"
    allowed_roles: [read]
`
	path := writeLoaderTestPolicy(t, yaml)
	_, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	// Check defaults.
	if rc.Raw.Global.MaxActiveCerts != 10 {
		t.Errorf("max_active_certs default: got %d, want 10", rc.Raw.Global.MaxActiveCerts)
	}
	if rc.GlobalDefaultTTL.Minutes() != 5 {
		t.Errorf("default_ttl default: got %s, want 5m", rc.GlobalDefaultTTL)
	}
	if rc.GlobalMaxTTL.Minutes() != 30 {
		t.Errorf("max_ttl default: got %s, want 30m", rc.GlobalMaxTTL)
	}
	if rc.Raw.Global.RateLimit.RequestsPerWindow != 10 {
		t.Errorf("rate limit default: got %d, want 10", rc.Raw.Global.RateLimit.RequestsPerWindow)
	}
	if rc.Raw.Global.RateLimit.WindowSeconds != 60 {
		t.Errorf("window seconds default: got %d, want 60", rc.Raw.Global.RateLimit.WindowSeconds)
	}

	// Agent default.
	bot := rc.Raw.Agents["bot"]
	if bot.MaxConcurrentCerts != 3 {
		t.Errorf("agent max_concurrent_certs default: got %d, want 3", bot.MaxConcurrentCerts)
	}

	// Target defaults.
	srv := rc.Raw.Targets["server"]
	if srv.Port != 22 {
		t.Errorf("target port default: got %d, want 22", srv.Port)
	}

	// Target with no max_ttl defaults to global max_ttl.
	if rc.TargetMaxTTLs["server"].Minutes() != 30 {
		t.Errorf("target max_ttl default: got %s, want 30m", rc.TargetMaxTTLs["server"])
	}
}

func TestLoader_WithTemplatesAndRBAC(t *testing.T) {
	yaml := `
global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"
templates:
  monitoring:
    description: "read-only monitoring"
    ssh:
      web: {roles: [read]}
    services:
      grafana: {methods: [GET]}
    dashboard: "viewer"
agents:
  bot:
    uid: 1000
    inherits: [monitoring]
    ssh:
      db: {roles: [read]}
    dashboard: "admin"
roles:
  read:
    principal: "agent-read"
targets:
  web:
    host: "10.0.0.1"
    allowed_roles: [read]
  db:
    host: "10.0.0.2"
    allowed_roles: [read]
`
	path := writeLoaderTestPolicy(t, yaml)
	_, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	// Check that RBAC was resolved.
	if rc.AgentPerms == nil {
		t.Fatal("AgentPerms is nil")
	}
	perms := rc.AgentPerms["bot"]
	if perms == nil {
		t.Fatal("bot perms not found")
	}
	if perms.LegacyMode {
		t.Error("bot should not be in legacy mode")
	}
	if perms.Dashboard != DashboardAdmin {
		t.Errorf("dashboard: got %d, want %d (admin)", perms.Dashboard, DashboardAdmin)
	}
	// web from template, db from agent.
	if _, ok := perms.SSHAccess["web"]; !ok {
		t.Error("expected web SSH from template")
	}
	if _, ok := perms.SSHAccess["db"]; !ok {
		t.Error("expected db SSH from agent")
	}
}

// ---------------------------------------------------------------------------
// Validation error cases (table-driven)
// ---------------------------------------------------------------------------

func TestLoader_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "no agents defined",
			yaml: `
agents: {}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read]}
`,
			wantErr: "no agents defined",
		},
		{
			name: "duplicate agent UIDs",
			yaml: `
agents:
  a: {uid: 100}
  b: {uid: 100}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read]}
`,
			wantErr: "duplicate UID",
		},
		{
			name: "undefined role in target",
			yaml: `
agents:
  a: {uid: 100}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [admin]}
`,
			wantErr: "undefined role",
		},
		{
			name: "role with empty principal",
			yaml: `
agents:
  a: {uid: 100}
roles:
  read: {principal: ""}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read]}
`,
			wantErr: "empty principal",
		},
		{
			name: "target with empty host",
			yaml: `
agents:
  a: {uid: 100}
roles:
  read: {principal: "r"}
targets:
  s: {host: "", allowed_roles: [read]}
`,
			wantErr: "empty host",
		},
		{
			name: "duplicate target host:port",
			yaml: `
agents:
  a: {uid: 100}
roles:
  read: {principal: "r"}
targets:
  s1: {host: "1.2.3.4", port: 22, allowed_roles: [read]}
  s2: {host: "1.2.3.4", port: 22, allowed_roles: [read]}
`,
			wantErr: "duplicate target host",
		},
		{
			name: "invalid global default_ttl",
			yaml: `
global:
  default_ttl: "nope"
  max_ttl: "30m"
agents:
  a: {uid: 100}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read]}
`,
			wantErr: "invalid global default_ttl",
		},
		{
			name: "invalid global max_ttl",
			yaml: `
global:
  default_ttl: "5m"
  max_ttl: "badvalue"
agents:
  a: {uid: 100}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read]}
`,
			wantErr: "invalid global max_ttl",
		},
		{
			name: "default_ttl exceeds max_ttl",
			yaml: `
global:
  default_ttl: "1h"
  max_ttl: "30m"
agents:
  a: {uid: 100}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read]}
`,
			wantErr: "exceeds max_ttl",
		},
		{
			name: "target max_ttl exceeds global max_ttl",
			yaml: `
global:
  default_ttl: "5m"
  max_ttl: "10m"
agents:
  a: {uid: 100}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read], max_ttl: "20m"}
`,
			wantErr: "exceeds global max_ttl",
		},
		{
			name: "invalid target max_ttl format",
			yaml: `
global:
  default_ttl: "5m"
  max_ttl: "30m"
agents:
  a: {uid: 100}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read], max_ttl: "notaduration"}
`,
			wantErr: "invalid max_ttl",
		},
		{
			name: "agent inherits undefined template",
			yaml: `
agents:
  a:
    uid: 100
    inherits: [nonexistent]
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read]}
`,
			wantErr: "undefined template",
		},
		{
			name: "invalid YAML syntax",
			yaml: `
agents:
  a: {uid: [broken
roles:
`,
			wantErr: "parsing YAML",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeLoaderTestPolicy(t, tt.yaml)
			_, _, err := LoadFromFile(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Missing file
// ---------------------------------------------------------------------------

func TestLoader_MissingFile(t *testing.T) {
	_, _, err := LoadFromFile("/tmp/nonexistent-policy-file-xyz.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "reading file") {
		t.Errorf("error %q should mention file reading", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Hot-reload
// ---------------------------------------------------------------------------

func TestLoader_HotReload(t *testing.T) {
	initialYAML := `
agents:
  bot: {uid: 1000}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read], auto_approve: true}
`
	path := writeLoaderTestPolicy(t, initialYAML)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// Verify initial state.
	if rc.Raw.Global.MaxActiveCerts != 10 { // default
		t.Fatalf("initial max_active_certs: got %d, want 10", rc.Raw.Global.MaxActiveCerts)
	}

	// Rewrite with changed values.
	updatedYAML := `
global:
  max_active_certs: 25
agents:
  bot: {uid: 1000}
  newbot: {uid: 2000}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read], auto_approve: false}
`
	if err := os.WriteFile(path, []byte(updatedYAML), 0644); err != nil {
		t.Fatal(err)
	}

	rc2, err := loader.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if rc2.Raw.Global.MaxActiveCerts != 25 {
		t.Errorf("reloaded max_active_certs: got %d, want 25", rc2.Raw.Global.MaxActiveCerts)
	}
	if len(rc2.Raw.Agents) != 2 {
		t.Errorf("reloaded agents: got %d, want 2", len(rc2.Raw.Agents))
	}
	if rc2.Raw.Targets["s"].AutoApprove {
		t.Error("expected auto_approve false after reload")
	}

	// Loader.Resolved() should return the new config.
	rc3 := loader.Resolved()
	if rc3.Raw.Global.MaxActiveCerts != 25 {
		t.Errorf("Resolved() max_active_certs: got %d, want 25", rc3.Raw.Global.MaxActiveCerts)
	}
}

func TestLoader_HotReloadInvalidKeepsOld(t *testing.T) {
	validYAML := `
agents:
  bot: {uid: 1000}
roles:
  read: {principal: "r"}
targets:
  s: {host: "1.2.3.4", allowed_roles: [read]}
`
	path := writeLoaderTestPolicy(t, validYAML)
	loader, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// Overwrite with invalid YAML.
	if err := os.WriteFile(path, []byte("{{{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = loader.Reload()
	if err == nil {
		t.Fatal("expected reload error for invalid YAML")
	}

	// Original config should be preserved.
	current := loader.Resolved()
	if current != rc {
		t.Error("Resolved() should return original config after failed reload")
	}
}

// ---------------------------------------------------------------------------
// applyDefaults
// ---------------------------------------------------------------------------

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{
		Agents: map[string]AgentPolicy{
			"bot": {UID: 1000}, // MaxConcurrentCerts = 0
		},
		Targets: map[string]TargetPolicy{
			"s": {Host: "1.2.3.4"}, // Port = 0
		},
	}

	applyDefaults(cfg)

	if cfg.Global.MaxActiveCerts != 10 {
		t.Errorf("max_active_certs: got %d, want 10", cfg.Global.MaxActiveCerts)
	}
	if cfg.Global.DefaultTTL != "5m" {
		t.Errorf("default_ttl: got %q, want %q", cfg.Global.DefaultTTL, "5m")
	}
	if cfg.Global.MaxTTL != "30m" {
		t.Errorf("max_ttl: got %q, want %q", cfg.Global.MaxTTL, "30m")
	}
	if cfg.Global.RateLimit.RequestsPerWindow != 10 {
		t.Errorf("requests_per_window: got %d, want 10", cfg.Global.RateLimit.RequestsPerWindow)
	}
	if cfg.Global.RateLimit.WindowSeconds != 60 {
		t.Errorf("window_seconds: got %d, want 60", cfg.Global.RateLimit.WindowSeconds)
	}
	if cfg.Agents["bot"].MaxConcurrentCerts != 3 {
		t.Errorf("agent max_concurrent_certs: got %d, want 3", cfg.Agents["bot"].MaxConcurrentCerts)
	}
	if cfg.Targets["s"].Port != 22 {
		t.Errorf("target port: got %d, want 22", cfg.Targets["s"].Port)
	}
}

func TestApplyDefaults_DoesNotOverrideExisting(t *testing.T) {
	cfg := &Config{
		Global: GlobalPolicy{
			MaxActiveCerts: 50,
			DefaultTTL:     "10m",
			MaxTTL:         "1h",
			RateLimit: RateLimitConfig{
				RequestsPerWindow: 100,
				WindowSeconds:     300,
			},
		},
		Agents: map[string]AgentPolicy{
			"bot": {UID: 1000, MaxConcurrentCerts: 10},
		},
		Targets: map[string]TargetPolicy{
			"s": {Host: "1.2.3.4", Port: 2222},
		},
	}

	applyDefaults(cfg)

	if cfg.Global.MaxActiveCerts != 50 {
		t.Errorf("should not override: got %d, want 50", cfg.Global.MaxActiveCerts)
	}
	if cfg.Global.DefaultTTL != "10m" {
		t.Errorf("should not override: got %q, want %q", cfg.Global.DefaultTTL, "10m")
	}
	if cfg.Global.MaxTTL != "1h" {
		t.Errorf("should not override: got %q, want %q", cfg.Global.MaxTTL, "1h")
	}
	if cfg.Global.RateLimit.RequestsPerWindow != 100 {
		t.Errorf("should not override: got %d, want 100", cfg.Global.RateLimit.RequestsPerWindow)
	}
	if cfg.Agents["bot"].MaxConcurrentCerts != 10 {
		t.Errorf("should not override: got %d, want 10", cfg.Agents["bot"].MaxConcurrentCerts)
	}
	if cfg.Targets["s"].Port != 2222 {
		t.Errorf("should not override: got %d, want 2222", cfg.Targets["s"].Port)
	}
}
