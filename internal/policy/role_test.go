package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// resolveRoles tests
// ---------------------------------------------------------------------------

func TestResolveRoles_Defaults(t *testing.T) {
	cfg := &Config{
		Roles: map[string]RoleDefinition{
			"read": {Principal: "agent-read"},
		},
	}

	resolved, err := resolveRoles(cfg)
	if err != nil {
		t.Fatalf("resolveRoles: %v", err)
	}

	r := resolved["read"]
	if r == nil {
		t.Fatal("expected resolved role 'read'")
	}
	if r.Name != "read" {
		t.Errorf("Name: got %q, want %q", r.Name, "read")
	}
	if r.Principal != "agent-read" {
		t.Errorf("Principal: got %q, want %q", r.Principal, "agent-read")
	}
	if r.Shell != "/bin/bash" {
		t.Errorf("Shell: got %q, want /bin/bash (default)", r.Shell)
	}
	if r.SudoRules != nil {
		t.Errorf("SudoRules: got %v, want nil (no sudo by default)", r.SudoRules)
	}
	if !r.System {
		t.Error("System: got false, want true (default)")
	}
}

func TestResolveRoles_CustomShell(t *testing.T) {
	cfg := &Config{
		Roles: map[string]RoleDefinition{
			"read": {Principal: "agent-read", Shell: "/bin/rbash"},
		},
	}

	resolved, err := resolveRoles(cfg)
	if err != nil {
		t.Fatalf("resolveRoles: %v", err)
	}

	r := resolved["read"]
	if r == nil {
		t.Fatal("expected resolved role 'read'")
	}
	if r.Shell != "/bin/rbash" {
		t.Errorf("Shell: got %q, want /bin/rbash", r.Shell)
	}
}

func TestResolveRoles_SudoBool(t *testing.T) {
	// sudo: true → ["ALL"]
	cfg := &Config{
		Roles: map[string]RoleDefinition{
			"admin": {Principal: "agent-admin", Sudo: true},
		},
	}

	resolved, err := resolveRoles(cfg)
	if err != nil {
		t.Fatalf("resolveRoles: %v", err)
	}

	r := resolved["admin"]
	if r == nil {
		t.Fatal("expected resolved role 'admin'")
	}
	if len(r.SudoRules) != 1 || r.SudoRules[0] != "ALL" {
		t.Errorf("SudoRules: got %v, want [ALL]", r.SudoRules)
	}

	// sudo: false → nil
	cfg2 := &Config{
		Roles: map[string]RoleDefinition{
			"read": {Principal: "agent-read", Sudo: false},
		},
	}

	resolved2, err := resolveRoles(cfg2)
	if err != nil {
		t.Fatalf("resolveRoles: %v", err)
	}

	r2 := resolved2["read"]
	if r2 == nil {
		t.Fatal("expected resolved role 'read'")
	}
	if r2.SudoRules != nil {
		t.Errorf("SudoRules: got %v, want nil for sudo: false", r2.SudoRules)
	}
}

func TestResolveRoles_SudoList(t *testing.T) {
	cfg := &Config{
		Roles: map[string]RoleDefinition{
			"operator": {
				Principal: "agent-op",
				Sudo: []interface{}{
					"/usr/bin/systemctl status *",
					"/usr/bin/docker ps *",
					"/usr/bin/journalctl *",
				},
			},
		},
	}

	resolved, err := resolveRoles(cfg)
	if err != nil {
		t.Fatalf("resolveRoles: %v", err)
	}

	r := resolved["operator"]
	if r == nil {
		t.Fatal("expected resolved role 'operator'")
	}
	want := []string{
		"/usr/bin/systemctl status *",
		"/usr/bin/docker ps *",
		"/usr/bin/journalctl *",
	}
	if len(r.SudoRules) != len(want) {
		t.Fatalf("SudoRules length: got %d, want %d", len(r.SudoRules), len(want))
	}
	for i, w := range want {
		if r.SudoRules[i] != w {
			t.Errorf("SudoRules[%d]: got %q, want %q", i, r.SudoRules[i], w)
		}
	}
}

func TestResolveRoles_SystemFalse(t *testing.T) {
	f := false
	cfg := &Config{
		Roles: map[string]RoleDefinition{
			"custom": {Principal: "custom-user", System: &f},
		},
	}

	resolved, err := resolveRoles(cfg)
	if err != nil {
		t.Fatalf("resolveRoles: %v", err)
	}

	r := resolved["custom"]
	if r == nil {
		t.Fatal("expected resolved role 'custom'")
	}
	if r.System {
		t.Error("System: got true, want false")
	}
}

func TestResolveRoles_InvalidShell(t *testing.T) {
	// Shell not starting with / should be rejected at validation time.
	policyYAML := `
global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"
agents:
  test:
    uid: 1000
roles:
  bad:
    principal: "agent-bad"
    shell: "relative/path/bash"
targets:
  web:
    host: "10.0.0.1"
    allowed_roles: [bad]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(policyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for shell not starting with /")
	}
	if got := err.Error(); !contains(got, "invalid shell") {
		t.Errorf("error should mention invalid shell, got: %s", got)
	}
}

func TestResolveRoles_InvalidPrincipal(t *testing.T) {
	// Principal with invalid chars should be rejected.
	policyYAML := `
global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"
agents:
  test:
    uid: 1000
roles:
  bad:
    principal: "Agent Read!"
targets:
  web:
    host: "10.0.0.1"
    allowed_roles: [bad]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(policyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid principal")
	}
	if got := err.Error(); !contains(got, "invalid principal") {
		t.Errorf("error should mention invalid principal, got: %s", got)
	}
}

func TestResolveRoles_InvalidSudoType(t *testing.T) {
	// Sudo with an unsupported type (e.g. int) should be rejected.
	policyYAML := `
global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"
agents:
  test:
    uid: 1000
roles:
  bad:
    principal: "agent-bad"
    sudo: 42
targets:
  web:
    host: "10.0.0.1"
    allowed_roles: [bad]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(policyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid sudo type")
	}
	if got := err.Error(); !contains(got, "invalid sudo type") {
		t.Errorf("error should mention invalid sudo type, got: %s", got)
	}
}

func TestResolveRoles_EmptySudoString(t *testing.T) {
	// Sudo list with empty string should be rejected.
	policyYAML := `
global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"
agents:
  test:
    uid: 1000
roles:
  bad:
    principal: "agent-bad"
    sudo:
      - "/usr/bin/systemctl *"
      - ""
targets:
  web:
    host: "10.0.0.1"
    allowed_roles: [bad]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(policyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for empty sudo string")
	}
	if got := err.Error(); !contains(got, "empty string not allowed") {
		t.Errorf("error should mention empty string, got: %s", got)
	}
}

func TestResolveRoles_IntegrationWithLoadFromFile(t *testing.T) {
	// Full integration test: load a policy with all new role fields.
	policyYAML := `
global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"
agents:
  test:
    uid: 1000
roles:
  read:
    principal: "agent-read"
    shell: "/bin/rbash"
    sudo: false
  operator:
    principal: "agent-op"
    sudo:
      - "/usr/bin/systemctl status *"
      - "/usr/bin/docker ps *"
  admin:
    principal: "agent-admin"
    sudo: true
    system: false
targets:
  web:
    host: "10.0.0.1"
    allowed_roles: [read, operator, admin]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(policyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, rc, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if len(rc.ResolvedRoles) != 3 {
		t.Fatalf("ResolvedRoles: got %d, want 3", len(rc.ResolvedRoles))
	}

	// read: rbash, no sudo, system=true (default)
	read := rc.ResolvedRoles["read"]
	if read.Shell != "/bin/rbash" {
		t.Errorf("read.Shell: got %q, want /bin/rbash", read.Shell)
	}
	if read.SudoRules != nil {
		t.Errorf("read.SudoRules: got %v, want nil", read.SudoRules)
	}
	if !read.System {
		t.Error("read.System: got false, want true")
	}

	// operator: default shell, specific commands
	op := rc.ResolvedRoles["operator"]
	if op.Shell != "/bin/bash" {
		t.Errorf("operator.Shell: got %q, want /bin/bash", op.Shell)
	}
	if len(op.SudoRules) != 2 {
		t.Fatalf("operator.SudoRules length: got %d, want 2", len(op.SudoRules))
	}

	// admin: sudo=true → ["ALL"], system=false
	admin := rc.ResolvedRoles["admin"]
	if len(admin.SudoRules) != 1 || admin.SudoRules[0] != "ALL" {
		t.Errorf("admin.SudoRules: got %v, want [ALL]", admin.SudoRules)
	}
	if admin.System {
		t.Error("admin.System: got true, want false")
	}
}

func TestResolveRoles_PrincipalValidChars(t *testing.T) {
	// Valid principals should pass.
	validPrincipals := []string{
		"agent-read",
		"agent_op",
		"a",
		"_underscored",
		"user123",
		"a-b-c_d",
	}
	for _, p := range validPrincipals {
		if !principalRe.MatchString(p) {
			t.Errorf("principalRe should match %q", p)
		}
	}

	// Invalid principals should fail.
	invalidPrincipals := []string{
		"",
		"Agent-Read",      // uppercase
		"agent read",      // space
		"agent!read",      // special char
		"123agent",        // starts with digit
		"-agent",          // starts with hyphen
		"a" + string(make([]byte, 32)), // >32 chars
	}
	for _, p := range invalidPrincipals {
		if principalRe.MatchString(p) {
			t.Errorf("principalRe should NOT match %q", p)
		}
	}
}

// contains is a simple substring check helper.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
