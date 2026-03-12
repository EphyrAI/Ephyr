package policy

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

// baseRBACConfig returns a Config with templates, targets, roles, and several
// agents exercising different RBAC patterns.
func baseRBACConfig() *Config {
	return &Config{
		Global: GlobalPolicy{
			MaxActiveCerts: 10,
			DefaultTTL:     "5m",
			MaxTTL:         "30m",
		},
		Roles: map[string]RoleDefinition{
			"read":     {Principal: "agent-read"},
			"operator": {Principal: "agent-op"},
			"admin":    {Principal: "agent-admin"},
		},
		Targets: map[string]TargetPolicy{
			"web": {
				Host:         "10.0.0.1",
				Port:         22,
				AllowedRoles: []string{"read", "operator"},
				AutoApprove:  true,
			},
			"db": {
				Host:         "10.0.0.2",
				Port:         22,
				AllowedRoles: []string{"read"},
				AutoApprove:  false,
			},
			"staging": {
				Host:         "10.0.0.3",
				Port:         22,
				AllowedRoles: []string{"read", "operator", "admin"},
				AutoApprove:  true,
			},
		},
		Templates: map[string]TemplatePolicy{
			"monitoring": {
				Description: "read-only monitoring",
				SSH: map[string]AgentTargetAccess{
					"web": {Roles: []string{"read"}},
					"db":  {Roles: []string{"read"}},
				},
				Services: map[string]ServiceAccess{
					"grafana":    {Methods: []string{"GET"}},
					"uptime-kuma": {Methods: nil}, // all methods
				},
				Remotes: map[string]RemoteAccess{
					"demo-tools": {Tools: []string{"roll_dice", "get_time"}},
				},
				Dashboard: "viewer",
			},
			"full-ops": {
				Description: "full operational access",
				SSH: map[string]AgentTargetAccess{
					"*": {Roles: []string{"read", "operator"}},
				},
				Services: map[string]ServiceAccess{
					"*": {Methods: nil}, // all methods, all services
				},
				Remotes: map[string]RemoteAccess{
					"*": {Tools: nil}, // all tools, all remotes
				},
				Dashboard: "operator",
			},
		},
		Agents: map[string]AgentPolicy{
			// Legacy agent: no RBAC fields at all.
			"legacy-bot": {
				UID:                1000,
				MaxConcurrentCerts: 3,
				Description:        "legacy agent with no RBAC",
			},

			// Agent inheriting single template.
			"monitor-bot": {
				UID:                1001,
				MaxConcurrentCerts: 2,
				Description:        "monitoring agent",
				Inherits:           []string{"monitoring"},
			},

			// Agent inheriting multiple templates (left-to-right merge).
			"ops-monitor": {
				UID:                1002,
				MaxConcurrentCerts: 3,
				Description:        "ops+monitoring agent",
				Inherits:           []string{"full-ops", "monitoring"},
			},

			// Agent with template + agent-level override.
			"override-bot": {
				UID:                1003,
				MaxConcurrentCerts: 3,
				Description:        "agent with overrides",
				Inherits:           []string{"monitoring"},
				SSH: map[string]AgentTargetAccess{
					"web":     {Roles: []string{"read", "operator"}, AutoApprove: boolPtr(false)},
					"staging": {Roles: []string{"admin"}},
				},
				Services: map[string]ServiceAccess{
					"grafana": {Methods: []string{"GET", "POST"}}, // override monitoring GET-only
				},
				Remotes: map[string]RemoteAccess{
					"demo-tools": {Tools: nil}, // override to all tools
				},
				Dashboard: "admin",
			},

			// Agent with wildcard SSH.
			"wildcard-ssh": {
				UID:                1004,
				MaxConcurrentCerts: 3,
				SSH: map[string]AgentTargetAccess{
					"*": {Roles: []string{"read"}},
				},
			},

			// Agent with wildcard services with method restrictions.
			"wildcard-svc": {
				UID:                1005,
				MaxConcurrentCerts: 3,
				Services: map[string]ServiceAccess{
					"*": {Methods: []string{"GET"}},
				},
			},

			// Agent with wildcard remotes with tool restrictions.
			"wildcard-remote": {
				UID:                1006,
				MaxConcurrentCerts: 3,
				Remotes: map[string]RemoteAccess{
					"*": {Tools: []string{"roll_dice"}},
				},
			},

			// Agent with only dashboard set (has RBAC).
			"dashboard-only": {
				UID:                1007,
				MaxConcurrentCerts: 1,
				Dashboard:          "viewer",
			},

			// Agent inheriting full-ops with an agent-level SSH override.
			"ops-override": {
				UID:                1008,
				MaxConcurrentCerts: 3,
				Inherits:           []string{"full-ops"},
				SSH: map[string]AgentTargetAccess{
					"web": {Roles: []string{"read"}}, // restrict web to read-only
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// ResolveAgentPerms
// ---------------------------------------------------------------------------

func TestResolveAgentPerms_LegacyMode(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	p := perms["legacy-bot"]
	if p == nil {
		t.Fatal("legacy-bot perms not found")
	}
	if !p.LegacyMode {
		t.Error("expected LegacyMode=true for agent with no RBAC fields")
	}
	if p.Dashboard != DashboardAdmin {
		t.Errorf("legacy mode dashboard: got %d, want %d (admin)", p.Dashboard, DashboardAdmin)
	}
}

func TestResolveAgentPerms_SingleTemplateInheritance(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	p := perms["monitor-bot"]
	if p == nil {
		t.Fatal("monitor-bot perms not found")
	}
	if p.LegacyMode {
		t.Error("monitor-bot should not be in legacy mode")
	}

	// SSH: inherited from monitoring template (web:read, db:read).
	// web: monitoring says [read], target allows [read, operator] → intersect = [read].
	if access, ok := p.SSHAccess["web"]; !ok {
		t.Error("expected SSH access to web")
	} else if !sliceEqual(access.Roles, []string{"read"}) {
		t.Errorf("web roles: got %v, want [read]", access.Roles)
	}

	// db: monitoring says [read], target allows [read] → intersect = [read].
	if access, ok := p.SSHAccess["db"]; !ok {
		t.Error("expected SSH access to db")
	} else if !sliceEqual(access.Roles, []string{"read"}) {
		t.Errorf("db roles: got %v, want [read]", access.Roles)
	}

	// Services.
	if svc, ok := p.ServiceAccess["grafana"]; !ok {
		t.Error("expected grafana service access")
	} else if !sliceEqual(svc.Methods, []string{"GET"}) {
		t.Errorf("grafana methods: got %v, want [GET]", svc.Methods)
	}

	if svc, ok := p.ServiceAccess["uptime-kuma"]; !ok {
		t.Error("expected uptime-kuma service access")
	} else if len(svc.Methods) != 0 {
		t.Errorf("uptime-kuma methods: got %v, want empty (all)", svc.Methods)
	}

	// Remotes.
	if remote, ok := p.RemoteAccess["demo-tools"]; !ok {
		t.Error("expected demo-tools remote access")
	} else if !sliceEqual(remote.Tools, []string{"roll_dice", "get_time"}) {
		t.Errorf("demo-tools tools: got %v, want [roll_dice, get_time]", remote.Tools)
	}

	// Dashboard.
	if p.Dashboard != DashboardViewer {
		t.Errorf("dashboard: got %d, want %d (viewer)", p.Dashboard, DashboardViewer)
	}
}

func TestResolveAgentPerms_MultipleTemplatesMerge(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	p := perms["ops-monitor"]
	if p == nil {
		t.Fatal("ops-monitor perms not found")
	}

	// full-ops is first: SSH["*"] = [read, operator].
	// monitoring is second: SSH["web"] and SSH["db"] should NOT override "*"
	// because first-wins per key: "*" from full-ops wins for "*",
	// but "web" and "db" from monitoring are different keys so they get added.
	if _, ok := p.SSHAccess["*"]; !ok {
		t.Error("expected wildcard SSH access from full-ops")
	}
	// monitoring's "web" and "db" should also be present (different keys).
	if _, ok := p.SSHAccess["web"]; !ok {
		t.Error("expected web SSH from monitoring")
	}
	if _, ok := p.SSHAccess["db"]; !ok {
		t.Error("expected db SSH from monitoring")
	}

	// Services: full-ops has "*", monitoring has "grafana" and "uptime-kuma".
	if _, ok := p.ServiceAccess["*"]; !ok {
		t.Error("expected wildcard service from full-ops")
	}
	if _, ok := p.ServiceAccess["grafana"]; !ok {
		t.Error("expected grafana service from monitoring")
	}

	// Dashboard: full-ops is "operator", monitoring is "viewer".
	// First-wins: operator.
	if p.Dashboard != DashboardOperator {
		t.Errorf("dashboard: got %d, want %d (operator)", p.Dashboard, DashboardOperator)
	}
}

func TestResolveAgentPerms_AgentOverridesTemplate(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	p := perms["override-bot"]
	if p == nil {
		t.Fatal("override-bot perms not found")
	}

	// Agent overrides web SSH: [read, operator] with auto_approve=false.
	// Target allows [read, operator] → intersect = [read, operator].
	webAccess := p.SSHAccess["web"]
	if webAccess == nil {
		t.Fatal("expected web SSH access")
	}
	if !sliceEqual(webAccess.Roles, []string{"read", "operator"}) {
		t.Errorf("web roles: got %v, want [read, operator]", webAccess.Roles)
	}
	if webAccess.AutoApprove == nil || *webAccess.AutoApprove != false {
		t.Error("web auto_approve should be false (agent override)")
	}

	// Agent adds staging SSH: [admin].
	// Target allows [read, operator, admin] → intersect = [admin].
	stagingAccess := p.SSHAccess["staging"]
	if stagingAccess == nil {
		t.Fatal("expected staging SSH access")
	}
	if !sliceEqual(stagingAccess.Roles, []string{"admin"}) {
		t.Errorf("staging roles: got %v, want [admin]", stagingAccess.Roles)
	}

	// Template's db SSH should still be present (not overridden).
	dbAccess := p.SSHAccess["db"]
	if dbAccess == nil {
		t.Fatal("expected db SSH from monitoring template")
	}

	// Agent overrides grafana to GET+POST (template was GET-only).
	grafana := p.ServiceAccess["grafana"]
	if grafana == nil {
		t.Fatal("expected grafana service")
	}
	if !sliceEqual(grafana.Methods, []string{"GET", "POST"}) {
		t.Errorf("grafana methods: got %v, want [GET, POST]", grafana.Methods)
	}

	// Template's uptime-kuma should still be present.
	if _, ok := p.ServiceAccess["uptime-kuma"]; !ok {
		t.Error("expected uptime-kuma from template")
	}

	// Agent overrides demo-tools to all tools (nil).
	demoTools := p.RemoteAccess["demo-tools"]
	if demoTools == nil {
		t.Fatal("expected demo-tools remote")
	}
	if len(demoTools.Tools) != 0 {
		t.Errorf("demo-tools tools: got %v, want empty (all)", demoTools.Tools)
	}

	// Dashboard: agent sets "admin", overriding template "viewer".
	if p.Dashboard != DashboardAdmin {
		t.Errorf("dashboard: got %d, want %d (admin)", p.Dashboard, DashboardAdmin)
	}
}

func TestResolveAgentPerms_AgentOverrideWinsOverTemplate(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	p := perms["ops-override"]
	if p == nil {
		t.Fatal("ops-override perms not found")
	}

	// full-ops template has SSH["*"] = [read, operator].
	// Agent overrides web to [read] only.
	// Agent-level always wins, so web should be [read] only.
	webAccess := p.SSHAccess["web"]
	if webAccess == nil {
		t.Fatal("expected web SSH")
	}
	// Target allows [read, operator], agent says [read] → intersect = [read].
	if !sliceEqual(webAccess.Roles, []string{"read"}) {
		t.Errorf("web roles: got %v, want [read]", webAccess.Roles)
	}

	// Wildcard from template should still be there.
	if _, ok := p.SSHAccess["*"]; !ok {
		t.Error("expected wildcard SSH from full-ops template")
	}
}

// ---------------------------------------------------------------------------
// CanAccessTarget
// ---------------------------------------------------------------------------

func TestCanAccessTarget(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	tests := []struct {
		name   string
		agent  string
		target string
		want   bool
	}{
		{"legacy has access to anything", "legacy-bot", "web", true},
		{"legacy has access to unknown target", "legacy-bot", "nonexistent", true},
		{"monitor-bot can access web", "monitor-bot", "web", true},
		{"monitor-bot can access db", "monitor-bot", "db", true},
		{"monitor-bot cannot access staging", "monitor-bot", "staging", false},
		{"wildcard-ssh can access any target", "wildcard-ssh", "web", true},
		{"wildcard-ssh can access unknown target", "wildcard-ssh", "anything", true},
		{"dashboard-only cannot access SSH targets", "dashboard-only", "web", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := perms[tt.agent]
			if p == nil {
				t.Fatalf("perms for %q not found", tt.agent)
			}
			if got := p.CanAccessTarget(tt.target); got != tt.want {
				t.Errorf("CanAccessTarget(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetTargetRoles
// ---------------------------------------------------------------------------

func TestGetTargetRoles(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	tests := []struct {
		name      string
		agent     string
		target    string
		wantRoles []string
		wantNil   bool // true if expecting nil (legacy mode)
	}{
		{"legacy returns nil (all roles)", "legacy-bot", "web", nil, true},
		{"monitor-bot web has read", "monitor-bot", "web", []string{"read"}, false},
		{"monitor-bot db has read", "monitor-bot", "db", []string{"read"}, false},
		{"monitor-bot staging has no access (empty)", "monitor-bot", "staging", []string{}, false},
		{"wildcard-ssh uses wildcard roles for unknown target", "wildcard-ssh", "unknown", []string{"read"}, false},
		{"override-bot web has read and operator", "override-bot", "web", []string{"read", "operator"}, false},
		{"override-bot staging has admin", "override-bot", "staging", []string{"admin"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := perms[tt.agent]
			if p == nil {
				t.Fatalf("perms for %q not found", tt.agent)
			}
			roles := p.GetTargetRoles(tt.target)
			if tt.wantNil {
				if roles != nil {
					t.Errorf("GetTargetRoles(%q) = %v, want nil", tt.target, roles)
				}
				return
			}
			if !sliceEqual(roles, tt.wantRoles) {
				t.Errorf("GetTargetRoles(%q) = %v, want %v", tt.target, roles, tt.wantRoles)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CanAccessService
// ---------------------------------------------------------------------------

func TestCanAccessService(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	tests := []struct {
		name    string
		agent   string
		service string
		method  string
		want    bool
	}{
		{"legacy can access any service", "legacy-bot", "grafana", "DELETE", true},
		{"monitor-bot grafana GET allowed", "monitor-bot", "grafana", "GET", true},
		{"monitor-bot grafana POST denied", "monitor-bot", "grafana", "POST", false},
		{"monitor-bot uptime-kuma any method", "monitor-bot", "uptime-kuma", "DELETE", true},
		{"monitor-bot unknown service denied", "monitor-bot", "portainer", "GET", false},
		{"override-bot grafana POST allowed (override)", "override-bot", "grafana", "POST", true},
		{"wildcard-svc any service GET", "wildcard-svc", "anything", "GET", true},
		{"wildcard-svc any service POST denied", "wildcard-svc", "anything", "POST", false},
		{"dashboard-only no service access", "dashboard-only", "grafana", "GET", false},
		{"case insensitive method match", "monitor-bot", "grafana", "get", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := perms[tt.agent]
			if p == nil {
				t.Fatalf("perms for %q not found", tt.agent)
			}
			if got := p.CanAccessService(tt.service, tt.method); got != tt.want {
				t.Errorf("CanAccessService(%q, %q) = %v, want %v", tt.service, tt.method, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CanAccessRemote
// ---------------------------------------------------------------------------

func TestCanAccessRemote(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	tests := []struct {
		name   string
		agent  string
		remote string
		tool   string
		want   bool
	}{
		{"legacy can access any remote", "legacy-bot", "demo-tools", "roll_dice", true},
		{"monitor-bot demo-tools roll_dice", "monitor-bot", "demo-tools", "roll_dice", true},
		{"monitor-bot demo-tools get_time", "monitor-bot", "demo-tools", "get_time", true},
		{"monitor-bot demo-tools unknown tool denied", "monitor-bot", "demo-tools", "unknown_tool", false},
		{"monitor-bot unknown remote denied", "monitor-bot", "other-remote", "tool", false},
		{"monitor-bot remote-level check (empty tool)", "monitor-bot", "demo-tools", "", true},
		{"override-bot demo-tools all tools (nil)", "override-bot", "demo-tools", "any_tool", true},
		{"wildcard-remote any remote roll_dice", "wildcard-remote", "anything", "roll_dice", true},
		{"wildcard-remote any remote other tool denied", "wildcard-remote", "anything", "other_tool", false},
		{"wildcard-remote remote-level check", "wildcard-remote", "anything", "", true},
		{"dashboard-only no remote access", "dashboard-only", "demo-tools", "roll_dice", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := perms[tt.agent]
			if p == nil {
				t.Fatalf("perms for %q not found", tt.agent)
			}
			if got := p.CanAccessRemote(tt.remote, tt.tool); got != tt.want {
				t.Errorf("CanAccessRemote(%q, %q) = %v, want %v", tt.remote, tt.tool, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetTargetAutoApprove
// ---------------------------------------------------------------------------

func TestGetTargetAutoApprove(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	tests := []struct {
		name      string
		agent     string
		target    string
		wantNil   bool
		wantValue bool
	}{
		{"legacy returns nil", "legacy-bot", "web", true, false},
		{"override-bot web has false", "override-bot", "web", false, false},
		{"monitor-bot web has nil (no override)", "monitor-bot", "web", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := perms[tt.agent]
			if p == nil {
				t.Fatalf("perms for %q not found", tt.agent)
			}
			got := p.GetTargetAutoApprove(tt.target)
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %v", *got)
				}
			} else {
				if got == nil {
					t.Error("expected non-nil")
				} else if *got != tt.wantValue {
					t.Errorf("got %v, want %v", *got, tt.wantValue)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SSH role intersection
// ---------------------------------------------------------------------------

func TestRoleIntersection(t *testing.T) {
	tests := []struct {
		name        string
		agentRoles  []string
		targetRoles []string
		want        []string
	}{
		{"full overlap", []string{"read", "operator"}, []string{"read", "operator"}, []string{"read", "operator"}},
		{"partial overlap", []string{"read", "admin"}, []string{"read", "operator"}, []string{"read"}},
		{"no overlap", []string{"admin"}, []string{"read", "operator"}, nil},
		{"empty agent roles", nil, []string{"read"}, nil},
		{"empty target roles", []string{"read"}, nil, nil},
		{"both empty", nil, nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intersectRoles(tt.agentRoles, tt.targetRoles)
			if !sliceEqual(got, tt.want) {
				t.Errorf("intersectRoles(%v, %v) = %v, want %v",
					tt.agentRoles, tt.targetRoles, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseDashboardLevel
// ---------------------------------------------------------------------------

func TestParseDashboardLevel(t *testing.T) {
	tests := []struct {
		input string
		want  DashboardLevel
	}{
		{"viewer", DashboardViewer},
		{"Viewer", DashboardViewer},
		{"VIEWER", DashboardViewer},
		{"operator", DashboardOperator},
		{"admin", DashboardAdmin},
		{"Admin", DashboardAdmin},
		{"none", DashboardNone},
		{"", DashboardNone},
		{"invalid", DashboardNone},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := parseDashboardLevel(tt.input); got != tt.want {
				t.Errorf("parseDashboardLevel(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge case: agent with Inherits referencing undefined template.
// ResolveAgentPerms silently skips undefined templates; validation would
// have caught this already, but we test the resolver handles it gracefully.
// ---------------------------------------------------------------------------

func TestResolveAgentPerms_UndefinedTemplateSkipped(t *testing.T) {
	cfg := &Config{
		Agents: map[string]AgentPolicy{
			"bot": {
				UID:      1000,
				Inherits: []string{"nonexistent"},
				SSH: map[string]AgentTargetAccess{
					"web": {Roles: []string{"read"}},
				},
			},
		},
		Templates: map[string]TemplatePolicy{},
		Targets: map[string]TargetPolicy{
			"web": {Host: "10.0.0.1", AllowedRoles: []string{"read"}},
		},
	}

	perms := ResolveAgentPerms(cfg)
	p := perms["bot"]
	if p == nil {
		t.Fatal("bot perms not found")
	}
	if p.LegacyMode {
		t.Error("should not be legacy mode (has SSH field)")
	}
	if _, ok := p.SSHAccess["web"]; !ok {
		t.Error("expected web SSH access from agent-level settings")
	}
}

// ---------------------------------------------------------------------------
// Edge case: agent with only Inherits and no direct RBAC fields.
// ---------------------------------------------------------------------------

func TestResolveAgentPerms_OnlyInherits(t *testing.T) {
	cfg := baseRBACConfig()

	// Add an agent with only Inherits.
	cfg.Agents["inherits-only"] = AgentPolicy{
		UID:                1099,
		MaxConcurrentCerts: 3,
		Inherits:           []string{"monitoring"},
	}

	perms := ResolveAgentPerms(cfg)
	p := perms["inherits-only"]
	if p == nil {
		t.Fatal("inherits-only perms not found")
	}
	if p.LegacyMode {
		t.Error("should not be legacy mode (has Inherits)")
	}
	if p.Dashboard != DashboardViewer {
		t.Errorf("dashboard: got %d, want %d (viewer from monitoring)", p.Dashboard, DashboardViewer)
	}
}

// ---------------------------------------------------------------------------
// Edge case: wildcard target SSH roles are NOT intersected (code skips "*").
// ---------------------------------------------------------------------------

func TestResolveAgentPerms_WildcardSSHNotIntersected(t *testing.T) {
	cfg := baseRBACConfig()
	perms := ResolveAgentPerms(cfg)

	// ops-monitor inherits full-ops which has SSH["*"] = [read, operator].
	// The wildcard entry should NOT be intersected with any specific target.
	p := perms["ops-monitor"]
	if p == nil {
		t.Fatal("ops-monitor perms not found")
	}

	wc := p.SSHAccess["*"]
	if wc == nil {
		t.Fatal("expected wildcard SSH access")
	}
	if !sliceEqual(wc.Roles, []string{"read", "operator"}) {
		t.Errorf("wildcard roles: got %v, want [read, operator]", wc.Roles)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sliceEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
