package policy

import "strings"

// ResolveAgentPerms resolves effective permissions for all agents.
// For each agent, it merges template permissions (left-to-right from
// the inherits list) and then overlays agent-specific settings.
// Agents with no RBAC fields get LegacyMode=true for full access.
func ResolveAgentPerms(cfg *Config) map[string]*ResolvedAgentPerms {
	result := make(map[string]*ResolvedAgentPerms)
	for name, agent := range cfg.Agents {
		result[name] = resolveAgent(name, &agent, cfg)
	}
	return result
}

func resolveAgent(name string, agent *AgentPolicy, cfg *Config) *ResolvedAgentPerms {
	// Check if agent has ANY RBAC fields set.
	hasRBAC := len(agent.SSH) > 0 ||
		len(agent.Services) > 0 ||
		len(agent.Remotes) > 0 ||
		agent.Dashboard != "" ||
		len(agent.Inherits) > 0

	if !hasRBAC {
		return &ResolvedAgentPerms{LegacyMode: true, Dashboard: DashboardAdmin}
	}

	perms := &ResolvedAgentPerms{
		SSHAccess:     make(map[string]*AgentTargetAccess),
		ServiceAccess: make(map[string]*ServiceAccess),
		RemoteAccess:  make(map[string]*RemoteAccess),
	}

	// Merge templates (left-to-right, first-wins per key).
	for _, tmplName := range agent.Inherits {
		if tmpl, ok := cfg.Templates[tmplName]; ok {
			mergeTemplatePerms(perms, &tmpl)
		}
	}

	// Override with agent-specific settings (always wins over templates).
	for target, access := range agent.SSH {
		a := access // copy
		perms.SSHAccess[target] = &a
	}
	for svc, access := range agent.Services {
		a := access
		perms.ServiceAccess[svc] = &a
	}
	for remote, access := range agent.Remotes {
		a := access
		perms.RemoteAccess[remote] = &a
	}
	if agent.Dashboard != "" {
		perms.Dashboard = parseDashboardLevel(agent.Dashboard)
	}

	// Intersect SSH roles with target allowed_roles so an agent can
	// never exceed what the target permits.
	for targetName, access := range perms.SSHAccess {
		if targetName == "*" {
			continue
		}
		if target, ok := cfg.Targets[targetName]; ok {
			access.Roles = intersectRoles(access.Roles, target.AllowedRoles)
		}
	}

	return perms
}

func mergeTemplatePerms(perms *ResolvedAgentPerms, tmpl *TemplatePolicy) {
	for k, v := range tmpl.SSH {
		if _, exists := perms.SSHAccess[k]; !exists {
			a := v
			perms.SSHAccess[k] = &a
		}
	}
	for k, v := range tmpl.Services {
		if _, exists := perms.ServiceAccess[k]; !exists {
			a := v
			perms.ServiceAccess[k] = &a
		}
	}
	for k, v := range tmpl.Remotes {
		if _, exists := perms.RemoteAccess[k]; !exists {
			a := v
			perms.RemoteAccess[k] = &a
		}
	}
	if perms.Dashboard == DashboardNone && tmpl.Dashboard != "" {
		perms.Dashboard = parseDashboardLevel(tmpl.Dashboard)
	}
}

func intersectRoles(agentRoles, targetRoles []string) []string {
	set := make(map[string]bool)
	for _, r := range targetRoles {
		set[r] = true
	}
	var result []string
	for _, r := range agentRoles {
		if set[r] {
			result = append(result, r)
		}
	}
	return result
}

func parseDashboardLevel(s string) DashboardLevel {
	switch strings.ToLower(s) {
	case "viewer":
		return DashboardViewer
	case "operator":
		return DashboardOperator
	case "admin":
		return DashboardAdmin
	default:
		return DashboardNone
	}
}

// --- Helper methods for checking permissions ---

// CanAccessTarget returns true if the agent can access the given target.
// Supports wildcard "*" entries for blanket access.
func (p *ResolvedAgentPerms) CanAccessTarget(target string) bool {
	if p.LegacyMode {
		return true
	}
	if _, ok := p.SSHAccess[target]; ok {
		return true
	}
	if _, ok := p.SSHAccess["*"]; ok {
		return true
	}
	return false
}

// GetTargetRoles returns the allowed roles for a target.
// Returns nil for legacy mode (meaning all roles allowed).
// Returns empty slice if no access.
func (p *ResolvedAgentPerms) GetTargetRoles(target string) []string {
	if p.LegacyMode {
		return nil // nil = all roles (legacy)
	}
	if access, ok := p.SSHAccess[target]; ok {
		return access.Roles
	}
	if access, ok := p.SSHAccess["*"]; ok {
		return access.Roles
	}
	return []string{} // empty = no access
}

// GetTargetAutoApprove returns the per-agent auto_approve override for a target.
// Returns nil if no override (fall back to target default).
func (p *ResolvedAgentPerms) GetTargetAutoApprove(target string) *bool {
	if p.LegacyMode {
		return nil
	}
	if access, ok := p.SSHAccess[target]; ok {
		return access.AutoApprove
	}
	if access, ok := p.SSHAccess["*"]; ok {
		return access.AutoApprove
	}
	return nil
}

// CanAccessService returns true if the agent can use the given service with
// the given HTTP method. Supports wildcard "*" entries.
func (p *ResolvedAgentPerms) CanAccessService(service, method string) bool {
	if p.LegacyMode {
		return true
	}
	access := p.getServiceAccess(service)
	if access == nil {
		return false
	}
	if len(access.Methods) == 0 {
		return true // empty = all methods
	}
	for _, m := range access.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func (p *ResolvedAgentPerms) getServiceAccess(service string) *ServiceAccess {
	if access, ok := p.ServiceAccess[service]; ok {
		return access
	}
	if access, ok := p.ServiceAccess["*"]; ok {
		return access
	}
	return nil
}

// CanAccessRemote returns true if the agent can call tools on the given remote.
// If tool is empty, checks remote-level access. Supports wildcard "*" entries.
func (p *ResolvedAgentPerms) CanAccessRemote(remote, tool string) bool {
	if p.LegacyMode {
		return true
	}
	access := p.getRemoteAccess(remote)
	if access == nil {
		return false
	}
	if len(access.Tools) == 0 {
		return true // empty = all tools
	}
	if tool == "" {
		return true // remote-level access check (tools exist = has access)
	}
	for _, t := range access.Tools {
		if t == tool {
			return true
		}
	}
	return false
}

func (p *ResolvedAgentPerms) getRemoteAccess(remote string) *RemoteAccess {
	if access, ok := p.RemoteAccess[remote]; ok {
		return access
	}
	if access, ok := p.RemoteAccess["*"]; ok {
		return access
	}
	return nil
}
