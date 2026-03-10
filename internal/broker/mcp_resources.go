package broker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// MCP Resource types.

type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type MCPResourcesListResult struct {
	Resources []MCPResource `json:"resources"`
}

type MCPResourcesReadParams struct {
	URI string `json:"uri"`
}

type MCPResourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
}

type MCPResourcesReadResult struct {
	Contents []MCPResourceContent `json:"contents"`
}

type MCPResourcesCapability struct {
	ListChanged bool `json:"listChanged"`
}

// handleResourcesList returns the list of available resources.
func (s *MCPServer) handleResourcesList(w http.ResponseWriter, req jsonRPCRequest) {
	resources := []MCPResource{
		{
			URI:         "clauth://overview",
			Name:        "System Overview",
			Description: "High-level summary of Clauth broker capabilities, available targets, services, and your agent permissions",
			MimeType:    "text/markdown",
		},
		{
			URI:         "clauth://targets",
			Name:        "SSH Targets",
			Description: "Available SSH targets with hosts, ports, allowed roles, TTLs, and auto-approve status",
			MimeType:    "text/markdown",
		},
		{
			URI:         "clauth://services",
			Name:        "HTTP Proxy Services",
			Description: "Configured web services accessible through the authenticated HTTP proxy with credential injection",
			MimeType:    "text/markdown",
		},
		{
			URI:         "clauth://roles",
			Name:        "Roles & Permissions",
			Description: "Available roles, their SSH principals, and what each role can do on targets",
			MimeType:    "text/markdown",
		},
		{
			URI:         "clauth://status",
			Name:        "Agent Status",
			Description: "Your current active certificates, sessions, and recent activity",
			MimeType:    "text/markdown",
		},
		{
			URI:         "clauth://tools",
			Name:        "Tools Reference",
			Description: "Quick reference for all available MCP tools with parameters and usage examples",
			MimeType:    "text/markdown",
		},
	}

	s.writeJSONRPC(w, req.ID, MCPResourcesListResult{Resources: resources}, nil)
}

// handleResourcesRead returns the content of a specific resource.
func (s *MCPServer) handleResourcesRead(w http.ResponseWriter, req jsonRPCRequest, agent *MCPAgent) {
	var params MCPResourcesReadParams
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.writeJSONRPC(w, req.ID, nil, &jsonRPCError{
				Code:    mcpErrInvalidParams,
				Message: "invalid params: " + err.Error(),
			})
			return
		}
	}

	if params.URI == "" {
		s.writeJSONRPC(w, req.ID, nil, &jsonRPCError{
			Code:    mcpErrInvalidParams,
			Message: "uri is required",
		})
		return
	}

	var content string
	var err error

	switch params.URI {
	case "clauth://overview":
		content = s.resourceOverview(agent)
	case "clauth://targets":
		content = s.resourceTargets()
	case "clauth://services":
		content = s.resourceServices()
	case "clauth://roles":
		content = s.resourceRoles()
	case "clauth://status":
		content = s.resourceStatus(agent)
	case "clauth://tools":
		content = s.resourceTools()
	default:
		err = fmt.Errorf("unknown resource: %s", params.URI)
	}

	if err != nil {
		s.writeJSONRPC(w, req.ID, nil, &jsonRPCError{
			Code:    mcpErrInvalidParams,
			Message: err.Error(),
		})
		return
	}

	s.writeJSONRPC(w, req.ID, MCPResourcesReadResult{
		Contents: []MCPResourceContent{
			{
				URI:      params.URI,
				MimeType: "text/markdown",
				Text:     content,
			},
		},
	}, nil)
}

// resourceOverview returns a high-level summary of the broker.
func (s *MCPServer) resourceOverview(agent *MCPAgent) string {
	var b strings.Builder
	cfg := s.broker.policyEngine.Config()

	b.WriteString("# Clauth Agent Access Broker\n\n")
	b.WriteString("Zero-trust infrastructure access for AI agents. Every connection authenticated, authorized, audited.\n\n")

	b.WriteString(fmt.Sprintf("**Agent:** %s\n", agent.Name))
	b.WriteString("**Protocol:** MCP 2025-03-26 (JSON-RPC 2.0 over Streamable HTTP)\n")
	b.WriteString("**Broker:** clauth v1.0.0\n\n")

	// Targets summary
	targets := cfg.Raw.Targets
	names := sortedKeys(targets)
	b.WriteString(fmt.Sprintf("## SSH Targets (%d available)\n\n", len(targets)))
	b.WriteString("You can execute commands on these hosts via ephemeral SSH certificates:\n\n")
	b.WriteString("| Target | Host | Roles | Auto-approve |\n")
	b.WriteString("|--------|------|-------|--------------|\n")
	for _, name := range names {
		t := targets[name]
		roles := strings.Join(t.AllowedRoles, ", ")
		approve := "no"
		if t.AutoApprove {
			approve = "yes"
		}
		port := t.Port
		if port == 0 {
			port = 22
		}
		b.WriteString(fmt.Sprintf("| %s | %s:%d | %s | %s |\n", name, t.Host, port, roles, approve))
	}

	// Services summary
	b.WriteString("\n")
	if s.proxyEngine != nil {
		services := s.proxyEngine.ListServices()
		b.WriteString(fmt.Sprintf("## HTTP Proxy Services (%d available)\n\n", len(services)))
		b.WriteString("You can make authenticated HTTP requests to these services. Credentials are injected automatically -- you never see tokens or passwords.\n\n")
		b.WriteString("| Service | URL | Auth |\n")
		b.WriteString("|---------|-----|------|\n")
		for _, svc := range services {
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", svc.Name, svc.URLPrefix, svc.AuthType))
		}
	}

	// Tools summary
	b.WriteString("\n## Available Tools (8)\n\n")
	b.WriteString("| Tool | Purpose |\n")
	b.WriteString("|------|---------|\n")
	b.WriteString("| `list_targets` | Discover SSH targets and allowed roles |\n")
	b.WriteString("| `exec` | Run a command on a target (one-shot or session) |\n")
	b.WriteString("| `session_create` | Open persistent SSH session (60x faster) |\n")
	b.WriteString("| `session_close` | Close a persistent session |\n")
	b.WriteString("| `list_sessions` | List active SSH sessions |\n")
	b.WriteString("| `list_certs` | List active certificates |\n")
	b.WriteString("| `http_request` | HTTP request via authenticated proxy |\n")
	b.WriteString("| `list_services` | List available proxy services |\n")

	b.WriteString("\n## Quick Start\n\n")
	b.WriteString("1. Use `list_targets` to see what hosts you can access\n")
	b.WriteString("2. Use `exec` to run commands: `{\"target\": \"hostname\", \"role\": \"read\", \"command\": \"uptime\"}`\n")
	b.WriteString("3. For multiple commands, use `session_create` first, then pass `session_id` to `exec`\n")
	b.WriteString("4. Use `list_services` to see HTTP services, then `http_request` to query them\n")

	return b.String()
}

// resourceTargets returns detailed target information.
func (s *MCPServer) resourceTargets() string {
	var b strings.Builder
	cfg := s.broker.policyEngine.Config()

	b.WriteString("# SSH Targets\n\n")
	b.WriteString("These hosts are accessible via ephemeral SSH certificates. The broker generates a keypair, signs it with the CA, connects, runs your command, and returns the result.\n\n")

	names := sortedKeys(cfg.Raw.Targets)
	for _, name := range names {
		t := cfg.Raw.Targets[name]
		approve := "Manual approval required"
		if t.AutoApprove {
			approve = "Auto-approved"
		}
		port := t.Port
		if port == 0 {
			port = 22
		}
		b.WriteString(fmt.Sprintf("## %s\n\n", name))
		b.WriteString(fmt.Sprintf("- **Host:** %s:%d\n", t.Host, port))
		if t.VLAN > 0 {
			b.WriteString(fmt.Sprintf("- **VLAN:** %d\n", t.VLAN))
		}
		b.WriteString(fmt.Sprintf("- **Allowed roles:** %s\n", strings.Join(t.AllowedRoles, ", ")))
		if t.MaxTTL != "" {
			b.WriteString(fmt.Sprintf("- **Max TTL:** %s\n", t.MaxTTL))
		}
		b.WriteString(fmt.Sprintf("- **Approval:** %s\n", approve))
		if t.Description != "" {
			b.WriteString(fmt.Sprintf("- **Description:** %s\n", t.Description))
		}
		if t.ForceCommand != "" {
			b.WriteString(fmt.Sprintf("- **Force command:** `%s`\n", t.ForceCommand))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Usage\n\n")
	b.WriteString("```\n")
	b.WriteString("# One-shot command (~850ms)\n")
	b.WriteString("exec: { target: \"<name>\", role: \"read\", command: \"hostname\" }\n\n")
	b.WriteString("# Persistent session (~14ms per command after first)\n")
	b.WriteString("session_create: { target: \"<name>\", role: \"operator\" }\n")
	b.WriteString("exec: { target: \"<name>\", role: \"operator\", command: \"...\", session_id: \"<id>\" }\n")
	b.WriteString("session_close: { session_id: \"<id>\" }\n")
	b.WriteString("```\n")

	return b.String()
}

// resourceServices returns detailed service information.
func (s *MCPServer) resourceServices() string {
	var b strings.Builder

	b.WriteString("# HTTP Proxy Services\n\n")
	b.WriteString("The broker proxies HTTP requests to these services, automatically injecting stored credentials. You never see tokens, passwords, or API keys -- just make the request and the broker handles authentication.\n\n")

	if s.proxyEngine == nil {
		b.WriteString("No proxy engine configured.\n")
		return b.String()
	}

	services := s.proxyEngine.ListServices()
	if len(services) == 0 {
		b.WriteString("No services configured.\n")
		return b.String()
	}

	for _, svc := range services {
		b.WriteString(fmt.Sprintf("## %s\n\n", svc.Name))
		b.WriteString(fmt.Sprintf("- **URL prefix:** `%s`\n", svc.URLPrefix))
		b.WriteString(fmt.Sprintf("- **Auth type:** %s\n", svc.AuthType))
		if svc.Description != "" {
			b.WriteString(fmt.Sprintf("- **Description:** %s\n", svc.Description))
		}
		if len(svc.AllowedMethods) > 0 {
			b.WriteString(fmt.Sprintf("- **Allowed methods:** %s\n", strings.Join(svc.AllowedMethods, ", ")))
		}
		if len(svc.AllowedPaths) > 0 {
			b.WriteString(fmt.Sprintf("- **Allowed paths:** %s\n", strings.Join(svc.AllowedPaths, ", ")))
		}
		if svc.Timeout > 0 {
			b.WriteString(fmt.Sprintf("- **Timeout:** %ds\n", svc.Timeout))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Usage\n\n")
	b.WriteString("```\n")
	b.WriteString("# List available services\n")
	b.WriteString("list_services: {}\n\n")
	b.WriteString("# Make an authenticated request (URL must start with a service URL prefix)\n")
	b.WriteString("http_request: { url: \"https://api.github.com/user/repos\", method: \"GET\" }\n")
	b.WriteString("```\n")

	return b.String()
}

// resourceRoles returns role definitions.
func (s *MCPServer) resourceRoles() string {
	var b strings.Builder
	cfg := s.broker.policyEngine.Config()

	b.WriteString("# Roles & Permissions\n\n")
	b.WriteString("Roles determine what SSH principal you connect as on each target. Each role maps to a specific user account on the target host with defined capabilities.\n\n")

	b.WriteString("| Role | SSH Principal | Description |\n")
	b.WriteString("|------|--------------|-------------|\n")
	names := sortedKeys(cfg.Raw.Roles)
	for _, name := range names {
		r := cfg.Raw.Roles[name]
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", name, r.Principal, r.Description))
	}

	b.WriteString("\n## Role Details\n\n")
	b.WriteString("### read (agent-read)\n")
	b.WriteString("- Restricted shell (rbash)\n")
	b.WriteString("- No sudo access\n")
	b.WriteString("- Can read files, check status, inspect configurations\n\n")

	b.WriteString("### operator (agent-op)\n")
	b.WriteString("- Full bash shell\n")
	b.WriteString("- Sudo for: systemctl status/restart, docker ps/logs/inspect, journalctl, df, free\n")
	b.WriteString("- Can restart services, check logs, monitor resources\n\n")

	b.WriteString("### admin (agent-admin)\n")
	b.WriteString("- Full bash shell\n")
	b.WriteString("- Sudo for: all operator commands + systemctl start/enable, docker run/exec/pull\n")
	b.WriteString("- Can deploy containers, start services, pull images\n\n")

	b.WriteString("## Role Selection\n\n")
	b.WriteString("Always use the **least privileged role** that gets the job done:\n")
	b.WriteString("- Checking status, reading configs, listing files -> `read`\n")
	b.WriteString("- Restarting services, viewing logs -> `operator`\n")
	b.WriteString("- Deploying new containers, enabling services -> `admin`\n")

	return b.String()
}

// resourceStatus returns the agent's current status.
func (s *MCPServer) resourceStatus(agent *MCPAgent) string {
	var b strings.Builder

	b.WriteString("# Agent Status\n\n")
	b.WriteString(fmt.Sprintf("**Agent:** %s\n", agent.Name))
	b.WriteString(fmt.Sprintf("**Timestamp:** %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	// Active certs count
	total := s.broker.policyEngine.ActiveCertsTotal()
	b.WriteString(fmt.Sprintf("## Active Certificates (%d total)\n\n", total))
	if total == 0 {
		b.WriteString("No active certificates.\n\n")
	} else {
		b.WriteString("Use `list_certs` tool for detailed certificate information.\n\n")
	}

	// Active sessions
	if s.execPool != nil {
		sessions := s.execPool.ListSessions(agent.Name)
		b.WriteString(fmt.Sprintf("## Active SSH Sessions (%d)\n\n", len(sessions)))
		if len(sessions) == 0 {
			b.WriteString("No active sessions. Use `session_create` to open one for faster sequential commands.\n\n")
		} else {
			for _, sess := range sessions {
				if data, err := json.Marshal(sess); err == nil {
					var info struct {
						ID     string `json:"session_id"`
						Target string `json:"target"`
						Role   string `json:"role"`
					}
					if json.Unmarshal(data, &info) == nil && info.ID != "" {
						short := info.ID
						if len(short) > 12 {
							short = short[:12] + "..."
						}
						b.WriteString(fmt.Sprintf("- **%s** -> %s (%s)\n", short, info.Target, info.Role))
					}
				}
			}
			b.WriteString("\n")
		}
	}

	// Recent activity
	if s.broker.activityStore != nil {
		entries := s.broker.activityStore.Query(ActivityQuery{
			Agent: agent.Name,
			Limit: 10,
		})
		b.WriteString(fmt.Sprintf("## Recent Activity (last %d)\n\n", len(entries)))
		if len(entries) == 0 {
			b.WriteString("No recent activity.\n")
		} else {
			b.WriteString("| Time | Type | Target | Details |\n")
			b.WriteString("|------|------|--------|---------|\n")
			for _, e := range entries {
				detail := e.Target
				if e.Service != "" {
					detail = e.Service
				}
				if e.URL != "" {
					// Truncate long URLs
					u := e.URL
					if len(u) > 50 {
						u = u[:50] + "..."
					}
					detail = u
				}
				status := ""
				if e.StatusCode > 0 {
					status = fmt.Sprintf(" [%d]", e.StatusCode)
				}
				b.WriteString(fmt.Sprintf("| %s | %s | %s | %s%s |\n",
					e.Timestamp.Format("15:04:05"), e.Type, detail, e.Method, status))
			}
		}
	}

	return b.String()
}

// resourceTools returns a quick reference for all tools.
func (s *MCPServer) resourceTools() string {
	var b strings.Builder

	b.WriteString("# MCP Tools Reference\n\n")
	b.WriteString("## SSH Operations\n\n")

	b.WriteString("### list_targets\n")
	b.WriteString("List all SSH targets you can access.\n")
	b.WriteString("- **Parameters:** none\n")
	b.WriteString("- **Returns:** Array of targets with host, port, roles, auto-approve\n\n")

	b.WriteString("### exec\n")
	b.WriteString("Execute a command on a target via ephemeral SSH certificate.\n")
	b.WriteString("- **target** (required): Target name from list_targets\n")
	b.WriteString("- **role** (required): Role to use (read, operator, admin)\n")
	b.WriteString("- **command** (required): Shell command to execute\n")
	b.WriteString("- **session_id** (optional): Reuse a persistent session for faster execution\n")
	b.WriteString("- **timeout** (optional): Timeout in seconds (1-300, default 30)\n")
	b.WriteString("- **Returns:** stdout, stderr, exit_code, duration_ms\n\n")

	b.WriteString("### session_create\n")
	b.WriteString("Open a persistent SSH session for faster sequential commands (~14ms vs ~850ms).\n")
	b.WriteString("- **target** (required): Target name\n")
	b.WriteString("- **role** (required): Role to use\n")
	b.WriteString("- **Returns:** session_id (pass to exec)\n")
	b.WriteString("- Sessions auto-close after 5 minutes idle. Max 5 concurrent.\n\n")

	b.WriteString("### session_close\n")
	b.WriteString("Close a persistent SSH session.\n")
	b.WriteString("- **session_id** (required): Session to close\n\n")

	b.WriteString("### list_sessions\n")
	b.WriteString("List your active persistent SSH sessions.\n")
	b.WriteString("- **Parameters:** none\n\n")

	b.WriteString("### list_certs\n")
	b.WriteString("List your active SSH certificates and their remaining TTL.\n")
	b.WriteString("- **Parameters:** none\n\n")

	b.WriteString("## HTTP Proxy Operations\n\n")

	b.WriteString("### http_request\n")
	b.WriteString("Make an HTTP request through the authenticated proxy. Credentials are injected automatically.\n")
	b.WriteString("- **url** (required): Full URL (must match a configured service URL prefix)\n")
	b.WriteString("- **method** (optional): GET, POST, PUT, PATCH, DELETE, HEAD (default GET)\n")
	b.WriteString("- **headers** (optional): Additional request headers (object)\n")
	b.WriteString("- **body** (optional): Request body for POST/PUT/PATCH\n")
	b.WriteString("- **timeout** (optional): Timeout in seconds (1-120, default 30)\n")
	b.WriteString("- **Returns:** status_code, headers, body, service, duration_ms\n\n")

	b.WriteString("### list_services\n")
	b.WriteString("List available HTTP proxy services and their URL prefixes.\n")
	b.WriteString("- **Parameters:** none\n")

	return b.String()
}

// sortedKeys returns map keys in sorted order. Works with any map[string]T.
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
