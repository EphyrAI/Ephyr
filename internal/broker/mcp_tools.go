package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/EphyrAI/Ephyr/internal/audit"
)

// --- Argument extraction helpers ---

// getStringArg extracts a string value from the untyped arguments map.
func getStringArg(args map[string]interface{}, key string) (string, bool) {
	v, ok := args[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// getBoolArg extracts a boolean value from the untyped arguments map.
// Returns the default value if the key is missing or not a bool.
func getBoolArg(args map[string]interface{}, key string, defaultVal bool) bool {
	v, ok := args[key]
	if !ok {
		return defaultVal
	}
	b, ok := v.(bool)
	if !ok {
		return defaultVal
	}
	return b
}

// getIntArg extracts an integer value from the untyped arguments map.
// JSON numbers arrive as float64, so both float64 and int are handled.
func getIntArg(args map[string]interface{}, key string, defaultVal int) int {
	v, ok := args[key]
	if !ok {
		return defaultVal
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return defaultVal
	}
}

// --- Error / success result helpers ---

// errorResult builds an MCPToolsCallResult indicating a tool-level error.
func errorResult(msg string) *MCPToolsCallResult {
	return &MCPToolsCallResult{
		Content: []MCPToolContent{{Type: "text", Text: msg}},
		IsError: true,
	}
}

// textResult builds a successful MCPToolsCallResult containing a single
// text content block (typically JSON-encoded data).
func textResult(text string) *MCPToolsCallResult {
	return &MCPToolsCallResult{
		Content: []MCPToolContent{{Type: "text", Text: text}},
	}
}

// jsonResult marshals v to JSON and wraps it in a text content block.
func jsonResult(v interface{}) (*MCPToolsCallResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	return textResult(string(data)), nil
}

// --- Tool definitions ---

// toolDefinitions returns the MCP tool schemas for all 16 tools.
func (s *MCPServer) toolDefinitions() []MCPToolDefinition {
	return []MCPToolDefinition{
		{
			Name:        "list_targets",
			Description: "List available SSH targets and their allowed roles",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "exec",
			Description: "Execute a command on a target host via SSH certificate authentication",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]interface{}{
						"type":        "string",
						"description": "Target host name from list_targets",
					},
					"role": map[string]interface{}{
						"type":        "string",
						"description": "Role to use (e.g. \"read\", \"operator\")",
					},
					"command": map[string]interface{}{
						"type":        "string",
						"description": "Shell command to execute",
					},
					"timeout": map[string]interface{}{
						"type":        "integer",
						"description": "Timeout in seconds (default 30, max 300)",
						"default":     30,
						"minimum":     1,
						"maximum":     300,
					},
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Reuse an existing persistent SSH session",
					},
				},
				"required": []string{"target", "role", "command"},
			},
		},
		{
			Name:        "session_create",
			Description: "Create a persistent SSH session for executing multiple commands without reconnecting",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]interface{}{
						"type":        "string",
						"description": "Target host name from list_targets",
					},
					"role": map[string]interface{}{
						"type":        "string",
						"description": "Role to use (e.g. \"read\", \"operator\")",
					},
				},
				"required": []string{"target", "role"},
			},
		},
		{
			Name:        "session_close",
			Description: "Close a persistent SSH session",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Session ID to close",
					},
				},
				"required": []string{"session_id"},
			},
		},
		{
			Name:        "list_sessions",
			Description: "List active persistent SSH sessions",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "list_certs",
			Description: "List active SSH certificates for this agent",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "http_request",
			Description: "Make an HTTP request through the broker's authenticated proxy. Credentials for configured services are injected automatically.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "Full URL to request",
					},
					"method": map[string]interface{}{
						"type":        "string",
						"description": "HTTP method (default GET)",
						"enum":        []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"},
						"default":     "GET",
					},
					"headers": map[string]interface{}{
						"type":        "object",
						"description": "Additional request headers (key-value pairs)",
						"additionalProperties": map[string]interface{}{
							"type": "string",
						},
					},
					"body": map[string]interface{}{
						"type":        "string",
						"description": "Request body (for POST/PUT/PATCH)",
					},
					"timeout": map[string]interface{}{
						"type":        "integer",
						"description": "Timeout in seconds (default 30, max 120)",
						"default":     30,
						"minimum":     1,
						"maximum":     120,
					},
				},
				"required": []string{"url"},
			},
		},
		{
			Name:        "list_services",
			Description: "List configured services available through the HTTP proxy, showing which services have automatic credential injection",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "list_remotes",
			Description: "List federated remote MCP servers, their tools, and connection status",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		// v0.2: Task identity tools.
		{
			Name:        "task_create",
			Description: "Create a new task with scoped identity. Returns a CTT-E token for authenticating subsequent requests.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Human-readable description of the task",
					},
					"ttl": map[string]interface{}{
						"type":        "string",
						"description": "Task TTL as Go duration (default '30m', max '1h')",
						"default":     "30m",
					},
					"can_delegate": map[string]interface{}{
						"type":        "boolean",
						"description": "Whether this task can delegate to child tasks (default false)",
						"default":     false,
					},
					"holder_pub_key": map[string]interface{}{
						"type":        "string",
						"description": "Base64url-encoded Ed25519 public key (32 bytes) for holder binding",
					},
				},
				"required": []string{"description"},
			},
		},
		{
			Name:        "task_delegate",
			Description: "Delegate a child task from an existing parent task with attenuated capabilities. The child task receives a CTT-D token with equal or reduced permissions.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"parent_task_id": map[string]interface{}{
						"type":        "string",
						"description": "ID of the parent task to delegate from (must have can_delegate=true)",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Human-readable description of the child task",
					},
					"ttl": map[string]interface{}{
						"type":        "string",
						"description": "Child task TTL as Go duration (default '10m', must be <= parent's remaining TTL)",
						"default":     "10m",
					},
					"envelope": map[string]interface{}{
						"type":        "object",
						"description": "Attenuated capability envelope (must be subset of parent's). If omitted, inherits parent's envelope.",
						"properties": map[string]interface{}{
							"targets":  map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
							"roles":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
							"services": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
							"remotes":  map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
							"methods":  map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						},
					},
					"can_delegate": map[string]interface{}{
						"type":        "boolean",
						"description": "Whether the child task can further delegate (default false)",
						"default":     false,
					},
				},
				"required": []string{"parent_task_id", "description"},
			},
		},
		{
			Name:        "task_info",
			Description: "Get information about a task including its envelope, lineage, and remaining TTL",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"task_id": map[string]interface{}{
						"type":        "string",
						"description": "Task ID (ULID). If omitted, lists all active tasks for this agent.",
					},
				},
			},
		},
		{
			Name:        "task_revoke",
			Description: "Revoke a task and invalidate all its tokens. Cascading: also invalidates any child tasks.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"task_id": map[string]interface{}{
						"type":        "string",
						"description": "Task ID to revoke",
					},
				},
				"required": []string{"task_id"},
			},
		},
		{
			Name:        "task_list",
			Description: "List active tasks for this agent",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		// v0.3.2: Ephyr Bind tool.
		{
			Name:        "task_bind",
			Description: "Bind a holder public key to a delegated task (Ephyr Bind). Must be called within the bind deadline.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"task_id": map[string]interface{}{
						"type":        "string",
						"description": "The task ID to bind a key to",
					},
					"holder_pub_key": map[string]interface{}{
						"type":        "string",
						"description": "Base64url-encoded Ed25519 public key (32 bytes)",
					},
				},
				"required": []string{"task_id", "holder_pub_key"},
			},
		},
	}
}

// --- Tool dispatch ---

// handleToolCall dispatches a tools/call request to the appropriate handler
// based on the tool name. context.Context is threaded through for
// cancellation and timeout support.
func (s *MCPServer) handleToolCall(ctx context.Context, agent *MCPAgent, toolName string, args map[string]interface{}) (*MCPToolsCallResult, error) {
	switch toolName {
	case "list_targets":
		return s.toolListTargets(ctx, agent)
	case "exec":
		return s.toolExec(ctx, agent, args)
	case "session_create":
		return s.toolSessionCreate(ctx, agent, args)
	case "session_close":
		return s.toolSessionClose(ctx, agent, args)
	case "list_sessions":
		return s.toolListSessions(ctx, agent)
	case "list_certs":
		return s.toolListCerts(ctx, agent)
	case "http_request":
		return s.toolHTTPRequest(ctx, agent, args)
	case "list_services":
		return s.toolListServices(ctx, agent)
	case "list_remotes":
		return s.toolListRemotes(ctx, agent)
	// v0.2: Task identity tool dispatch.
	case "task_create":
		return s.toolTaskCreate(ctx, agent, args)
	case "task_delegate":
		return s.toolTaskDelegate(ctx, agent, args)
	case "task_info":
		return s.toolTaskInfo(ctx, agent, args)
	case "task_revoke":
		return s.toolTaskRevoke(ctx, agent, args)
	case "task_list":
		return s.toolTaskList(ctx, agent, args)
	// v0.3.2: Ephyr Bind tool dispatch.
	case "task_bind":
		return s.toolTaskBind(ctx, agent, args)
	default:
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
}

// --- Tool handlers ---

// mcpTargetInfo is the JSON shape returned by list_targets.
type mcpTargetInfo struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	VLAN        int      `json:"vlan,omitempty"`
	Roles       []string `json:"roles"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
}

// toolListTargets returns the targets this agent may access, filtered by
// the intersection of the agent's roles and each target's allowed_roles.
func (s *MCPServer) toolListTargets(ctx context.Context, agent *MCPAgent) (*MCPToolsCallResult, error) {
	s.broker.policyMu.RLock()
	cfg := s.broker.policyCfg.Raw
	s.broker.policyMu.RUnlock()

	agentRoles := make(map[string]bool, len(agent.Roles))
	for _, r := range agent.Roles {
		agentRoles[r] = true
	}

	var targets []mcpTargetInfo
	for name, t := range cfg.Targets {
		// Compute the intersection of agent roles and target's allowed roles.
		var matchedRoles []string
		for _, r := range t.AllowedRoles {
			if agentRoles[r] {
				matchedRoles = append(matchedRoles, r)
			}
		}
		if len(matchedRoles) == 0 {
			continue // agent has no permitted role on this target
		}

		port := t.Port
		if port == 0 {
			port = 22
		}

		targets = append(targets, mcpTargetInfo{
			Name:        name,
			Host:        t.Host,
			Port:        port,
			VLAN:        t.VLAN,
			Roles:       matchedRoles,
			Description: t.Description,
			Enabled:     s.broker.hostCtl.IsEnabled(name),
		})
	}

	// Return empty array instead of null.
	if targets == nil {
		targets = []mcpTargetInfo{}
	}

	return jsonResult(targets)
}

// toolExec executes a command on a target via SSH certificate authentication.
func (s *MCPServer) toolExec(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	// Extract required arguments.
	target, ok := getStringArg(args, "target")
	if !ok || target == "" {
		return errorResult("missing required argument: target"), nil
	}
	role, ok := getStringArg(args, "role")
	if !ok || role == "" {
		return errorResult("missing required argument: role"), nil
	}
	command, ok := getStringArg(args, "command")
	if !ok || command == "" {
		return errorResult("missing required argument: command"), nil
	}

	// Extract optional arguments.
	timeout := getIntArg(args, "timeout", 30)
	if timeout < 1 {
		timeout = 1
	}
	if timeout > 300 {
		timeout = 300
	}
	sessionID, _ := getStringArg(args, "session_id")

	// Validate: target exists in policy.
	s.broker.policyMu.RLock()
	tgt, targetExists := s.broker.policyCfg.Raw.Targets[target]
	s.broker.policyMu.RUnlock()
	if !targetExists {
		return errorResult(fmt.Sprintf("unknown target: %s", target)), nil
	}

	// RBAC: Check target and role access.
	perms := s.getAgentPerms(agent)
	if !perms.CanAccessTarget(target) {
		return errorResult(fmt.Sprintf("access denied to target %q", target)), nil
	}
	targetRoles := perms.GetTargetRoles(target)
	if targetRoles != nil && len(targetRoles) > 0 {
		roleAllowed := false
		for _, r := range targetRoles {
			if r == role {
				roleAllowed = true
				break
			}
		}
		if !roleAllowed {
			return errorResult(fmt.Sprintf("role %q is not permitted on target %q for this agent", role, target)), nil
		}
	}

	// Validate: role is in agent's allowed roles.
	roleInAgent := false
	for _, r := range agent.Roles {
		if r == role {
			roleInAgent = true
			break
		}
	}
	if !roleInAgent {
		return errorResult(fmt.Sprintf("role %q is not in your allowed roles", role)), nil
	}

	// Validate: role is in target's allowed_roles.
	roleInTarget := false
	for _, r := range tgt.AllowedRoles {
		if r == role {
			roleInTarget = true
			break
		}
	}
	if !roleInTarget {
		return errorResult(fmt.Sprintf("role %q is not allowed on target %q", role, target)), nil
	}

	// Validate: host is enabled.
	if !s.broker.hostCtl.IsEnabled(target) {
		s.broker.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityWarn,
			EventType: "exec_denied",
			Agent:     agent.Name,
			Details: map[string]string{
				"target": target,
				"role":   role,
				"reason": "target disabled",
			},
		})
		if s.broker.eventHub != nil {
			s.broker.eventHub.Broadcast(Event{
				Type: "exec_denied",
				Data: map[string]interface{}{
					"agent":  agent.Name,
					"target": target,
					"reason": "target disabled",
				},
			})
		}
		return errorResult(fmt.Sprintf("target %q is currently disabled", target)), nil
	}

	// Enforce task envelope if present.
	if err := enforceExecEnvelope(agent, target, role); err != nil {
		if s.broker.metrics != nil {
			s.broker.metrics.TokensRejected.Add(1)
		}
		return errorResult(fmt.Sprintf("envelope violation: %s", err)), nil
	}

	// Command filtering (only runs if target has command_filter: true).
	if tgt.CommandFilter {
		filterResult := CheckCommand(command, tgt.CommandDeny, tgt.CommandAllow, true)
		if s.broker.metrics != nil {
			s.broker.metrics.CommandsFiltered.Add(1)
		}
		if !filterResult.Allowed {
			if s.broker.metrics != nil {
				s.broker.metrics.CommandsDenied.Add(1)
			}

			// Audit log the denial.
			s.broker.auditLog.LogEvent(audit.AuditEvent{
				Severity:  audit.SeverityWarn,
				EventType: "command_denied",
				Agent:     agent.Name,
				Target:    target,
				Role:      role,
				Details: map[string]string{
					"command": truncate(command, 200),
					"pattern": filterResult.Pattern,
					"mode":    filterResult.Mode,
					"reason":  filterResult.Reason,
				},
			})

			// Optional auto-revoke: disable the target for all agents.
			if tgt.AutoRevokeOnDeny {
				if s.broker.metrics != nil {
					s.broker.metrics.AutoRevocations.Add(1)
				}
				s.broker.hostCtl.SetEnabled(target, false)

				s.broker.auditLog.LogEvent(audit.AuditEvent{
					Severity:  audit.SeverityAlert,
					EventType: "auto_revoke",
					Agent:     agent.Name,
					Target:    target,
					Role:      role,
					Details: map[string]string{
						"command": truncate(command, 200),
						"reason":  "Agent attempted prohibited command; target access auto-revoked pending human review",
					},
				})

				if s.broker.eventHub != nil {
					s.broker.eventHub.Broadcast(Event{
						Type: "agent_auto_revoked",
						Data: map[string]interface{}{
							"agent":   agent.Name,
							"target":  target,
							"command": truncate(command, 200),
							"reason":  filterResult.Reason,
						},
					})
				}

				return errorResult(fmt.Sprintf("%s\n\nYour access to %s has been suspended pending human review.", filterResult.Reason, target)), nil
			}

			return errorResult(filterResult.Reason), nil
		}
	}

	// Check that the exec pool is available.
	if s.execPool == nil {
		return errorResult("exec subsystem is not available"), nil
	}

	// Execute the command.
	var result *ExecResult
	var err error
	if sessionID != "" {
		result, err = s.execPool.ExecInSession(agent.Name, sessionID, command, timeout)
	} else {
		result, err = s.execPool.ExecOneShot(agent.Name, target, role, command, timeout)
	}
	if err != nil {
		return errorResult(fmt.Sprintf("exec failed: %s", err.Error())), nil
	}

	// Non-zero exit code is NOT an MCP error -- it is a valid command result.
	return jsonResult(result)
}

// mcpSessionCreateResult is the JSON shape returned by session_create.
type mcpSessionCreateResult struct {
	SessionID string `json:"session_id"`
	Target    string `json:"target"`
	Role      string `json:"role"`
	Message   string `json:"message"`
}

// toolSessionCreate creates a persistent SSH session for the agent.
func (s *MCPServer) toolSessionCreate(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	target, ok := getStringArg(args, "target")
	if !ok || target == "" {
		return errorResult("missing required argument: target"), nil
	}
	role, ok := getStringArg(args, "role")
	if !ok || role == "" {
		return errorResult("missing required argument: role"), nil
	}

	// Validate: target exists in policy.
	s.broker.policyMu.RLock()
	tgt, targetExists := s.broker.policyCfg.Raw.Targets[target]
	s.broker.policyMu.RUnlock()
	if !targetExists {
		return errorResult(fmt.Sprintf("unknown target: %s", target)), nil
	}

	// RBAC: Check target and role access.
	perms := s.getAgentPerms(agent)
	if !perms.CanAccessTarget(target) {
		return errorResult(fmt.Sprintf("access denied to target %q", target)), nil
	}
	targetRoles := perms.GetTargetRoles(target)
	if targetRoles != nil && len(targetRoles) > 0 {
		roleAllowed := false
		for _, r := range targetRoles {
			if r == role {
				roleAllowed = true
				break
			}
		}
		if !roleAllowed {
			return errorResult(fmt.Sprintf("role %q is not permitted on target %q for this agent", role, target)), nil
		}
	}

	// Validate: role is in agent's allowed roles.
	roleInAgent := false
	for _, r := range agent.Roles {
		if r == role {
			roleInAgent = true
			break
		}
	}
	if !roleInAgent {
		return errorResult(fmt.Sprintf("role %q is not in your allowed roles", role)), nil
	}

	// Validate: role is in target's allowed_roles.
	roleInTarget := false
	for _, r := range tgt.AllowedRoles {
		if r == role {
			roleInTarget = true
			break
		}
	}
	if !roleInTarget {
		return errorResult(fmt.Sprintf("role %q is not allowed on target %q", role, target)), nil
	}

	// Validate: host is enabled.
	if !s.broker.hostCtl.IsEnabled(target) {
		s.broker.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityWarn,
			EventType: "session_denied",
			Agent:     agent.Name,
			Details: map[string]string{
				"target": target,
				"role":   role,
				"reason": "target disabled",
			},
		})
		if s.broker.eventHub != nil {
			s.broker.eventHub.Broadcast(Event{
				Type: "session_denied",
				Data: map[string]interface{}{
					"agent":  agent.Name,
					"target": target,
					"reason": "target disabled",
				},
			})
		}
		return errorResult(fmt.Sprintf("target %q is currently disabled", target)), nil
	}

	if s.execPool == nil {
		return errorResult("exec subsystem is not available"), nil
	}

	session, err := s.execPool.CreateSession(agent.Name, target, role)
	if err != nil {
		return errorResult(fmt.Sprintf("session creation failed: %s", err.Error())), nil
	}

	return jsonResult(mcpSessionCreateResult{
		SessionID: session.ID,
		Target:    target,
		Role:      role,
		Message:   fmt.Sprintf("Persistent SSH session created for %s on %s (role: %s)", agent.Name, target, role),
	})
}

// toolSessionClose closes a persistent SSH session.
func (s *MCPServer) toolSessionClose(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	sessionID, ok := getStringArg(args, "session_id")
	if !ok || sessionID == "" {
		return errorResult("missing required argument: session_id"), nil
	}

	if s.execPool == nil {
		return errorResult("exec subsystem is not available"), nil
	}

	if err := s.execPool.CloseSession(agent.Name, sessionID); err != nil {
		return errorResult(fmt.Sprintf("failed to close session: %s", err.Error())), nil
	}

	return jsonResult(map[string]string{
		"session_id": sessionID,
		"message":    "Session closed successfully",
	})
}

// toolListSessions returns all active persistent SSH sessions for this agent.
func (s *MCPServer) toolListSessions(ctx context.Context, agent *MCPAgent) (*MCPToolsCallResult, error) {
	if s.execPool == nil {
		return errorResult("exec subsystem is not available"), nil
	}

	sessions := s.execPool.ListSessions(agent.Name)

	// Return empty array instead of null.
	if sessions == nil {
		sessions = []*ExecSessionInfo{}
	}

	return jsonResult(sessions)
}

// mcpCertInfo is the JSON shape returned by list_certs, excluding the raw
// certificate string for brevity.
type mcpCertInfo struct {
	Serial    string `json:"serial"`
	Target    string `json:"target"`
	Role      string `json:"role"`
	Principal string `json:"principal"`
	ExpiresAt string `json:"expires_at"`
}

// toolListCerts returns active SSH certificates belonging to this agent.
func (s *MCPServer) toolListCerts(ctx context.Context, agent *MCPAgent) (*MCPToolsCallResult, error) {
	allCerts := s.broker.state.ListAllCerts()

	var agentCerts []mcpCertInfo
	for _, cert := range allCerts {
		if cert.AgentName != agent.Name {
			continue
		}
		agentCerts = append(agentCerts, mcpCertInfo{
			Serial:    cert.Serial,
			Target:    cert.Target,
			Role:      cert.Role,
			Principal: cert.Principal,
			ExpiresAt: cert.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	// Return empty array instead of null.
	if agentCerts == nil {
		agentCerts = []mcpCertInfo{}
	}

	return jsonResult(agentCerts)
}


// toolHTTPRequest makes an HTTP request through the broker's authenticated proxy.
func (s *MCPServer) toolHTTPRequest(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	// Extract required args
	rawURL, ok := getStringArg(args, "url")
	if !ok || rawURL == "" {
		return errorResult("missing required argument: url"), nil
	}

	// Extract optional args
	method, _ := getStringArg(args, "method")
	if method == "" {
		method = "GET"
	}
	// Validate method
	validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true}
	method = strings.ToUpper(method)
	if !validMethods[method] {
		return errorResult(fmt.Sprintf("invalid method: %s", method)), nil
	}

	body, _ := getStringArg(args, "body")
	timeout := getIntArg(args, "timeout", 30)
	if timeout < 1 {
		timeout = 1
	}
	if timeout > 120 {
		timeout = 120
	}

	// Extract headers (map[string]interface{} -> map[string]string)
	var headers map[string]string
	if headersRaw, ok := args["headers"]; ok {
		if headersMap, ok := headersRaw.(map[string]interface{}); ok {
			headers = make(map[string]string)
			for k, v := range headersMap {
				if sv, ok := v.(string); ok {
					headers[k] = sv
				}
			}
		}
	}

	// RBAC: Check service access.
	if s.proxyEngine != nil {
		perms := s.getAgentPerms(agent)
		if svc := s.proxyEngine.matchService(rawURL); svc != nil {
			if !perms.CanAccessService(svc.Name, method) {
				return errorResult(fmt.Sprintf("access denied to service %q with method %s", svc.Name, method)), nil
			}
		}
	}

	// Enforce task envelope if present.
	if s.proxyEngine != nil {
		if svc := s.proxyEngine.matchService(rawURL); svc != nil {
			if err := enforceProxyEnvelope(agent, svc.Name, method); err != nil {
				if s.broker.metrics != nil {
					s.broker.metrics.TokensRejected.Add(1)
				}
				return errorResult(fmt.Sprintf("envelope violation: %s", err)), nil
			}
		}
	}

	// Request filtering (only runs if service has request_filter: true).
	if s.proxyEngine != nil {
		if svc := s.proxyEngine.matchService(rawURL); svc != nil && svc.RequestFilter {
			// Extract URL path for pattern matching.
			urlPath := rawURL
			if parsed, parseErr := url.Parse(rawURL); parseErr == nil {
				urlPath = parsed.Path
			}

			// Check URL path against RequestDeny/RequestAllow.
			filterResult := CheckCommand(urlPath, svc.RequestDeny, svc.RequestAllow, true)
			if s.broker.metrics != nil {
				s.broker.metrics.CommandsFiltered.Add(1)
			}
			if !filterResult.Allowed {
				if s.broker.metrics != nil {
					s.broker.metrics.CommandsDenied.Add(1)
				}

				s.broker.auditLog.LogEvent(audit.AuditEvent{
					Severity:  audit.SeverityWarn,
					EventType: "request_denied",
					Agent:     agent.Name,
					Details: map[string]string{
						"url":     truncate(rawURL, 200),
						"method":  method,
						"service": svc.Name,
						"pattern": filterResult.Pattern,
						"mode":    filterResult.Mode,
						"reason":  filterResult.Reason,
					},
				})

				if svc.AutoRevokeOnDeny {
					if s.broker.metrics != nil {
						s.broker.metrics.AutoRevocations.Add(1)
					}
					disabled := false
					svc.Enabled = &disabled

					s.broker.auditLog.LogEvent(audit.AuditEvent{
						Severity:  audit.SeverityAlert,
						EventType: "auto_revoke",
						Agent:     agent.Name,
						Details: map[string]string{
							"service": svc.Name,
							"url":     truncate(rawURL, 200),
							"reason":  "Agent attempted prohibited request; service access auto-revoked pending human review",
						},
					})

					if s.broker.eventHub != nil {
						s.broker.eventHub.Broadcast(Event{
							Type: "agent_auto_revoked",
							Data: map[string]interface{}{
								"agent":   agent.Name,
								"service": svc.Name,
								"url":     truncate(rawURL, 200),
								"reason":  filterResult.Reason,
							},
						})
					}

					return errorResult(fmt.Sprintf("%s\n\nYour access to service %s has been suspended pending human review.", filterResult.Reason, svc.Name)), nil
				}

				return errorResult(filterResult.Reason), nil
			}

			// Check body against BodyDeny patterns (if body is non-empty and patterns exist).
			if len(svc.BodyDeny) > 0 && body != "" {
				bodyResult := CheckCommand(body, svc.BodyDeny, nil, true)
				if s.broker.metrics != nil {
					s.broker.metrics.CommandsFiltered.Add(1)
				}
				if !bodyResult.Allowed {
					if s.broker.metrics != nil {
						s.broker.metrics.CommandsDenied.Add(1)
					}

					s.broker.auditLog.LogEvent(audit.AuditEvent{
						Severity:  audit.SeverityWarn,
						EventType: "request_body_denied",
						Agent:     agent.Name,
						Details: map[string]string{
							"url":     truncate(rawURL, 200),
							"method":  method,
							"service": svc.Name,
							"pattern": bodyResult.Pattern,
							"reason":  bodyResult.Reason,
						},
					})

					if svc.AutoRevokeOnDeny {
						if s.broker.metrics != nil {
							s.broker.metrics.AutoRevocations.Add(1)
						}
						disabled := false
						svc.Enabled = &disabled

						s.broker.auditLog.LogEvent(audit.AuditEvent{
							Severity:  audit.SeverityAlert,
							EventType: "auto_revoke",
							Agent:     agent.Name,
							Details: map[string]string{
								"service": svc.Name,
								"url":     truncate(rawURL, 200),
								"reason":  "Agent sent prohibited request body; service access auto-revoked pending human review",
							},
						})
					}

					return errorResult(fmt.Sprintf("Request body blocked: %s", bodyResult.Reason)), nil
				}
			}
		}
	}

	// Check proxy engine is available
	if s.proxyEngine == nil {
		return errorResult("HTTP proxy is not available"), nil
	}

	// Build proxy request
	proxyReq := &ProxyRequest{
		URL:     rawURL,
		Method:  method,
		Headers: headers,
		Body:    body,
		Timeout: timeout,
	}

	// Execute through proxy
	result, err := s.proxyEngine.Do(agent.Name, proxyReq)
	if err != nil {
		return errorResult(fmt.Sprintf("proxy request failed: %s", err.Error())), nil
	}

	// Record activity (if activity store is available)
	if s.broker.activityStore != nil {
		s.broker.activityStore.Record(&ActivityEntry{
			Timestamp:  time.Now(),
			Agent:      agent.Name,
			Type:       ActivityHTTPProxy,
			URL:        rawURL,
			Method:     method,
			Service:    result.Service,
			StatusCode: result.StatusCode,
			DurationMs: result.DurationMs,
			Success:    result.StatusCode >= 200 && result.StatusCode < 400,
		})
	}

	return jsonResult(result)
}

// toolListServices returns the list of configured proxy services.
func (s *MCPServer) toolListServices(ctx context.Context, agent *MCPAgent) (*MCPToolsCallResult, error) {
	if s.proxyEngine == nil {
		return errorResult("HTTP proxy is not available"), nil
	}

	services := s.proxyEngine.ListServices()

	// Build a simple view for the agent
	type serviceInfo struct {
		Name        string   `json:"name"`
		URLPrefix   string   `json:"url_prefix"`
		Description string   `json:"description"`
		AuthType    string   `json:"auth_type"`
		Methods     []string `json:"allowed_methods,omitempty"`
	}

	var result []serviceInfo
	for _, svc := range services {
		result = append(result, serviceInfo{
			Name:        svc.Name,
			URLPrefix:   svc.URLPrefix,
			Description: svc.Description,
			AuthType:    svc.AuthType,
			Methods:     svc.AllowedMethods,
		})
	}

	if result == nil {
		result = []serviceInfo{}
	}

	return jsonResult(result)
}

// toolListRemotes returns the list of federated remote MCP servers with their
// connection status, tool counts, and descriptions.
func (s *MCPServer) toolListRemotes(ctx context.Context, agent *MCPAgent) (*MCPToolsCallResult, error) {
	if s.federator == nil {
		return errorResult("MCP federation is not configured"), nil
	}

	states := s.federator.ListRemoteStates()
	if len(states) == 0 {
		return textResult("No remote MCP servers configured."), nil
	}

	return jsonResult(states)
}
