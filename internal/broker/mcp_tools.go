package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
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

// toolDefinitions returns the MCP tool schemas for all six tools.
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
	VLAN        int      `json:"vlan"`
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
		return errorResult(fmt.Sprintf("target %q is currently disabled", target)), nil
	}

	// Check that the exec pool is available.
	if s.execPool == nil {
		return errorResult("exec subsystem is not available"), nil
	}

	// Execute the command.
	var result *ExecResult
	var err error
	if sessionID != "" {
		result, err = s.execPool.ExecInSession(sessionID, command, timeout)
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

	if err := s.execPool.CloseSession(sessionID); err != nil {
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
