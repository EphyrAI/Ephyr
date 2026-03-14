package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ben-spanswick/ephyr/internal/audit"
	macaroonpkg "github.com/ben-spanswick/ephyr/internal/macaroon"
	"github.com/ben-spanswick/ephyr/internal/policy"
	"github.com/ben-spanswick/ephyr/internal/token"
)

// MCPServer wraps the broker and provides MCP protocol handling via
// Streamable HTTP (JSON-RPC 2.0 over POST /mcp).
type MCPServer struct {
	broker      *BrokerServer
	execPool    *ExecSessionPool  // defined in mcp_exec.go, set via SetExecPool
	auth        *MCPAuthenticator // defined in mcp_auth.go
	proxyEngine *ProxyEngine      // defined in proxy.go, set via SetProxyEngine
	federator   *MCPFederator     // defined in federation.go, set via SetFederator
}

// --- JSON-RPC 2.0 types ---

// jsonRPCRequest is a JSON-RPC 2.0 request envelope.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // may be number, string, or null
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// jsonRPCResponse is a JSON-RPC 2.0 response envelope.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// jsonRPCError is the error object within a JSON-RPC 2.0 response.
type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// --- MCP protocol types ---

// MCPInitializeParams holds the client's initialization request.
type MCPInitializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities,omitempty"`
	ClientInfo      MCPClientInfo          `json:"clientInfo,omitempty"`
}

// MCPClientInfo describes the MCP client.
type MCPClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCPInitializeResult is the server's response to an initialize request.
type MCPInitializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    MCPCapabilities `json:"capabilities"`
	ServerInfo      MCPServerInfo   `json:"serverInfo"`
}

// MCPCapabilities advertises what the server supports.
type MCPCapabilities struct {
	Tools     *MCPToolsCapability     `json:"tools,omitempty"`
	Resources *MCPResourcesCapability `json:"resources,omitempty"`
}

// MCPToolsCapability describes tool support details.
type MCPToolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

// MCPServerInfo identifies the MCP server.
type MCPServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCPToolsListResult is the result for tools/list.
type MCPToolsListResult struct {
	Tools []MCPToolDefinition `json:"tools"`
}

// MCPToolsCallParams holds the parameters for a tools/call request.
type MCPToolsCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// MCPToolsCallResult is the result of a tools/call invocation.
type MCPToolsCallResult struct {
	Content []MCPToolContent `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

// MCPToolDefinition describes a single tool exposed via MCP.
type MCPToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// MCPToolContent is a single content block in a tool call result.
type MCPToolContent struct {
	Type string      `json:"type"`           // "text" or "json"
	Text string      `json:"text,omitempty"` // for type "text"
	Data interface{} `json:"data,omitempty"` // for type "json"
}

// MCPAgent represents an authenticated agent making MCP requests.
type MCPAgent struct {
	Name          string
	Roles         []string
	MaxConcurrent int
	AutoApprove   bool
	Perms         *policy.ResolvedAgentPerms
	TaskClaims    *token.TaskClaims      // non-nil when authenticated via CTT-E/CTT-D JWT token
	RawMacaroon   *macaroonpkg.Macaroon  // preserved from auth for delegation (v0.2b)
}

// HasTaskIdentity returns true if this agent authenticated with a task token.
func (a *MCPAgent) HasTaskIdentity() bool {
	return a.TaskClaims != nil
}

// TaskID returns the task ID if present, empty string otherwise.
func (a *MCPAgent) TaskID() string {
	if a.TaskClaims == nil {
		return ""
	}
	return a.TaskClaims.Task.ID
}

// --- Standard MCP / JSON-RPC error codes ---

const (
	mcpErrInvalidRequest = -32600
	mcpErrMethodNotFound = -32601
	mcpErrInvalidParams  = -32602
	mcpErrInternal       = -32603
)

// MCP protocol version this server implements.
const mcpProtocolVersion = "2025-03-26"

// NewMCPServer creates an MCPServer that wraps the given broker and uses
// the provided authenticator for API key validation.
func NewMCPServer(broker *BrokerServer, auth *MCPAuthenticator) *MCPServer {
	return &MCPServer{
		broker: broker,
		auth:   auth,
	}
}

// SetExecPool sets the execution session pool, which is created separately
// and may not be available at MCPServer construction time.
func (s *MCPServer) SetExecPool(pool *ExecSessionPool) {
	s.execPool = pool
}

// SetProxyEngine sets the HTTP proxy engine, which is created separately
// and may not be available at MCPServer construction time.
func (s *MCPServer) SetProxyEngine(engine *ProxyEngine) {
	s.proxyEngine = engine
}

// SetFederator sets the MCP federator, which is created separately
// and may not be available at MCPServer construction time.
func (s *MCPServer) SetFederator(fed *MCPFederator) {
	s.federator = fed
}

// ServeHTTP implements http.Handler. It is the single POST /mcp endpoint
// for Streamable HTTP MCP transport.
func (s *MCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// MCP Streamable HTTP only accepts POST.
	if r.Method != http.MethodPost {
		s.writeJSONRPC(w, nil, nil, &jsonRPCError{
			Code:    mcpErrInvalidRequest,
			Message: "MCP endpoint only accepts POST requests",
		})
		return
	}

	// Authenticate via Bearer token.
	agent, err := s.authenticateRequest(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Error: &jsonRPCError{
				Code:    mcpErrInvalidRequest,
				Message: "authentication failed: " + err.Error(),
			},
		})
		return
	}

	// Read and parse the JSON-RPC request.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		s.writeJSONRPC(w, nil, nil, &jsonRPCError{
			Code:    mcpErrInvalidRequest,
			Message: "failed to read request body",
		})
		return
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeJSONRPC(w, nil, nil, &jsonRPCError{
			Code:    mcpErrInvalidRequest,
			Message: "invalid JSON: " + err.Error(),
		})
		return
	}

	// Validate JSON-RPC version.
	if req.JSONRPC != "2.0" {
		s.writeJSONRPC(w, req.ID, nil, &jsonRPCError{
			Code:    mcpErrInvalidRequest,
			Message: "jsonrpc field must be \"2.0\"",
		})
		return
	}

	// Audit log the MCP request.
	mcpReqEvent := audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "mcp_request",
		Agent:     agent.Name,
		Details: map[string]string{
			"method": req.Method,
		},
	}
	if agent.HasTaskIdentity() {
		mcpReqEvent.TaskID = agent.TaskClaims.Task.ID
		mcpReqEvent.TaskRootID = agent.TaskClaims.Task.RootID
		mcpReqEvent.InitiatedBy = agent.TaskClaims.Task.InitiatedBy
	}
	s.broker.auditLog.LogEvent(mcpReqEvent)

	log.Printf("[mcp] agent=%s method=%s", agent.Name, req.Method)

	// Route to the appropriate method handler.
	ctx := r.Context()
	switch req.Method {
	case "initialize":
		s.handleInitialize(w, req)

	case "notifications/initialized":
		// Client confirmation notification -- no response needed.
		// Return 204 No Content for notifications (no id field).
		if req.ID == nil || string(req.ID) == "null" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// If client mistakenly sends an id, acknowledge it.
		s.writeJSONRPC(w, req.ID, map[string]string{"status": "ok"}, nil)

	case "tools/list":
		s.handleToolsList(w, req)

	case "tools/call":
		s.handleToolsCall(ctx, w, req, agent)

	case "resources/list":
		s.handleResourcesList(w, req)

	case "resources/read":
		s.handleResourcesRead(w, req, agent)

	default:
		s.writeJSONRPC(w, req.ID, nil, &jsonRPCError{
			Code:    mcpErrMethodNotFound,
			Message: fmt.Sprintf("method %q not found", req.Method),
		})
	}
}

// handleInitialize responds to the MCP initialize handshake with server
// capabilities and protocol version.
func (s *MCPServer) handleInitialize(w http.ResponseWriter, req jsonRPCRequest) {
	// Parse client params (optional, for logging).
	var params MCPInitializeParams
	if req.Params != nil {
		_ = json.Unmarshal(req.Params, &params)
	}

	if params.ClientInfo.Name != "" {
		log.Printf("[mcp] client: %s %s (protocol %s)",
			params.ClientInfo.Name, params.ClientInfo.Version, params.ProtocolVersion)
	}

	result := MCPInitializeResult{
		ProtocolVersion: mcpProtocolVersion,
		Capabilities: MCPCapabilities{
			Tools: &MCPToolsCapability{
				ListChanged: s.federator != nil,
			},
			Resources: &MCPResourcesCapability{
				ListChanged: false,
			},
		},
		ServerInfo: MCPServerInfo{
			Name:    "ephyr",
			Version: "1.0.0",
		},
	}

	s.writeJSONRPC(w, req.ID, result, nil)
}

// handleToolsList returns the list of available tool definitions.
func (s *MCPServer) handleToolsList(w http.ResponseWriter, req jsonRPCRequest) {
	tools := s.toolDefinitions()

	// Append federated tools from remote MCP servers.
	if s.federator != nil {
		tools = append(tools, s.federator.FederatedToolDefinitions()...)
	}

	result := MCPToolsListResult{
		Tools: tools,
	}

	s.writeJSONRPC(w, req.ID, result, nil)
}

// handleToolsCall dispatches a tool invocation to the tool handler.
// If the tool supports streaming, it switches the response to SSE format.
func (s *MCPServer) handleToolsCall(ctx context.Context, w http.ResponseWriter, req jsonRPCRequest, agent *MCPAgent) {
	var params MCPToolsCallParams
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.writeJSONRPC(w, req.ID, nil, &jsonRPCError{
				Code:    mcpErrInvalidParams,
				Message: "invalid tool call params: " + err.Error(),
			})
			return
		}
	}

	if params.Name == "" {
		s.writeJSONRPC(w, req.ID, nil, &jsonRPCError{
			Code:    mcpErrInvalidParams,
			Message: "tool name is required",
		})
		return
	}

	log.Printf("[mcp] agent=%s tool=%s", agent.Name, params.Name)

	// Audit log the tool call.
	toolCallEvent := audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "mcp_tool_call",
		Agent:     agent.Name,
		Details: map[string]string{
			"tool": params.Name,
		},
	}
	if agent.HasTaskIdentity() {
		toolCallEvent.TaskID = agent.TaskClaims.Task.ID
		toolCallEvent.TaskRootID = agent.TaskClaims.Task.RootID
		toolCallEvent.InitiatedBy = agent.TaskClaims.Task.InitiatedBy
	}
	s.broker.auditLog.LogEvent(toolCallEvent)

	// Check for federated tool call (remote.toolname pattern).
	if s.federator != nil && s.federator.IsFederatedTool(params.Name) {
		s.handleFederatedToolCall(ctx, w, req, agent, params)
		return
	}

	// Check if this tool supports streaming.
	if s.isStreamingTool(params.Name) {
		s.handleStreamingToolCall(ctx, w, req, agent, params)
		return
	}

	// Synchronous tool call -- dispatch to handleToolCall (defined in mcp_tools.go).
	result, err := s.handleToolCall(ctx, agent, params.Name, params.Arguments)
	if err != nil {
		s.writeJSONRPC(w, req.ID, nil, &jsonRPCError{
			Code:    mcpErrInternal,
			Message: err.Error(),
		})
		return
	}

	s.writeJSONRPC(w, req.ID, result, nil)
}

// handleStreamingToolCall sends the tool call result as SSE events.
func (s *MCPServer) handleStreamingToolCall(ctx context.Context, w http.ResponseWriter, req jsonRPCRequest, agent *MCPAgent, params MCPToolsCallParams) {
	// Set SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback: write a single JSON-RPC error if flushing not supported.
		log.Printf("[mcp] warning: ResponseWriter does not support Flusher for SSE")
		return
	}

	// Execute the tool call (may take time for streaming tools).
	result, err := s.handleToolCall(ctx, agent, params.Name, params.Arguments)

	// Build the JSON-RPC response.
	var resp jsonRPCResponse
	resp.JSONRPC = "2.0"
	resp.ID = req.ID
	if err != nil {
		resp.Error = &jsonRPCError{
			Code:    mcpErrInternal,
			Message: err.Error(),
		}
	} else {
		resp.Result = result
	}

	data, marshalErr := json.Marshal(resp)
	if marshalErr != nil {
		log.Printf("[mcp] failed to marshal SSE response: %v", marshalErr)
		return
	}

	// Write as SSE event.
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

// getAgentPerms returns the resolved RBAC permissions for an agent.
// Falls back to legacy mode (full access) if perms are nil.
func (s *MCPServer) getAgentPerms(agent *MCPAgent) *policy.ResolvedAgentPerms {
	if agent.Perms != nil {
		return agent.Perms
	}
	return &policy.ResolvedAgentPerms{LegacyMode: true, Dashboard: policy.DashboardAdmin}
}

// handleFederatedToolCall forwards a tool call to a remote MCP server via the federator.
func (s *MCPServer) handleFederatedToolCall(ctx context.Context, w http.ResponseWriter, req jsonRPCRequest, agent *MCPAgent, params MCPToolsCallParams) {
	remoteName, toolName, ok := s.federator.ParseFederatedTool(params.Name)
	if !ok {
		s.writeJSONRPC(w, req.ID, errorResult("unknown federated tool: "+params.Name), nil)
		return
	}

	state := s.federator.getState(remoteName)
	if state == nil {
		s.writeJSONRPC(w, req.ID, errorResult("unknown remote: "+remoteName), nil)
		return
	}

	// Block calls to disabled remotes.
	state.mu.RLock()
	remoteEnabled := state.Config.Enabled
	state.mu.RUnlock()
	if !remoteEnabled {
		s.writeJSONRPC(w, req.ID, errorResult("remote "+remoteName+" is disabled"), nil)
		return
	}

	// RBAC: Check if agent has permission to access this remote and tool.
	perms := s.getAgentPerms(agent)
	if !perms.CanAccessRemote(remoteName, toolName) {
		s.writeJSONRPC(w, req.ID, errorResult(fmt.Sprintf("access denied to remote %q tool %q", remoteName, toolName)), nil)
		return
	}

	// Enforce task envelope if present.
	if err := enforceFederationEnvelope(agent, remoteName); err != nil {
		if s.broker.metrics != nil {
			s.broker.metrics.TokensRejected.Add(1)
		}
		s.writeJSONRPC(w, req.ID, errorResult(fmt.Sprintf("envelope violation: %s", err)), nil)
		return
	}

	// Check/issue MCP access grant (unless passthrough mode).
	if s.broker.grantStore != nil {
		grantMode := s.broker.grantStore.Mode
		// Check remote-specific grant mode.
		cfg, cfgOK := s.federator.GetRemote(remoteName)
		if cfgOK && cfg != nil && cfg.GrantMode != "" {
			grantMode = GrantMode(cfg.GrantMode)
		}
		if grantMode == GrantModeTTL {
			existing := s.broker.grantStore.Validate(GrantTypeMCP, agent.Name, remoteName)
			if existing == nil {
				s.broker.grantStore.Issue(GrantTypeMCP, agent.Name, remoteName, 0, map[string]string{
					"remote": remoteName,
					"tool":   toolName,
				})
				s.broker.eventHub.Broadcast(Event{
					Type: "grant_issued",
					Data: map[string]string{
						"type":   "mcp",
						"agent":  agent.Name,
						"target": remoteName,
					},
				})
			}
		}
	}

	// Marshal arguments back to json.RawMessage for the federation client.
	argsJSON, _ := json.Marshal(params.Arguments)

	timeout := 30
	if t, ok := params.Arguments["timeout"]; ok {
		if tf, ok := t.(float64); ok {
			timeout = int(tf)
		}
	}

	content, isError, err := s.federator.callRemoteTool(state, toolName, argsJSON, timeout)
	if err != nil {
		s.writeJSONRPC(w, req.ID, errorResult("federation error: "+err.Error()), nil)
		return
	}

	// Record activity.
	if s.broker.activityStore != nil {
		s.broker.activityStore.Record(&ActivityEntry{
			Timestamp: time.Now(),
			Agent:     agent.Name,
			Type:      ActivityMCPCall,
			Service:   remoteName,
			Target:    toolName,
			Method:    "tools/call",
			Success:   !isError,
		})
	}

	// Audit log.
	fedEvent := audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "mcp_federation",
		Agent:     agent.Name,
		Details: map[string]string{
			"remote": remoteName,
			"tool":   toolName,
		},
	}
	if agent.HasTaskIdentity() {
		fedEvent.TaskID = agent.TaskClaims.Task.ID
		fedEvent.TaskRootID = agent.TaskClaims.Task.RootID
		fedEvent.InitiatedBy = agent.TaskClaims.Task.InitiatedBy
	}
	s.broker.auditLog.LogEvent(fedEvent)

	result := &MCPToolsCallResult{Content: content, IsError: isError}
	s.writeJSONRPC(w, req.ID, result, nil)
}

// isStreamingTool returns true if the named tool should use SSE transport.
// This is a placeholder that can be extended as streaming tools are added.
func (s *MCPServer) isStreamingTool(name string) bool {
	// Tools that produce streaming output (e.g., exec with long-running commands).
	switch name {
	case "exec_stream":
		return true
	default:
		return false
	}
}

// authenticateRequest extracts and validates the Bearer token from the
// Authorization header. Tries macaroon (mac_ prefix) first, then JWT
// (CTT-E/CTT-D), then falls through to API key authentication.
func (s *MCPServer) authenticateRequest(r *http.Request) (*MCPAgent, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("Authorization header must use Bearer scheme")
	}

	bearerToken := authHeader[7:]
	if bearerToken == "" {
		return nil, fmt.Errorf("empty API key")
	}

	// 1. Try macaroon authentication (mac_ prefix).
	if strings.HasPrefix(bearerToken, "mac_") {
		agent, err := s.authenticateWithMacaroon(strings.TrimPrefix(bearerToken, "mac_"))
		if err != nil {
			if s.broker.metrics != nil {
				s.broker.metrics.MacaroonsRejected.Add(1)
			}
			return nil, err
		}
		if s.broker.metrics != nil {
			s.broker.metrics.MacaroonsVerified.Add(1)
		}
		return agent, nil
	}

	// 2. Try CTT-E/CTT-D JWT task token authentication.
	agent, err := s.authenticateWithCTTE(bearerToken)
	if err != nil {
		// CTT-E was presented but invalid — reject with metrics.
		if s.broker.metrics != nil {
			s.broker.metrics.TokensRejected.Add(1)
		}
		return nil, err
	}
	if agent != nil {
		// Successfully authenticated via CTT-E — track metrics.
		if s.broker.metrics != nil {
			s.broker.metrics.TokensValidated.Add(1)
		}
		return agent, nil
	}

	// 3. Fall through to API key authentication.
	return s.auth.Authenticate(bearerToken)
}

// writeJSONRPC writes a JSON-RPC 2.0 response. If both result and rpcErr are nil,
// this writes a successful response with a null result.
func (s *MCPServer) writeJSONRPC(w http.ResponseWriter, id json.RawMessage, result interface{}, rpcErr *jsonRPCError) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
	}

	if rpcErr != nil {
		resp.Error = rpcErr
		// Use appropriate HTTP status for errors without an id (parse/invalid request).
		if id == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	} else {
		resp.Result = result
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

