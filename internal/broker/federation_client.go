package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// requestIDCounter is an atomically-incremented counter for JSON-RPC request IDs.
var requestIDCounter atomic.Int64

// --- Response wrapper types for parsing remote MCP server responses ---

// federationJSONRPCResponse is used to parse remote server responses where
// the Result field must be raw JSON for further unmarshalling. The existing
// jsonRPCResponse type uses interface{} for Result, which works for outbound
// responses but not for precise inbound parsing.
type federationJSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// mcpInitResult holds the parsed result of a remote initialize response.
type mcpInitResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	ServerInfo      MCPServerInfo   `json:"serverInfo"`
	Capabilities    json.RawMessage `json:"capabilities"`
}

// mcpToolsListResult holds the parsed result of a remote tools/list response.
type mcpToolsListResult struct {
	Tools []MCPToolDefinition `json:"tools"`
}

// mcpResourcesListRemoteResult holds the parsed result of a remote resources/list response.
type mcpResourcesListRemoteResult struct {
	Resources []MCPResource `json:"resources"`
}

// mcpToolsCallResponse holds the parsed result of a remote tools/call response.
type mcpToolsCallResponse struct {
	Content []MCPToolContent `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

// discoverRemote performs the full MCP handshake with a remote server:
// 1. POST initialize with clientInfo
// 2. POST notifications/initialized
// 3. POST tools/list -> cache tools
// 4. POST resources/list -> cache resources (ignore error if not supported)
func (f *MCPFederator) discoverRemote(state *RemoteMCPState) error {
	state.mu.Lock()
	state.Status = RemoteStatusInitializing
	state.StatusMessage = "performing MCP handshake"
	state.mu.Unlock()

	// 1. Send initialize request.
	initParams := map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]string{
			"name":    "clauth-federator",
			"version": "1.0.0",
		},
	}

	resp, err := f.sendJSONRPC(state, "initialize", initParams)
	if err != nil {
		f.markError(state, fmt.Sprintf("initialize failed: %v", err))
		return fmt.Errorf("initialize %s: %w", state.Config.Name, err)
	}

	// Parse initialize result.
	var initResult mcpInitResult
	if resp.Result != nil {
		if err := json.Unmarshal(resp.Result, &initResult); err != nil {
			f.markError(state, fmt.Sprintf("parse initialize result: %v", err))
			return fmt.Errorf("parse initialize result from %s: %w", state.Config.Name, err)
		}
	}

	state.mu.Lock()
	state.ProtocolVersion = initResult.ProtocolVersion
	state.ServerInfo = initResult.ServerInfo
	state.mu.Unlock()

	// 2. Send notifications/initialized (fire-and-forget, no response expected).
	_, _ = f.sendJSONRPC(state, "notifications/initialized", nil)

	// 3. Send tools/list and cache tools.
	toolsResp, err := f.sendJSONRPC(state, "tools/list", nil)
	if err != nil {
		f.markError(state, fmt.Sprintf("tools/list failed: %v", err))
		return fmt.Errorf("tools/list on %s: %w", state.Config.Name, err)
	}

	var toolsResult mcpToolsListResult
	if toolsResp.Result != nil {
		if err := json.Unmarshal(toolsResp.Result, &toolsResult); err != nil {
			f.markError(state, fmt.Sprintf("parse tools/list result: %v", err))
			return fmt.Errorf("parse tools/list from %s: %w", state.Config.Name, err)
		}
	}

	// 4. Send resources/list and cache resources (optional, not all servers support it).
	var resourcesList []MCPResource
	resourcesResp, err := f.sendJSONRPC(state, "resources/list", nil)
	if err == nil && resourcesResp.Result != nil {
		var resourcesResult mcpResourcesListRemoteResult
		if parseErr := json.Unmarshal(resourcesResp.Result, &resourcesResult); parseErr == nil {
			resourcesList = resourcesResult.Resources
		}
	}
	// If resources/list fails or parsing fails, we just leave the list empty.

	// Update state to connected with discovered tools and resources.
	state.mu.Lock()
	state.Tools = toolsResult.Tools
	if state.Tools == nil {
		state.Tools = []MCPToolDefinition{}
	}
	state.Resources = resourcesList
	if state.Resources == nil {
		state.Resources = []MCPResource{}
	}
	state.Status = RemoteStatusConnected
	state.StatusMessage = "connected"
	state.LastRefresh = time.Now()
	state.ErrorCount = 0
	state.mu.Unlock()

	log.Printf("[federation] discovered %s: %d tools, %d resources (server: %s %s, protocol: %s)",
		state.Config.Name,
		len(toolsResult.Tools),
		len(resourcesList),
		initResult.ServerInfo.Name,
		initResult.ServerInfo.Version,
		initResult.ProtocolVersion,
	)

	return nil
}

// callRemoteTool forwards a tools/call request to a remote MCP server.
// Returns the content array, an isError flag, and any transport/protocol error.
func (f *MCPFederator) callRemoteTool(state *RemoteMCPState, toolName string, arguments json.RawMessage, timeout int) ([]MCPToolContent, bool, error) {
	// Build tools/call params.
	params := map[string]interface{}{
		"name": toolName,
	}
	if arguments != nil {
		var args interface{}
		if err := json.Unmarshal(arguments, &args); err == nil {
			params["arguments"] = args
		} else {
			// If the arguments can't be parsed, pass them as-is string.
			params["arguments"] = map[string]interface{}{}
		}
	}

	// Apply timeout override if specified.
	var resp *federationJSONRPCResponse
	var err error

	if timeout > 0 {
		// Temporarily adjust the client timeout for this call.
		originalClient := state.httpClient
		overrideClient := *originalClient
		overrideClient.Timeout = time.Duration(timeout) * time.Second
		state.mu.Lock()
		state.httpClient = &overrideClient
		state.mu.Unlock()
		resp, err = f.sendJSONRPC(state, "tools/call", params)
		state.mu.Lock()
		state.httpClient = originalClient
		state.mu.Unlock()
	} else {
		resp, err = f.sendJSONRPC(state, "tools/call", params)
	}

	if err != nil {
		state.mu.Lock()
		state.ErrorCount++
		state.LastError = time.Now()
		state.LastErrorMsg = err.Error()
		state.mu.Unlock()
		return nil, false, fmt.Errorf("tools/call on %s: %w", state.Config.Name, err)
	}

	// Parse the tools/call result.
	var callResult mcpToolsCallResponse
	if resp.Result != nil {
		if err := json.Unmarshal(resp.Result, &callResult); err != nil {
			return nil, false, fmt.Errorf("parse tools/call result from %s: %w", state.Config.Name, err)
		}
	}

	if callResult.Content == nil {
		callResult.Content = []MCPToolContent{}
	}

	return callResult.Content, callResult.IsError, nil
}

// readRemoteResource forwards a resources/read request to a remote MCP server.
func (f *MCPFederator) readRemoteResource(state *RemoteMCPState, uri string) (*MCPResourcesReadResult, error) {
	params := map[string]string{
		"uri": uri,
	}

	resp, err := f.sendJSONRPC(state, "resources/read", params)
	if err != nil {
		state.mu.Lock()
		state.ErrorCount++
		state.LastError = time.Now()
		state.LastErrorMsg = err.Error()
		state.mu.Unlock()
		return nil, fmt.Errorf("resources/read on %s: %w", state.Config.Name, err)
	}

	// Parse the resources/read result.
	var readResult MCPResourcesReadResult
	if resp.Result != nil {
		if err := json.Unmarshal(resp.Result, &readResult); err != nil {
			return nil, fmt.Errorf("parse resources/read result from %s: %w", state.Config.Name, err)
		}
	}

	return &readResult, nil
}

// sendJSONRPC sends a JSON-RPC 2.0 request to a remote MCP server and returns
// the parsed response. It handles auth injection, request ID generation, and
// response size limiting.
func (f *MCPFederator) sendJSONRPC(state *RemoteMCPState, method string, params interface{}) (*federationJSONRPCResponse, error) {
	// Generate a unique request ID.
	id := requestIDCounter.Add(1)

	// Build the JSON-RPC request.
	rpcReq := struct {
		JSONRPC string      `json:"jsonrpc"`
		ID      int64       `json:"id"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params,omitempty"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	state.mu.RLock()
	cfg := state.Config
	client := state.httpClient
	state.mu.RUnlock()

	// Create the HTTP request.
	httpReq, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	// Inject authentication credentials.
	f.injectAuth(httpReq, &cfg)

	// Add any extra static headers from config.
	for k, v := range cfg.Headers {
		httpReq.Header.Set(k, v)
	}

	// Execute the request.
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request to %s: %w", cfg.URL, err)
	}
	defer httpResp.Body.Close()

	// Read response body with size cap.
	maxBytes := int64(cfg.MaxResponseKB) * 1024
	if maxBytes <= 0 {
		maxBytes = int64(federationDefaultMaxResponseKB) * 1024
	}
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxBytes))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", cfg.URL, err)
	}

	// Check HTTP status.
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		// For notifications (204 No Content), return a synthetic empty response.
		if httpResp.StatusCode == http.StatusNoContent {
			return &federationJSONRPCResponse{
				JSONRPC: "2.0",
			}, nil
		}
		return nil, fmt.Errorf("http %d from %s: %s", httpResp.StatusCode, cfg.URL, truncateBytes(respBody, 200))
	}

	// Handle empty body (e.g., for notifications).
	if len(respBody) == 0 {
		return &federationJSONRPCResponse{
			JSONRPC: "2.0",
		}, nil
	}

	// Parse the JSON-RPC response.
	var rpcResp federationJSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse json-rpc response from %s: %w (body: %s)",
			cfg.URL, err, truncateBytes(respBody, 200))
	}

	// Check for JSON-RPC error.
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("json-rpc error from %s: [%d] %s",
			cfg.URL, rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return &rpcResp, nil
}

// injectAuth adds authentication to an HTTP request based on the remote config.
// Follows the same pattern as proxy.go's injectCredentials.
func (f *MCPFederator) injectAuth(req *http.Request, cfg *RemoteMCPConfig) {
	switch cfg.AuthType {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+cfg.Credential)
	case "basic":
		encoded := base64.StdEncoding.EncodeToString(
			[]byte(cfg.Username + ":" + cfg.Credential),
		)
		req.Header.Set("Authorization", "Basic "+encoded)
	case "header":
		header := cfg.TokenHeader
		if header == "" {
			header = "Authorization"
		}
		value := cfg.Credential
		if cfg.TokenPrefix != "" {
			value = cfg.TokenPrefix + cfg.Credential
		}
		req.Header.Set(header, value)
	case "query":
		paramName := cfg.TokenHeader
		if paramName == "" {
			paramName = "token"
		}
		q := req.URL.Query()
		q.Set(paramName, cfg.Credential)
		req.URL.RawQuery = q.Encode()
	case "none":
		// No credentials injected.
	}
}

// markError records an error on a remote state, incrementing the consecutive
// error count and updating status fields.
func (f *MCPFederator) markError(state *RemoteMCPState, msg string) {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.Status = RemoteStatusError
	state.StatusMessage = msg
	state.ErrorCount++
	state.LastError = time.Now()
	state.LastErrorMsg = msg
	state.LastRefresh = time.Now() // count failed attempts for backoff timing
}

// truncateBytes returns a string representation of the byte slice, truncated
// to maxLen with an ellipsis if necessary.
func truncateBytes(b []byte, maxLen int) string {
	if len(b) <= maxLen {
		return string(b)
	}
	if maxLen <= 3 {
		return string(b[:maxLen])
	}
	return string(b[:maxLen-3]) + "..."
}
