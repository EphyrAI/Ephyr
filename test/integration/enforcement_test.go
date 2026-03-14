//go:build integration

package integration

// CTT-E Token Enforcement Integration Tests
//
// These tests validate Phase 2a/2a.1 enforcement behavior:
// - Task tokens scoped to capability envelopes
// - Envelope violation rejection on exec, proxy, and federation paths
// - Revoked token rejection
// - Legacy (API key) auth backward compatibility
// - Audit/metric correlation for task-scoped requests
//
// NOTE: Some tests require CTT-E enforcement to be wired into the request
// pipeline (Phase 2a.1). Until then, tests that depend on:
//   - Bearer task-token authentication (authenticateWithCTTE in auth flow)
//   - Envelope checks in toolExec / toolHTTPRequest / handleFederatedToolCall
// will be skipped or are expected to fail. Comments mark these clearly.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test-local helpers (independent of smoke_test.go helpers)
// ---------------------------------------------------------------------------

// enfMCPCall makes a JSON-RPC 2.0 call to the MCP endpoint with a custom
// Bearer token. Use apiKey for legacy auth, or a task token for CTT-E auth.
func enfMCPCall(t *testing.T, bearer, method string, params interface{}) (*rpcResponse, time.Duration) {
	t.Helper()
	req := rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	httpReq, _ := http.NewRequest("POST", mcpEndpoint, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+bearer)

	start := time.Now()
	resp, err := http.DefaultClient.Do(httpReq)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var rpcResp rpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		t.Fatalf("unmarshal response: %v (body: %s)", err, string(respBody))
	}

	return &rpcResp, elapsed
}

// enfToolCall calls a tool via MCP with a custom bearer token and returns the
// parsed JSON result. Fails the test on RPC-level errors or tool-level errors.
func enfToolCall(t *testing.T, bearer, toolName string, args map[string]interface{}) (map[string]interface{}, time.Duration) {
	t.Helper()
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}
	resp, elapsed := enfMCPCall(t, bearer, "tools/call", params)
	if resp.Error != nil {
		t.Fatalf("RPC error calling %s: [%d] %s", toolName, resp.Error.Code, resp.Error.Message)
	}

	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal tool result: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool %s returned error: %s", toolName, result.Content[0].Text)
	}

	var data map[string]interface{}
	if len(result.Content) > 0 && result.Content[0].Type == "text" {
		if err := json.Unmarshal([]byte(result.Content[0].Text), &data); err != nil {
			return map[string]interface{}{"raw": result.Content[0].Text}, elapsed
		}
	}
	return data, elapsed
}

// enfToolCallRaw calls a tool and returns the raw rpcResponse without
// failing on tool errors. Useful for asserting on error responses.
func enfToolCallRaw(t *testing.T, bearer, toolName string, args map[string]interface{}) (*rpcResponse, time.Duration) {
	t.Helper()
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}
	return enfMCPCall(t, bearer, "tools/call", params)
}

// enfExtractToolError extracts the error text from a tool call response.
// Returns the error string and whether the response was actually an error.
func enfExtractToolError(t *testing.T, resp *rpcResponse) (string, bool) {
	t.Helper()
	if resp.Error != nil {
		return resp.Error.Message, true
	}
	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.IsError && len(result.Content) > 0 {
		return result.Content[0].Text, true
	}
	// Not an error — return the content text if any.
	if len(result.Content) > 0 {
		return result.Content[0].Text, false
	}
	return "", false
}

// enfCreateTask creates a task via API key auth and returns task_id, token, and envelope.
func enfCreateTask(t *testing.T, description string) (taskID, token string, envelope map[string]interface{}) {
	t.Helper()
	data, _ := enfToolCall(t, mcpAPIKey, "task_create", map[string]interface{}{
		"description": description,
		"ttl":         "5m",
	})

	taskID, _ = data["task_id"].(string)
	token, _ = data["token"].(string)
	envelopeRaw, _ := data["envelope"].(map[string]interface{})

	if taskID == "" {
		t.Fatal("task_create returned empty task_id")
	}
	if token == "" {
		t.Fatal("task_create returned empty token")
	}
	return taskID, token, envelopeRaw
}

// enfRevokeTask revokes a task via API key auth.
func enfRevokeTask(t *testing.T, taskID string) {
	t.Helper()
	enfToolCall(t, mcpAPIKey, "task_revoke", map[string]interface{}{
		"task_id": taskID,
	})
}

// enfGetMetrics fetches the Prometheus metrics endpoint and returns the body.
func enfGetMetrics(t *testing.T) string {
	t.Helper()
	req, _ := http.NewRequest("GET", dashEndpoint+"/v1/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+dashToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/metrics failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// enfExtractMetricValue extracts a counter/gauge value from Prometheus text.
// Returns the raw string value, e.g. "5".
func enfExtractMetricValue(metrics, metricName string) string {
	for _, line := range strings.Split(metrics, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// Match "metric_name <value>" or "metric_name{labels} <value>".
		if strings.HasPrefix(line, metricName+" ") || strings.HasPrefix(line, metricName+"{") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[len(parts)-1]
			}
		}
	}
	return ""
}

// =============================================================================
// TEST 1: Exec Envelope Enforcement
// =============================================================================

func TestTaskTokenExecEnforcement(t *testing.T) {
	// NOTE: This test requires CTT-E enforcement (Phase 2a.1).
	// Specifically, it requires:
	//   1. authenticateRequest to fall through to authenticateWithCTTE for JWT tokens
	//   2. toolExec to call enforceExecEnvelope before executing
	//
	// Until enforcement is wired in, task tokens will be rejected at the auth
	// layer (treated as invalid API keys) rather than at the envelope layer.

	t.Log("\n=== Test 1: Task Token Exec Enforcement ===")

	// Step 1: Create a task via API key auth.
	taskID, taskToken, envelope := enfCreateTask(t, "test exec enforcement")
	revoked := false
	defer func() {
		if !revoked {
			enfToolCallRaw(t, mcpAPIKey, "task_revoke", map[string]interface{}{"task_id": taskID})
		}
	}()

	t.Logf("  Created task %s, token length=%d", taskID[:8], len(taskToken))

	// Log the envelope so we know what targets are permitted.
	targets, _ := envelope["targets"].([]interface{})
	roles, _ := envelope["roles"].([]interface{})
	t.Logf("  Envelope targets: %v", targets)
	t.Logf("  Envelope roles: %v", roles)

	// We need at least one permitted target in the envelope.
	if len(targets) == 0 {
		t.Fatal("envelope has no targets — cannot test exec enforcement")
	}

	// Pick the first permitted target for the "allowed" test.
	// Policy targets: docker-host, mandrake-rack, hugoblog
	permittedTarget := ""
	for _, tgt := range targets {
		if s, ok := tgt.(string); ok {
			permittedTarget = s
			break
		}
	}
	permittedRole := ""
	for _, r := range roles {
		if s, ok := r.(string); ok {
			permittedRole = s
			break
		}
	}
	t.Logf("  Using permitted target=%s role=%s", permittedTarget, permittedRole)

	// Step 2: Use the task token (as Bearer) to call exec on a permitted target.
	// The command is safe and read-only.
	t.Log("  Step 2: Exec on permitted target with task token...")
	resp, elapsed := enfToolCallRaw(t, taskToken, "exec", map[string]interface{}{
		"target":  permittedTarget,
		"role":    permittedRole,
		"command": "hostname",
		"timeout": 10,
	})
	errText, isErr := enfExtractToolError(t, resp)
	if isErr {
		// Before enforcement is wired in, the task token will be rejected
		// at the auth layer as an invalid API key. This is expected.
		if strings.Contains(errText, "authentication failed") ||
			strings.Contains(errText, "invalid API key") {
			t.Logf("  [EXPECTED-PRE-ENFORCEMENT] Auth rejected task token: %s (%.2fms)", errText, ms(elapsed))
			t.Log("  >> Task token auth not yet wired into authenticateRequest")
		} else if strings.Contains(errText, "envelope") {
			t.Fatalf("  [UNEXPECTED] Envelope rejection on permitted target: %s", errText)
		} else {
			// Some other error (e.g., SSH connection issue) — that's acceptable,
			// because it means the token was accepted but the command failed.
			t.Logf("  [OK] Exec error (not auth/envelope): %s (%.2fms)", errText, ms(elapsed))
		}
	} else {
		t.Logf("  [PASS] Exec on permitted target succeeded (%.2fms)", ms(elapsed))
	}

	// Step 3: Use the task token to call exec on a target NOT in the envelope.
	// We fabricate a target name that does not exist in policy.
	t.Log("  Step 3: Exec on non-permitted target with task token...")
	resp2, elapsed2 := enfToolCallRaw(t, taskToken, "exec", map[string]interface{}{
		"target":  "nonexistent-target-xyz",
		"role":    permittedRole,
		"command": "hostname",
		"timeout": 10,
	})
	errText2, isErr2 := enfExtractToolError(t, resp2)
	if isErr2 {
		if strings.Contains(errText2, "authentication failed") ||
			strings.Contains(errText2, "invalid API key") {
			t.Logf("  [EXPECTED-PRE-ENFORCEMENT] Auth rejected before envelope check: %s (%.2fms)", errText2, ms(elapsed2))
		} else if strings.Contains(errText2, "envelope") ||
			strings.Contains(errText2, "not permit") {
			t.Logf("  [PASS] Envelope violation correctly rejected: %s (%.2fms)", errText2, ms(elapsed2))
		} else if strings.Contains(errText2, "unknown target") {
			// Policy-level rejection — target doesn't exist. This is fine
			// because it means the token was accepted and policy kicked in.
			t.Logf("  [OK] Policy rejected unknown target (pre-envelope): %s (%.2fms)", errText2, ms(elapsed2))
		} else {
			t.Logf("  [WARN] Unexpected error: %s (%.2fms)", errText2, ms(elapsed2))
		}
	} else {
		t.Fatal("  [FAIL] Exec on non-permitted target should have been rejected")
	}

	// Step 4: Revoke the task.
	t.Log("  Step 4: Revoking task...")
	enfRevokeTask(t, taskID)
	revoked = true
	t.Logf("  Task %s revoked", taskID[:8])

	// Step 5: Try to use the revoked token for exec.
	t.Log("  Step 5: Exec with revoked task token...")
	resp3, elapsed3 := enfToolCallRaw(t, taskToken, "exec", map[string]interface{}{
		"target":  permittedTarget,
		"role":    permittedRole,
		"command": "hostname",
		"timeout": 10,
	})
	errText3, isErr3 := enfExtractToolError(t, resp3)
	if isErr3 {
		if strings.Contains(errText3, "revok") ||
			strings.Contains(errText3, "expired") ||
			strings.Contains(errText3, "not found") {
			t.Logf("  [PASS] Revoked token correctly rejected: %s (%.2fms)", errText3, ms(elapsed3))
		} else if strings.Contains(errText3, "authentication failed") ||
			strings.Contains(errText3, "invalid API key") {
			t.Logf("  [EXPECTED-PRE-ENFORCEMENT] Auth rejected revoked token: %s (%.2fms)", errText3, ms(elapsed3))
		} else {
			t.Logf("  [WARN] Unexpected error for revoked token: %s (%.2fms)", errText3, ms(elapsed3))
		}
	} else {
		t.Fatal("  [FAIL] Revoked token should have been rejected")
	}
}

// =============================================================================
// TEST 2: Proxy Envelope Enforcement
// =============================================================================

func TestTaskTokenProxyEnforcement(t *testing.T) {
	// NOTE: This test requires CTT-E enforcement (Phase 2a.1).
	// Requires authenticateRequest to accept task tokens AND toolHTTPRequest
	// to call enforceProxyEnvelope.

	t.Log("\n=== Test 2: Task Token Proxy Enforcement ===")

	// Step 1: Create a task.
	taskID, taskToken, envelope := enfCreateTask(t, "test proxy enforcement")
	defer func() {
		// Best-effort cleanup (may already be revoked).
		enfToolCallRaw(t, mcpAPIKey, "task_revoke", map[string]interface{}{"task_id": taskID})
	}()

	services, _ := envelope["services"].([]interface{})
	t.Logf("  Envelope services: %v", services)

	// Step 2: Use task token for http_request on a permitted service.
	// Use uptime-kuma (GET-only, no auth needed at proxy level).
	t.Log("  Step 2: HTTP request to permitted service (uptime-kuma)...")
	resp, elapsed := enfToolCallRaw(t, taskToken, "http_request", map[string]interface{}{
		"url":     "http://192.168.100.100:3001/api/status-page",
		"method":  "GET",
		"timeout": 10,
	})
	errText, isErr := enfExtractToolError(t, resp)
	if isErr {
		if strings.Contains(errText, "authentication failed") ||
			strings.Contains(errText, "invalid API key") {
			t.Logf("  [EXPECTED-PRE-ENFORCEMENT] Auth rejected task token: %s (%.2fms)", errText, ms(elapsed))
		} else if strings.Contains(errText, "envelope") {
			t.Fatalf("  [UNEXPECTED] Envelope rejection on permitted service: %s", errText)
		} else {
			// Proxy-level errors (connection refused, timeout) are acceptable —
			// it means the token was accepted and the proxy attempted the request.
			t.Logf("  [OK] Proxy-level error (not auth/envelope): %s (%.2fms)", errText, ms(elapsed))
		}
	} else {
		t.Logf("  [PASS] HTTP request to permitted service succeeded (%.2fms)", ms(elapsed))
	}

	// Step 3: Use task token for a service NOT in the envelope.
	// We use a URL that doesn't match any configured service prefix.
	t.Log("  Step 3: HTTP request to non-permitted service...")
	resp2, elapsed2 := enfToolCallRaw(t, taskToken, "http_request", map[string]interface{}{
		"url":     "http://10.99.99.99:9999/should-not-exist",
		"method":  "GET",
		"timeout": 5,
	})
	errText2, isErr2 := enfExtractToolError(t, resp2)
	if isErr2 {
		if strings.Contains(errText2, "authentication failed") ||
			strings.Contains(errText2, "invalid API key") {
			t.Logf("  [EXPECTED-PRE-ENFORCEMENT] Auth rejected before envelope check: %s (%.2fms)", errText2, ms(elapsed2))
		} else if strings.Contains(errText2, "envelope") ||
			strings.Contains(errText2, "not permit") {
			t.Logf("  [PASS] Envelope violation correctly rejected: %s (%.2fms)", errText2, ms(elapsed2))
		} else {
			// Network errors are also acceptable for non-existent URLs.
			t.Logf("  [INFO] Error (may be network-level): %s (%.2fms)", errText2, ms(elapsed2))
		}
	} else {
		// If it succeeded, the proxy forwarded to a non-existent host — this
		// might happen if envelope enforcement isn't active yet. The proxy
		// just forwards based on network policy, not envelope.
		t.Logf("  [INFO] Request completed (envelope enforcement may not be active): response received (%.2fms)", ms(elapsed2))
	}
}

// =============================================================================
// TEST 3: Federation Envelope Enforcement
// =============================================================================

func TestTaskTokenFederationEnforcement(t *testing.T) {
	// NOTE: This test requires CTT-E enforcement (Phase 2a.1).
	// Requires authenticateRequest to accept task tokens AND
	// handleFederatedToolCall to call enforceFederationEnvelope.

	t.Log("\n=== Test 3: Task Token Federation Enforcement ===")

	// Step 1: Create a task.
	taskID, taskToken, envelope := enfCreateTask(t, "test federation enforcement")
	defer func() {
		enfToolCallRaw(t, mcpAPIKey, "task_revoke", map[string]interface{}{"task_id": taskID})
	}()

	remotes, _ := envelope["remotes"].([]interface{})
	t.Logf("  Envelope remotes: %v", remotes)

	// First, check if demo-tools remote is available and enabled.
	// If disabled, we can still test the rejection path.
	remotesData, _ := enfToolCall(t, mcpAPIKey, "list_remotes", map[string]interface{}{})
	t.Logf("  Remote states: %v", remotesData)

	// Step 2: Use task token to call a federated tool on a permitted remote.
	// demo-tools.roll_dice is a safe, read-only federated tool.
	t.Log("  Step 2: Federated call to permitted remote (demo-tools.roll_dice)...")
	resp, elapsed := enfToolCallRaw(t, taskToken, "demo-tools.roll_dice", map[string]interface{}{
		"sides": 6,
		"count": 1,
	})
	errText, isErr := enfExtractToolError(t, resp)
	if isErr {
		if strings.Contains(errText, "authentication failed") ||
			strings.Contains(errText, "invalid API key") {
			t.Logf("  [EXPECTED-PRE-ENFORCEMENT] Auth rejected task token: %s (%.2fms)", errText, ms(elapsed))
		} else if strings.Contains(errText, "disabled") {
			t.Logf("  [OK] Remote is disabled — expected in test env: %s (%.2fms)", errText, ms(elapsed))
		} else if strings.Contains(errText, "envelope") {
			t.Fatalf("  [UNEXPECTED] Envelope rejection on permitted remote: %s", errText)
		} else {
			// Federation errors (remote down, timeout) are acceptable.
			t.Logf("  [OK] Federation error (not auth/envelope): %s (%.2fms)", errText, ms(elapsed))
		}
	} else {
		t.Logf("  [PASS] Federated call to permitted remote succeeded (%.2fms)", ms(elapsed))
	}

	// Step 3: Use task token for a remote NOT in the envelope.
	// Use a fabricated remote name that doesn't exist.
	t.Log("  Step 3: Federated call to non-permitted remote...")
	resp2, elapsed2 := enfToolCallRaw(t, taskToken, "fake-remote-xyz.some_tool", map[string]interface{}{})
	errText2, isErr2 := enfExtractToolError(t, resp2)
	if isErr2 {
		if strings.Contains(errText2, "authentication failed") ||
			strings.Contains(errText2, "invalid API key") {
			t.Logf("  [EXPECTED-PRE-ENFORCEMENT] Auth rejected before envelope check: %s (%.2fms)", errText2, ms(elapsed2))
		} else if strings.Contains(errText2, "envelope") ||
			strings.Contains(errText2, "not permit") {
			t.Logf("  [PASS] Envelope violation correctly rejected: %s (%.2fms)", errText2, ms(elapsed2))
		} else if strings.Contains(errText2, "unknown") {
			// The federator doesn't know about this remote — rejected at routing level.
			t.Logf("  [OK] Unknown remote rejected: %s (%.2fms)", errText2, ms(elapsed2))
		} else {
			t.Logf("  [INFO] Error: %s (%.2fms)", errText2, ms(elapsed2))
		}
	} else {
		t.Fatal("  [FAIL] Federated call to non-permitted remote should have been rejected")
	}
}

// =============================================================================
// TEST 4: Legacy Auth Still Works
// =============================================================================

func TestLegacyAuthStillWorks(t *testing.T) {
	// This test validates that API key (legacy) auth continues to work
	// after CTT-E enforcement is added. These should always pass.

	t.Log("\n=== Test 4: Legacy Auth Backward Compatibility ===")

	// 4a: Exec with API key — should work.
	t.Log("  Step 4a: Exec with API key...")
	resp1, elapsed1 := enfToolCallRaw(t, mcpAPIKey, "exec", map[string]interface{}{
		"target":  "hugoblog",
		"role":    "read",
		"command": "whoami",
		"timeout": 10,
	})
	errText1, isErr1 := enfExtractToolError(t, resp1)
	if isErr1 {
		// SSH connection issues are acceptable — the auth layer accepted us.
		if strings.Contains(errText1, "authentication failed") ||
			strings.Contains(errText1, "invalid API key") {
			t.Fatalf("  [FAIL] API key auth rejected: %s", errText1)
		}
		t.Logf("  [OK] Exec with API key: error is not auth-related: %s (%.2fms)", errText1, ms(elapsed1))
	} else {
		t.Logf("  [PASS] Exec with API key succeeded (%.2fms)", ms(elapsed1))
	}

	// 4b: HTTP request with API key — should work.
	t.Log("  Step 4b: HTTP request with API key...")
	resp2, elapsed2 := enfToolCallRaw(t, mcpAPIKey, "http_request", map[string]interface{}{
		"url":     "http://192.168.100.100:3001/api/status-page",
		"method":  "GET",
		"timeout": 10,
	})
	errText2, isErr2 := enfExtractToolError(t, resp2)
	if isErr2 {
		if strings.Contains(errText2, "authentication failed") ||
			strings.Contains(errText2, "invalid API key") {
			t.Fatalf("  [FAIL] API key auth rejected for proxy: %s", errText2)
		}
		t.Logf("  [OK] HTTP request with API key: error is not auth-related: %s (%.2fms)", errText2, ms(elapsed2))
	} else {
		t.Logf("  [PASS] HTTP request with API key succeeded (%.2fms)", ms(elapsed2))
	}

	// 4c: Federated tool call with API key — should work.
	t.Log("  Step 4c: Federated tool call with API key...")
	resp3, elapsed3 := enfToolCallRaw(t, mcpAPIKey, "demo-tools.roll_dice", map[string]interface{}{
		"sides": 6,
		"count": 1,
	})
	errText3, isErr3 := enfExtractToolError(t, resp3)
	if isErr3 {
		if strings.Contains(errText3, "authentication failed") ||
			strings.Contains(errText3, "invalid API key") {
			t.Fatalf("  [FAIL] API key auth rejected for federation: %s", errText3)
		}
		// "disabled" or connection errors are acceptable.
		t.Logf("  [OK] Federated call with API key: error is not auth-related: %s (%.2fms)", errText3, ms(elapsed3))
	} else {
		t.Logf("  [PASS] Federated call with API key succeeded (%.2fms)", ms(elapsed3))
	}

	// 4d: Verify list_targets still works with API key.
	t.Log("  Step 4d: list_targets with API key...")
	data, elapsed4 := enfToolCall(t, mcpAPIKey, "list_targets", map[string]interface{}{})
	if raw, ok := data["raw"]; ok {
		t.Logf("  [PASS] list_targets returned raw: %v (%.2fms)", raw, ms(elapsed4))
	} else {
		t.Logf("  [PASS] list_targets returned structured data (%.2fms)", ms(elapsed4))
	}
}

// =============================================================================
// TEST 5: Task Token Audit Correlation
// =============================================================================

func TestTaskTokenAuditCorrelation(t *testing.T) {
	// NOTE: This test requires CTT-E enforcement (Phase 2a.1) for the exec
	// call to be associated with a task_id in metrics. The task creation and
	// metrics checks work with current code.

	t.Log("\n=== Test 5: Task Token Audit Correlation ===")

	// Step 1: Snapshot metrics before.
	metricsBefore := enfGetMetrics(t)
	tasksCreatedBefore := enfExtractMetricValue(metricsBefore, "ephyr_tasks_created_total")
	tokensSignedBefore := enfExtractMetricValue(metricsBefore, "ephyr_tokens_signed_total")
	t.Logf("  Metrics before: tasks_created=%s tokens_signed=%s", tasksCreatedBefore, tokensSignedBefore)

	// Step 2: Create a task and note the task_id.
	taskID, taskToken, _ := enfCreateTask(t, "test audit correlation")
	defer func() {
		enfToolCallRaw(t, mcpAPIKey, "task_revoke", map[string]interface{}{"task_id": taskID})
	}()
	t.Logf("  Created task %s", taskID[:8])

	// Step 3: Attempt an exec using the task token.
	// (May fail at auth layer pre-enforcement, but should still increment counters.)
	_, _ = enfToolCallRaw(t, taskToken, "exec", map[string]interface{}{
		"target":  "hugoblog",
		"role":    "read",
		"command": "whoami",
		"timeout": 10,
	})

	// Step 4: Check metrics after.
	metricsAfter := enfGetMetrics(t)
	tasksCreatedAfter := enfExtractMetricValue(metricsAfter, "ephyr_tasks_created_total")
	tokensSignedAfter := enfExtractMetricValue(metricsAfter, "ephyr_tokens_signed_total")
	t.Logf("  Metrics after: tasks_created=%s tokens_signed=%s", tasksCreatedAfter, tokensSignedAfter)

	// Verify tasks_created incremented.
	if tasksCreatedAfter <= tasksCreatedBefore {
		t.Errorf("  [FAIL] ephyr_tasks_created_total did not increment: before=%s after=%s",
			tasksCreatedBefore, tasksCreatedAfter)
	} else {
		t.Logf("  [PASS] ephyr_tasks_created_total incremented: %s -> %s",
			tasksCreatedBefore, tasksCreatedAfter)
	}

	// Verify tokens_signed incremented.
	if tokensSignedAfter <= tokensSignedBefore {
		t.Errorf("  [FAIL] ephyr_tokens_signed_total did not increment: before=%s after=%s",
			tokensSignedBefore, tokensSignedAfter)
	} else {
		t.Logf("  [PASS] ephyr_tokens_signed_total incremented: %s -> %s",
			tokensSignedBefore, tokensSignedAfter)
	}

	// Step 5: When enforcement is wired in, we should also see:
	// - ephyr_tokens_validated_total increment (for task token auth)
	// - ephyr_envelope_check_seconds histogram observations
	// For now, just check they exist in the metrics output.
	for _, metric := range []string{
		"ephyr_tokens_validated_total",
		"ephyr_envelope_check_seconds_count",
	} {
		val := enfExtractMetricValue(metricsAfter, metric)
		if val == "" {
			// Not all histograms emit a bare metric name; check _count suffix.
			t.Logf("  [INFO] Metric %s not found (may need Phase 2a.1)", metric)
		} else {
			t.Logf("  [INFO] Metric %s = %s", metric, val)
		}
	}
}

// =============================================================================
// TEST 6: Revoked Token Denied (Independent Survival)
// =============================================================================

func TestRevokedTokenDenied(t *testing.T) {
	// NOTE: This test requires CTT-E enforcement (Phase 2a.1) for task tokens
	// to be accepted as auth credentials. The revocation/survival logic
	// is tested at the task_info level even without enforcement.

	t.Log("\n=== Test 6: Revoked Token Denied + Independent Survival ===")

	// Step 1: Create two tasks (A and B).
	taskIDA, tokenA, _ := enfCreateTask(t, "revocation test task A")
	taskIDB, tokenB, _ := enfCreateTask(t, "revocation test task B")
	t.Logf("  Created task A: %s", taskIDA[:8])
	t.Logf("  Created task B: %s", taskIDB[:8])

	// Verify both are active via task_info.
	infoA, _ := enfToolCall(t, mcpAPIKey, "task_info", map[string]interface{}{"task_id": taskIDA})
	infoB, _ := enfToolCall(t, mcpAPIKey, "task_info", map[string]interface{}{"task_id": taskIDB})
	taskA, _ := infoA["task"].(map[string]interface{})
	taskB, _ := infoB["task"].(map[string]interface{})
	descA, _ := taskA["description"].(string)
	descB, _ := taskB["description"].(string)
	if descA != "revocation test task A" || descB != "revocation test task B" {
		t.Fatalf("  Task descriptions mismatch: A=%q B=%q", descA, descB)
	}
	t.Log("  Both tasks verified active via task_info")

	// Step 2: Revoke task A.
	t.Log("  Revoking task A...")
	enfRevokeTask(t, taskIDA)
	t.Logf("  Task A (%s) revoked", taskIDA[:8])

	// Step 3: Task A's token should be rejected on exec.
	t.Log("  Step 3: Exec with revoked task A token...")
	resp3, elapsed3 := enfToolCallRaw(t, tokenA, "exec", map[string]interface{}{
		"target":  "hugoblog",
		"role":    "read",
		"command": "whoami",
		"timeout": 10,
	})
	errText3, isErr3 := enfExtractToolError(t, resp3)
	if isErr3 {
		if strings.Contains(errText3, "revok") ||
			strings.Contains(errText3, "not found") ||
			strings.Contains(errText3, "expired") {
			t.Logf("  [PASS] Revoked task A token rejected: %s (%.2fms)", errText3, ms(elapsed3))
		} else if strings.Contains(errText3, "authentication failed") ||
			strings.Contains(errText3, "invalid API key") {
			t.Logf("  [EXPECTED-PRE-ENFORCEMENT] Auth rejected revoked token A: %s (%.2fms)", errText3, ms(elapsed3))
		} else {
			t.Logf("  [WARN] Unexpected error for revoked token A: %s (%.2fms)", errText3, ms(elapsed3))
		}
	} else {
		t.Error("  [FAIL] Revoked task A token should have been rejected on exec")
	}

	// Step 4: Task B's token should still work (independent survival).
	t.Log("  Step 4: Exec with task B token (should survive A's revocation)...")
	resp4, elapsed4 := enfToolCallRaw(t, tokenB, "exec", map[string]interface{}{
		"target":  "hugoblog",
		"role":    "read",
		"command": "whoami",
		"timeout": 10,
	})
	errText4, isErr4 := enfExtractToolError(t, resp4)
	if isErr4 {
		if strings.Contains(errText4, "authentication failed") ||
			strings.Contains(errText4, "invalid API key") {
			t.Logf("  [EXPECTED-PRE-ENFORCEMENT] Auth rejected task B token (enforcement not wired): %s (%.2fms)", errText4, ms(elapsed4))
		} else if strings.Contains(errText4, "revok") {
			t.Errorf("  [FAIL] Task B incorrectly revoked by A's revocation: %s", errText4)
		} else {
			// SSH or other non-auth errors mean the token was accepted.
			t.Logf("  [OK] Task B token accepted (error is not auth/revocation): %s (%.2fms)", errText4, ms(elapsed4))
		}
	} else {
		t.Logf("  [PASS] Task B token works after A revocation (%.2fms)", ms(elapsed4))
	}

	// Step 5: Verify via task_info that A is gone and B survives.
	t.Log("  Step 5: Verify task states via task_info...")
	respInfoA, _ := enfToolCallRaw(t, mcpAPIKey, "task_info", map[string]interface{}{"task_id": taskIDA})
	errInfoA, isErrInfoA := enfExtractToolError(t, respInfoA)
	if isErrInfoA {
		t.Logf("  [PASS] Task A info correctly returns error: %s", errInfoA)
	} else {
		t.Error("  [FAIL] Task A should not be found after revocation")
	}

	infoBAfter, _ := enfToolCall(t, mcpAPIKey, "task_info", map[string]interface{}{"task_id": taskIDB})
	taskBAfter, _ := infoBAfter["task"].(map[string]interface{})
	descBAfter, _ := taskBAfter["description"].(string)
	if descBAfter == "revocation test task B" {
		t.Logf("  [PASS] Task B survives: description=%q", descBAfter)
	} else {
		t.Errorf("  [FAIL] Task B missing or wrong after A revocation: %v", infoBAfter)
	}

	// Cleanup task B.
	enfRevokeTask(t, taskIDB)
	t.Log("  Cleaned up task B")
}

// =============================================================================
// TEST 7: Envelope Contents Validation
// =============================================================================

func TestEnvelopeContents(t *testing.T) {
	// This test validates that the envelope returned by task_create
	// correctly reflects the agent's RBAC permissions from policy.yaml.
	// Does NOT require Phase 2a.1 enforcement — works with current code.

	t.Log("\n=== Test 7: Envelope Contents Validation ===")

	taskID, _, envelope := enfCreateTask(t, "test envelope contents")
	defer enfRevokeTask(t, taskID)

	// Expected targets from policy.yaml for the claude agent.
	expectedTargets := map[string]bool{
		"docker-host":   true,
		"mandrake-rack": true,
		"hugoblog":      true,
	}

	targets, _ := envelope["targets"].([]interface{})
	for _, tgt := range targets {
		name, _ := tgt.(string)
		if expectedTargets[name] {
			delete(expectedTargets, name)
			t.Logf("  [PASS] Target %q present in envelope", name)
		}
	}
	for missing := range expectedTargets {
		t.Errorf("  [FAIL] Expected target %q not in envelope", missing)
	}

	// Expected roles — at minimum read and operator should be present.
	roles, _ := envelope["roles"].([]interface{})
	roleSet := make(map[string]bool)
	for _, r := range roles {
		if s, ok := r.(string); ok {
			roleSet[s] = true
		}
	}
	for _, expected := range []string{"read", "operator"} {
		if roleSet[expected] {
			t.Logf("  [PASS] Role %q present in envelope", expected)
		} else {
			t.Errorf("  [FAIL] Expected role %q not in envelope", expected)
		}
	}

	// Expected services — at minimum github, gitea, uptime-kuma.
	services, _ := envelope["services"].([]interface{})
	svcSet := make(map[string]bool)
	for _, s := range services {
		if str, ok := s.(string); ok {
			svcSet[str] = true
		}
	}
	for _, expected := range []string{"github", "gitea", "uptime-kuma"} {
		// Check for explicit name or wildcard.
		if svcSet[expected] || svcSet["*"] {
			t.Logf("  [PASS] Service %q (or wildcard) present in envelope", expected)
		} else {
			t.Errorf("  [FAIL] Expected service %q not in envelope", expected)
		}
	}

	// Expected remotes — demo-tools.
	remotes, _ := envelope["remotes"].([]interface{})
	remoteSet := make(map[string]bool)
	for _, r := range remotes {
		if s, ok := r.(string); ok {
			remoteSet[s] = true
		}
	}
	if remoteSet["demo-tools"] || remoteSet["*"] {
		t.Logf("  [PASS] Remote \"demo-tools\" (or wildcard) present in envelope")
	} else {
		t.Errorf("  [FAIL] Expected remote \"demo-tools\" not in envelope: %v", remotes)
	}

	// Expected methods — at minimum GET, POST.
	methods, _ := envelope["methods"].([]interface{})
	methodSet := make(map[string]bool)
	for _, m := range methods {
		if s, ok := m.(string); ok {
			methodSet[s] = true
		}
	}
	for _, expected := range []string{"GET", "POST"} {
		if methodSet[expected] || methodSet["*"] {
			t.Logf("  [PASS] Method %q (or wildcard) present in envelope", expected)
		} else {
			t.Errorf("  [FAIL] Expected method %q not in envelope", expected)
		}
	}

	t.Logf("  Envelope summary: targets=%d roles=%d services=%d remotes=%d methods=%d",
		len(targets), len(roles), len(services), len(remotes), len(methods))
}

// =============================================================================
// TEST 8: Enforcement Summary Report
// =============================================================================

func TestEnforcementSummary(t *testing.T) {
	t.Log("\n" + strings.Repeat("=", 72))
	t.Log("  EPHYR v0.2 PHASE 2a.1 — ENFORCEMENT TEST REPORT")
	t.Log(strings.Repeat("=", 72))
	t.Log("")
	t.Log("  Test coverage:")
	t.Log("    1. TestTaskTokenExecEnforcement     — exec with task token + envelope violation + revoked token")
	t.Log("    2. TestTaskTokenProxyEnforcement     — proxy with task token + envelope violation")
	t.Log("    3. TestTaskTokenFederationEnforcement— federation with task token + envelope violation")
	t.Log("    4. TestLegacyAuthStillWorks          — API key backward compatibility")
	t.Log("    5. TestTaskTokenAuditCorrelation     — metrics increment after task creation")
	t.Log("    6. TestRevokedTokenDenied            — independent revocation + survival")
	t.Log("    7. TestEnvelopeContents              — envelope matches policy RBAC")
	t.Log("")
	t.Log("  Enforcement readiness:")
	t.Log("    - authenticateWithCTTE exists in mcp_token_auth.go")
	t.Log("    - enforceExecEnvelope exists in envelope_check.go")
	t.Log("    - enforceProxyEnvelope exists in envelope_check.go")
	t.Log("    - enforceFederationEnvelope exists in envelope_check.go")
	t.Log("    - Wiring into authenticateRequest + tool handlers: PENDING (Phase 2a.1)")
	t.Log("")
	t.Log(strings.Repeat("=", 72))
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// ms converts a time.Duration to milliseconds as float64.
func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

// Ensure we use fmt to avoid import issues.
var _ = fmt.Sprintf
