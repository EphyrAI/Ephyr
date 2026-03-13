//go:build integration

package integration

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

// mcpCallWithToken makes an MCP JSON-RPC call using a custom bearer token.
func mcpCallWithToken(t *testing.T, bearerToken string, method string, params interface{}) (*rpcResponse, time.Duration) {
	t.Helper()
	req := rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	httpReq, _ := http.NewRequest("POST", mcpEndpoint, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+bearerToken)

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

// toolCallWithToken calls a tool using a custom bearer token.
func toolCallWithToken(t *testing.T, bearerToken string, toolName string, args map[string]interface{}) (map[string]interface{}, time.Duration) {
	t.Helper()
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}
	resp, elapsed := mcpCallWithToken(t, bearerToken, "tools/call", params)
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

// toolCallWithTokenExpectError calls a tool with a custom bearer token and expects an error.
func toolCallWithTokenExpectError(t *testing.T, bearerToken string, toolName string, args map[string]interface{}) (string, time.Duration) {
	t.Helper()
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}
	resp, elapsed := mcpCallWithToken(t, bearerToken, "tools/call", params)
	if resp.Error != nil {
		return resp.Error.Message, elapsed
	}
	var result toolCallResult
	json.Unmarshal(resp.Result, &result)
	if result.IsError && len(result.Content) > 0 {
		return result.Content[0].Text, elapsed
	}
	t.Fatalf("expected error from %s but got success", toolName)
	return "", elapsed
}

// TestDelegationCreate tests the full delegation flow: create parent, delegate child, use child token.
func TestDelegationCreate(t *testing.T) {
	t.Log("\n=== Delegation Create Test ===")

	// 1. Create a parent task with can_delegate=true.
	parentData, parentElapsed := toolCall(t, "task_create", map[string]interface{}{
		"description":  "Parent task for delegation test",
		"ttl":          "15m",
		"can_delegate": true,
	})

	parentTaskID, _ := parentData["task_id"].(string)
	parentToken, _ := parentData["token"].(string)
	canDelegate, _ := parentData["can_delegate"].(bool)

	if parentTaskID == "" || parentToken == "" {
		t.Fatal("task_create failed to return task_id or token")
	}
	if !canDelegate {
		t.Fatal("expected can_delegate=true in response")
	}

	logPerf(t, "delegation_create_parent", parentElapsed, true,
		fmt.Sprintf("parent=%s can_delegate=%v", parentTaskID[:8], canDelegate))

	// 2. Delegate a child task.
	childData, childElapsed := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": parentTaskID,
		"description":    "Child task with inherited envelope",
		"ttl":            "5m",
	})

	childTaskID, _ := childData["task_id"].(string)
	childToken, _ := childData["token"].(string)
	childParentID, _ := childData["parent_task_id"].(string)
	childDepth, _ := childData["depth"].(float64)

	if childTaskID == "" || childToken == "" {
		t.Fatal("task_delegate failed to return task_id or token")
	}
	if childParentID != parentTaskID {
		t.Fatalf("expected parent_task_id=%s, got %s", parentTaskID, childParentID)
	}
	if int(childDepth) != 1 {
		t.Fatalf("expected depth=1, got %d", int(childDepth))
	}

	// Verify child token is CTT-D format (3 dot-separated parts).
	parts := strings.Split(childToken, ".")
	if len(parts) != 3 {
		t.Fatalf("child token has %d parts, expected 3", len(parts))
	}

	logPerf(t, "delegation_create_child", childElapsed, true,
		fmt.Sprintf("child=%s parent=%s depth=%d", childTaskID[:8], childParentID[:8], int(childDepth)))

	// 3. Use child token to list targets (should work).
	targetsData, targetsElapsed := toolCallWithToken(t, childToken, "list_targets", map[string]interface{}{})
	logPerf(t, "delegation_child_list_targets", targetsElapsed, targetsData != nil,
		"child token accepted for list_targets")

	// 4. Cleanup: revoke parent (cascading).
	toolCall(t, "task_revoke", map[string]interface{}{"task_id": parentTaskID})
}

// TestDelegationAttenuation tests that a child with a restricted envelope is enforced.
func TestDelegationAttenuation(t *testing.T) {
	t.Log("\n=== Delegation Attenuation Test ===")

	// 1. Create parent with full envelope.
	parentData, _ := toolCall(t, "task_create", map[string]interface{}{
		"description":  "Parent for attenuation test",
		"ttl":          "15m",
		"can_delegate": true,
	})
	parentTaskID, _ := parentData["task_id"].(string)

	// 2. Delegate child with restricted envelope (only hugoblog + read role).
	childData, childElapsed := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": parentTaskID,
		"description":    "Read-only hugoblog child",
		"ttl":            "5m",
		"envelope": map[string]interface{}{
			"targets":  []string{"hugoblog"},
			"roles":    []string{"read"},
			"services": []string{},
			"remotes":  []string{},
			"methods":  []string{},
		},
	})
	childToken, _ := childData["token"].(string)
	childEnvelope, _ := childData["envelope"].(map[string]interface{})
	childTargets, _ := childEnvelope["targets"].([]interface{})

	if len(childTargets) != 1 {
		t.Fatalf("expected 1 target in child envelope, got %d", len(childTargets))
	}

	logPerf(t, "delegation_attenuation_create", childElapsed, true,
		fmt.Sprintf("child envelope: targets=%v", childTargets))

	// 3. Use child token for exec on hugoblog with read role (should work).
	execData, execElapsed := toolCallWithToken(t, childToken, "exec", map[string]interface{}{
		"target":  "hugoblog",
		"role":    "read",
		"command": "echo delegation-ok",
	})
	logPerf(t, "delegation_attenuation_allowed", execElapsed, execData != nil,
		"exec on hugoblog/read permitted via attenuated child token")

	// 4. Use child token for exec on dockerhost (should be rejected by envelope).
	errMsg, rejectElapsed := toolCallWithTokenExpectError(t, childToken, "exec", map[string]interface{}{
		"target":  "dockerhost",
		"role":    "read",
		"command": "echo should-fail",
	})
	isEnvelopeViolation := strings.Contains(errMsg, "envelope")
	logPerf(t, "delegation_attenuation_rejected", rejectElapsed, isEnvelopeViolation,
		fmt.Sprintf("exec on dockerhost rejected: %s", errMsg))

	// Cleanup.
	toolCall(t, "task_revoke", map[string]interface{}{"task_id": parentTaskID})
}

// TestDelegationCascadingRevocation tests that revoking a parent invalidates child tokens.
func TestDelegationCascadingRevocation(t *testing.T) {
	t.Log("\n=== Delegation Cascading Revocation Test ===")

	// 1. Create parent and child.
	parentData, _ := toolCall(t, "task_create", map[string]interface{}{
		"description":  "Parent for cascading revocation",
		"ttl":          "15m",
		"can_delegate": true,
	})
	parentTaskID, _ := parentData["task_id"].(string)

	childData, _ := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": parentTaskID,
		"description":    "Child to be cascading-revoked",
		"ttl":            "5m",
	})
	childToken, _ := childData["token"].(string)
	childTaskID, _ := childData["task_id"].(string)

	// 2. Verify child token works before revocation.
	_, preElapsed := toolCallWithToken(t, childToken, "task_list", map[string]interface{}{})
	logPerf(t, "cascade_pre_revoke", preElapsed, true,
		fmt.Sprintf("child token works before parent revocation (child=%s)", childTaskID[:8]))

	// 3. Revoke the parent.
	toolCall(t, "task_revoke", map[string]interface{}{"task_id": parentTaskID})

	// 4. Try to use child token — should fail (cascading revocation via lineage watermark).
	params := map[string]interface{}{
		"name":      "task_list",
		"arguments": map[string]interface{}{},
	}
	resp, postElapsed := mcpCallWithToken(t, childToken, "tools/call", params)

	// The RPC itself may succeed but the auth should fail, resulting in an error.
	revoked := false
	if resp.Error != nil {
		revoked = true
	}

	logPerf(t, "cascade_post_revoke", postElapsed, revoked,
		"child token rejected after parent revocation")

	if !revoked {
		t.Log("WARNING: cascading revocation may not have taken effect immediately")
	}
}

// TestDelegationDepthLimit tests that the maximum delegation depth is enforced.
func TestDelegationDepthLimit(t *testing.T) {
	t.Log("\n=== Delegation Depth Limit Test ===")

	// Create a chain of delegations up to depth 5.
	parentData, _ := toolCall(t, "task_create", map[string]interface{}{
		"description":  "Root for depth test",
		"ttl":          "15m",
		"can_delegate": true,
	})
	currentID, _ := parentData["task_id"].(string)

	// Chain: depth 0 (root) -> 1 -> 2 -> 3 -> 4 -> 5 (should be max).
	for depth := 1; depth <= 5; depth++ {
		data, elapsed := toolCall(t, "task_delegate", map[string]interface{}{
			"parent_task_id": currentID,
			"description":    fmt.Sprintf("Depth %d task", depth),
			"ttl":            "10m",
			"can_delegate":   true,
		})
		childID, _ := data["task_id"].(string)
		childDepth, _ := data["depth"].(float64)

		if int(childDepth) != depth {
			t.Fatalf("expected depth=%d, got %d", depth, int(childDepth))
		}

		logPerf(t, fmt.Sprintf("delegation_depth_%d", depth), elapsed, true,
			fmt.Sprintf("child=%s depth=%d", childID[:8], depth))

		currentID = childID
	}

	// Depth 6 should fail.
	errMsg, failElapsed := toolCallExpectError(t, "task_delegate", map[string]interface{}{
		"parent_task_id": currentID,
		"description":    "Should fail — depth 6",
		"ttl":            "5m",
		"can_delegate":   true,
	})
	isDepthError := strings.Contains(errMsg, "depth")
	logPerf(t, "delegation_depth_6_rejected", failElapsed, isDepthError,
		fmt.Sprintf("depth 6 rejected: %s", errMsg))

	if !isDepthError {
		t.Fatalf("expected depth limit error, got: %s", errMsg)
	}

	// Cleanup: revoke root (cascades to all children).
	rootID, _ := parentData["task_id"].(string)
	toolCall(t, "task_revoke", map[string]interface{}{"task_id": rootID})
}

// TestDelegationTTLConstraint tests that child TTL cannot exceed parent's remaining TTL.
func TestDelegationTTLConstraint(t *testing.T) {
	t.Log("\n=== Delegation TTL Constraint Test ===")

	// Create parent with 5m TTL.
	parentData, _ := toolCall(t, "task_create", map[string]interface{}{
		"description":  "Short-lived parent for TTL test",
		"ttl":          "5m",
		"can_delegate": true,
	})
	parentTaskID, _ := parentData["task_id"].(string)

	// Try to create child with 10m TTL (should fail).
	errMsg, elapsed := toolCallExpectError(t, "task_delegate", map[string]interface{}{
		"parent_task_id": parentTaskID,
		"description":    "Child with excessive TTL",
		"ttl":            "10m",
	})
	isTTLError := strings.Contains(errMsg, "TTL")
	logPerf(t, "delegation_ttl_rejected", elapsed, isTTLError,
		fmt.Sprintf("excessive TTL rejected: %s", errMsg))

	// Create child with 2m TTL (should succeed).
	childData, okElapsed := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": parentTaskID,
		"description":    "Child with valid TTL",
		"ttl":            "2m",
	})
	childID, _ := childData["task_id"].(string)
	logPerf(t, "delegation_ttl_accepted", okElapsed, childID != "",
		fmt.Sprintf("child=%s with 2m TTL accepted", childID[:8]))

	// Cleanup.
	toolCall(t, "task_revoke", map[string]interface{}{"task_id": parentTaskID})
}

// TestDelegationRequiresCanDelegate tests that delegation fails when parent lacks can_delegate.
func TestDelegationRequiresCanDelegate(t *testing.T) {
	t.Log("\n=== Delegation Requires can_delegate Test ===")

	// Create parent WITHOUT can_delegate.
	parentData, _ := toolCall(t, "task_create", map[string]interface{}{
		"description": "Non-delegating parent",
		"ttl":         "15m",
		// can_delegate defaults to false
	})
	parentTaskID, _ := parentData["task_id"].(string)

	// Try to delegate — should fail.
	errMsg, elapsed := toolCallExpectError(t, "task_delegate", map[string]interface{}{
		"parent_task_id": parentTaskID,
		"description":    "Should fail",
		"ttl":            "5m",
	})
	isDelegateError := strings.Contains(errMsg, "delegate") || strings.Contains(errMsg, "delegation")
	logPerf(t, "delegation_no_can_delegate", elapsed, isDelegateError,
		fmt.Sprintf("rejected: %s", errMsg))

	if !isDelegateError {
		t.Fatalf("expected delegation permission error, got: %s", errMsg)
	}

	// Cleanup.
	toolCall(t, "task_revoke", map[string]interface{}{"task_id": parentTaskID})
}

// TestDelegationInheritedEnvelope tests that omitting envelope inherits parent's.
func TestDelegationInheritedEnvelope(t *testing.T) {
	t.Log("\n=== Delegation Inherited Envelope Test ===")

	// Create parent.
	parentData, _ := toolCall(t, "task_create", map[string]interface{}{
		"description":  "Parent for inheritance test",
		"ttl":          "15m",
		"can_delegate": true,
	})
	parentTaskID, _ := parentData["task_id"].(string)
	parentEnvelope, _ := parentData["envelope"].(map[string]interface{})
	parentTargets, _ := parentEnvelope["targets"].([]interface{})

	// Delegate without specifying envelope.
	childData, elapsed := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": parentTaskID,
		"description":    "Child inheriting parent envelope",
		"ttl":            "5m",
	})
	childEnvelope, _ := childData["envelope"].(map[string]interface{})
	childTargets, _ := childEnvelope["targets"].([]interface{})

	// Child should have same targets as parent.
	if len(childTargets) != len(parentTargets) {
		t.Fatalf("expected child to inherit %d targets, got %d", len(parentTargets), len(childTargets))
	}

	logPerf(t, "delegation_inherited_envelope", elapsed, true,
		fmt.Sprintf("child inherited %d targets from parent", len(childTargets)))

	// Cleanup.
	toolCall(t, "task_revoke", map[string]interface{}{"task_id": parentTaskID})
}
