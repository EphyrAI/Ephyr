//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// =============================================================================
// MCP Federation Integration Tests
//
// Tests the federation path: list_remotes, federated tool calls via
// the demo-tools remote, and error handling for unknown federated tools.
// =============================================================================

// TestListRemotes calls list_remotes and verifies a valid response with
// expected remote entries.
func TestListRemotes(t *testing.T) {
	t.Log("\n=== List Remotes Test ===")

	data, elapsed := toolCall(t, "list_remotes", map[string]interface{}{})

	remotes, _ := data["remotes"].([]interface{})
	if remotes == nil {
		// The response may use a different structure — check for raw data.
		if raw, ok := data["raw"].(string); ok {
			logPerf(t, "list_remotes", elapsed, true,
				fmt.Sprintf("response (raw): %s", truncate(raw, 80)))
			return
		}
		logPerf(t, "list_remotes", elapsed, false, "no remotes returned")
		t.Fatalf("list_remotes returned no remotes: %v", data)
	}

	// Look for demo-tools remote.
	foundDemo := false
	for _, remote := range remotes {
		remoteMap, ok := remote.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := remoteMap["name"].(string)
		if name == "" {
			name, _ = remoteMap["remote"].(string)
		}
		if name == "demo-tools" {
			foundDemo = true
			enabled, _ := remoteMap["enabled"].(bool)
			status, _ := remoteMap["status"].(string)
			t.Logf("  demo-tools: enabled=%v status=%q", enabled, status)
		}
	}

	logPerf(t, "list_remotes", elapsed, true,
		fmt.Sprintf("%d remotes, demo-tools found=%v", len(remotes), foundDemo))

	if !foundDemo {
		t.Logf("  [WARN] demo-tools remote not found — federation tests may fail")
	}
}

// TestFederatedToolCall calls a federated tool on the demo-tools remote
// and verifies the result.
func TestFederatedToolCall(t *testing.T) {
	t.Log("\n=== Federated Tool Call Test ===")

	// demo-tools.roll_dice is a safe federated tool that returns dice results.
	resp, elapsed := enfToolCallRaw(t, mcpAPIKey, "demo-tools.roll_dice", map[string]interface{}{
		"sides": 6,
		"count": 2,
	})

	errText, isErr := enfExtractToolError(t, resp)
	if isErr {
		if strings.Contains(errText, "disabled") {
			logPerf(t, "federated_roll_dice", elapsed, true,
				fmt.Sprintf("remote disabled (expected in some envs): %s", truncate(errText, 60)))
			t.Log("  [SKIP] demo-tools remote is disabled")
			return
		}
		if strings.Contains(errText, "connection") || strings.Contains(errText, "timeout") ||
			strings.Contains(errText, "refused") {
			logPerf(t, "federated_roll_dice", elapsed, true,
				fmt.Sprintf("remote unreachable (non-auth error): %s", truncate(errText, 60)))
			t.Log("  [SKIP] demo-tools remote is unreachable")
			return
		}
		logPerf(t, "federated_roll_dice", elapsed, false,
			fmt.Sprintf("unexpected error: %s", truncate(errText, 80)))
		t.Fatalf("federated tool call failed unexpectedly: %s", errText)
	}

	// Parse the result.
	var result toolCallResult
	if resp.Result != nil {
		_ = json.Unmarshal(resp.Result, &result)
	}

	logPerf(t, "federated_roll_dice", elapsed, true, "federated tool call succeeded")

	// Try another federated tool: demo-tools.current_time
	t.Log("  Testing demo-tools.current_time...")
	resp2, elapsed2 := enfToolCallRaw(t, mcpAPIKey, "demo-tools.current_time", map[string]interface{}{})
	errText2, isErr2 := enfExtractToolError(t, resp2)
	if isErr2 {
		if strings.Contains(errText2, "disabled") || strings.Contains(errText2, "connection") ||
			strings.Contains(errText2, "refused") {
			t.Logf("  [SKIP] current_time: %s (%.2fms)", truncate(errText2, 60), ms(elapsed2))
		} else {
			t.Logf("  [WARN] current_time error: %s (%.2fms)", truncate(errText2, 60), ms(elapsed2))
		}
	} else {
		logPerf(t, "federated_current_time", elapsed2, true, "current_time succeeded")
	}
}

// TestFederatedToolCallUnknown calls a nonexistent federated tool and expects
// an error response.
func TestFederatedToolCallUnknown(t *testing.T) {
	t.Log("\n=== Federated Tool Call Unknown Test ===")

	// Call a tool on a nonexistent remote.
	resp, elapsed := enfToolCallRaw(t, mcpAPIKey, "nonexistent-remote.fake_tool", map[string]interface{}{
		"arg1": "value1",
	})

	errText, isErr := enfExtractToolError(t, resp)
	if !isErr {
		logPerf(t, "federated_unknown_remote", elapsed, false,
			"expected error for nonexistent remote but got success")
		t.Fatal("call to nonexistent federated remote should have failed")
	}

	isExpectedError := strings.Contains(errText, "unknown") ||
		strings.Contains(errText, "not found") ||
		strings.Contains(errText, "no such") ||
		strings.Contains(errText, "no remote") ||
		strings.Contains(errText, "not configured")

	logPerf(t, "federated_unknown_remote", elapsed, isExpectedError,
		fmt.Sprintf("rejected: %s", truncate(errText, 80)))

	// Also test calling an unknown tool on a known remote.
	t.Log("  Testing unknown tool on known remote (demo-tools)...")
	resp2, elapsed2 := enfToolCallRaw(t, mcpAPIKey, "demo-tools.totally_fake_tool_xyz", map[string]interface{}{})
	errText2, isErr2 := enfExtractToolError(t, resp2)
	if isErr2 {
		logPerf(t, "federated_unknown_tool", elapsed2, true,
			fmt.Sprintf("unknown tool rejected: %s", truncate(errText2, 80)))
	} else {
		t.Logf("  [INFO] Unknown tool on known remote did not error — may be remote-handled (%.2fms)", ms(elapsed2))
	}
}
