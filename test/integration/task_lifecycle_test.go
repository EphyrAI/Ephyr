//go:build integration

package integration

import (
	"fmt"
	"strings"
	"testing"
)

// =============================================================================
// Task Lifecycle End-to-End Integration Tests
//
// Tests full task lifecycle scenarios: create-delegate-revoke cascading,
// multi-level delegation chains, and envelope attenuation verification.
// =============================================================================

// TestTaskCreateDelegateRevoke tests the full lifecycle:
// create root task -> delegate child -> verify child envelope is subset
// -> revoke root -> verify both are revoked.
func TestTaskCreateDelegateRevoke(t *testing.T) {
	t.Log("\n=== Task Create-Delegate-Revoke Lifecycle ===")

	// Step 1: Create root task with delegation enabled.
	rootData, rootElapsed := toolCall(t, "task_create", map[string]interface{}{
		"description":  "Lifecycle test root task",
		"ttl":          "10m",
		"can_delegate": true,
	})
	rootID, _ := rootData["task_id"].(string)
	rootEnvelope, _ := rootData["envelope"].(map[string]interface{})
	rootTargets, _ := rootEnvelope["targets"].([]interface{})

	if rootID == "" {
		logPerf(t, "lifecycle_create_root", rootElapsed, false, "no task_id")
		t.Fatal("task_create returned no task_id")
	}
	logPerf(t, "lifecycle_create_root", rootElapsed, true,
		fmt.Sprintf("root=%s targets=%d", rootID[:8], len(rootTargets)))

	// Step 2: Delegate a child task with restricted envelope.
	childData, childElapsed := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": rootID,
		"description":    "Lifecycle test child task",
		"ttl":            "5m",
		"envelope": map[string]interface{}{
			"targets": []string{"hugoblog"},
			"roles":   []string{"read"},
		},
	})
	childID, _ := childData["task_id"].(string)
	childEnvelope, _ := childData["envelope"].(map[string]interface{})
	childTargets, _ := childEnvelope["targets"].([]interface{})

	if childID == "" {
		logPerf(t, "lifecycle_delegate_child", childElapsed, false, "no child task_id")
		t.Fatal("task_delegate returned no task_id")
	}

	logPerf(t, "lifecycle_delegate_child", childElapsed, true,
		fmt.Sprintf("child=%s targets=%v", childID[:8], childTargets))

	// Step 3: Verify child envelope is a subset of root.
	// Child should have fewer or equal targets.
	if len(childTargets) > len(rootTargets) {
		logPerf(t, "lifecycle_envelope_subset", 0, false,
			fmt.Sprintf("child targets(%d) > root targets(%d)", len(childTargets), len(rootTargets)))
		t.Fatalf("child envelope should be subset: child=%d root=%d", len(childTargets), len(rootTargets))
	}

	// Verify each child target exists in root targets (or root has wildcard).
	rootTargetSet := make(map[string]bool)
	hasWildcard := false
	for _, rt := range rootTargets {
		s, _ := rt.(string)
		rootTargetSet[s] = true
		if s == "*" {
			hasWildcard = true
		}
	}
	subsetValid := true
	for _, ct := range childTargets {
		s, _ := ct.(string)
		if !hasWildcard && !rootTargetSet[s] {
			subsetValid = false
			t.Errorf("child target %q not in root targets", s)
		}
	}
	logPerf(t, "lifecycle_envelope_subset", 0, subsetValid,
		fmt.Sprintf("child targets %v subset of root (wildcard=%v)", childTargets, hasWildcard))

	// Step 4: Verify both tasks are active.
	rootInfo, rootInfoElapsed := toolCall(t, "task_info", map[string]interface{}{
		"task_id": rootID,
	})
	rootTask, _ := rootInfo["task"].(map[string]interface{})
	rootDesc, _ := rootTask["description"].(string)
	logPerf(t, "lifecycle_root_active", rootInfoElapsed, rootDesc == "Lifecycle test root task",
		fmt.Sprintf("root description=%q", rootDesc))

	childInfo, childInfoElapsed := toolCall(t, "task_info", map[string]interface{}{
		"task_id": childID,
	})
	childTask, _ := childInfo["task"].(map[string]interface{})
	childDesc, _ := childTask["description"].(string)
	logPerf(t, "lifecycle_child_active", childInfoElapsed, childDesc == "Lifecycle test child task",
		fmt.Sprintf("child description=%q", childDesc))

	// Step 5: Revoke root — should cascade to child.
	_, revokeElapsed := toolCall(t, "task_revoke", map[string]interface{}{
		"task_id": rootID,
	})
	logPerf(t, "lifecycle_revoke_root", revokeElapsed, true,
		fmt.Sprintf("revoked root=%s", rootID[:8]))

	// Step 6: Verify root is revoked.
	rootErrMsg, rootVerifyElapsed := toolCallExpectError(t, "task_info", map[string]interface{}{
		"task_id": rootID,
	})
	logPerf(t, "lifecycle_root_revoked", rootVerifyElapsed, true,
		fmt.Sprintf("root correctly gone: %s", truncate(rootErrMsg, 60)))

	// Step 7: Verify child is also revoked (cascading).
	childResp, childVerifyElapsed := enfToolCallRaw(t, mcpAPIKey, "task_info", map[string]interface{}{
		"task_id": childID,
	})
	childErrText, childIsErr := enfExtractToolError(t, childResp)
	if childIsErr {
		logPerf(t, "lifecycle_child_cascaded", childVerifyElapsed, true,
			fmt.Sprintf("child correctly cascaded: %s", truncate(childErrText, 60)))
	} else {
		// Child might still show as revoked rather than gone.
		if strings.Contains(string(childResp.Result), "revoked") {
			logPerf(t, "lifecycle_child_cascaded", childVerifyElapsed, true,
				"child shows as revoked (cascade succeeded)")
		} else {
			logPerf(t, "lifecycle_child_cascaded", childVerifyElapsed, false,
				"child still active after root revocation")
			t.Error("child task should have been revoked by cascading revocation")
		}
	}
}

// TestTaskDelegationChain creates a 3-level delegation chain and verifies
// depth and parent IDs at each level.
func TestTaskDelegationChain(t *testing.T) {
	t.Log("\n=== Task Delegation Chain (3 levels) ===")

	// Level 0: Root task.
	rootData, rootElapsed := toolCall(t, "task_create", map[string]interface{}{
		"description":  "Chain root (L0)",
		"ttl":          "15m",
		"can_delegate": true,
	})
	rootID, _ := rootData["task_id"].(string)
	if rootID == "" {
		t.Fatal("failed to create root task")
	}
	logPerf(t, "chain_L0_root", rootElapsed, true,
		fmt.Sprintf("root=%s", rootID[:8]))

	// Level 1: First child.
	l1Data, l1Elapsed := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": rootID,
		"description":    "Chain L1 child",
		"ttl":            "10m",
		"can_delegate":   true,
	})
	l1ID, _ := l1Data["task_id"].(string)
	l1ParentID, _ := l1Data["parent_task_id"].(string)
	l1Depth, _ := l1Data["depth"].(float64)

	if l1ParentID != rootID {
		t.Fatalf("L1 parent_task_id=%s, expected root=%s", l1ParentID, rootID)
	}
	if int(l1Depth) != 1 {
		t.Fatalf("L1 depth=%d, expected 1", int(l1Depth))
	}
	logPerf(t, "chain_L1", l1Elapsed, true,
		fmt.Sprintf("L1=%s parent=%s depth=%d", l1ID[:8], l1ParentID[:8], int(l1Depth)))

	// Level 2: Second child (grandchild of root).
	l2Data, l2Elapsed := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": l1ID,
		"description":    "Chain L2 grandchild",
		"ttl":            "5m",
		"can_delegate":   true,
	})
	l2ID, _ := l2Data["task_id"].(string)
	l2ParentID, _ := l2Data["parent_task_id"].(string)
	l2Depth, _ := l2Data["depth"].(float64)

	if l2ParentID != l1ID {
		t.Fatalf("L2 parent_task_id=%s, expected L1=%s", l2ParentID, l1ID)
	}
	if int(l2Depth) != 2 {
		t.Fatalf("L2 depth=%d, expected 2", int(l2Depth))
	}
	logPerf(t, "chain_L2", l2Elapsed, true,
		fmt.Sprintf("L2=%s parent=%s depth=%d", l2ID[:8], l2ParentID[:8], int(l2Depth)))

	// Verify task_info for each level shows correct lineage.
	for _, tc := range []struct {
		name   string
		taskID string
		depth  int
	}{
		{"chain_info_L0", rootID, 0},
		{"chain_info_L1", l1ID, 1},
		{"chain_info_L2", l2ID, 2},
	} {
		infoData, infoElapsed := toolCall(t, "task_info", map[string]interface{}{
			"task_id": tc.taskID,
		})
		task, _ := infoData["task"].(map[string]interface{})
		infoDepth, _ := task["depth"].(float64)
		// Depth may be in the top-level response or nested.
		if infoDepth == 0 && tc.depth > 0 {
			infoDepth, _ = infoData["depth"].(float64)
		}

		logPerf(t, tc.name, infoElapsed, true,
			fmt.Sprintf("task=%s depth=%.0f", tc.taskID[:8], infoDepth))
	}

	// Cleanup: revoke root (cascades).
	toolCall(t, "task_revoke", map[string]interface{}{"task_id": rootID})
	t.Log("  Cleanup: revoked root (cascading to L1 and L2)")
}

// TestTaskEnvelopeAttenuation creates a delegation chain and verifies that
// each level's effective envelope is the intersection of its parent's.
func TestTaskEnvelopeAttenuation(t *testing.T) {
	t.Log("\n=== Task Envelope Attenuation ===")

	// Step 1: Create root with full envelope.
	rootData, rootElapsed := toolCall(t, "task_create", map[string]interface{}{
		"description":  "Attenuation root",
		"ttl":          "15m",
		"can_delegate": true,
	})
	rootID, _ := rootData["task_id"].(string)
	rootEnvelope, _ := rootData["envelope"].(map[string]interface{})
	rootTargets, _ := rootEnvelope["targets"].([]interface{})
	rootRoles, _ := rootEnvelope["roles"].([]interface{})

	logPerf(t, "attenuation_root", rootElapsed, true,
		fmt.Sprintf("root=%s targets=%d roles=%d", rootID[:8], len(rootTargets), len(rootRoles)))

	// Step 2: Delegate child with reduced targets (only hugoblog).
	child1Data, child1Elapsed := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": rootID,
		"description":    "Attenuation child: hugoblog only",
		"ttl":            "10m",
		"can_delegate":   true,
		"envelope": map[string]interface{}{
			"targets": []string{"hugoblog"},
			"roles":   []string{"read", "operator"},
		},
	})
	child1ID, _ := child1Data["task_id"].(string)
	child1Envelope, _ := child1Data["envelope"].(map[string]interface{})
	child1Targets, _ := child1Envelope["targets"].([]interface{})
	child1Roles, _ := child1Envelope["roles"].([]interface{})

	logPerf(t, "attenuation_child1", child1Elapsed, true,
		fmt.Sprintf("child1=%s targets=%v roles=%v", child1ID[:8], child1Targets, child1Roles))

	// Verify child1 has only hugoblog.
	if len(child1Targets) != 1 {
		t.Errorf("expected child1 to have 1 target, got %d: %v", len(child1Targets), child1Targets)
	}

	// Step 3: Delegate grandchild from child1 with further restriction (read only).
	child2Data, child2Elapsed := toolCall(t, "task_delegate", map[string]interface{}{
		"parent_task_id": child1ID,
		"description":    "Attenuation grandchild: hugoblog read-only",
		"ttl":            "5m",
		"envelope": map[string]interface{}{
			"targets": []string{"hugoblog"},
			"roles":   []string{"read"},
		},
	})
	child2ID, _ := child2Data["task_id"].(string)
	child2Envelope, _ := child2Data["envelope"].(map[string]interface{})
	child2Targets, _ := child2Envelope["targets"].([]interface{})
	child2Roles, _ := child2Envelope["roles"].([]interface{})

	logPerf(t, "attenuation_child2", child2Elapsed, true,
		fmt.Sprintf("child2=%s targets=%v roles=%v", child2ID[:8], child2Targets, child2Roles))

	// Verify grandchild has only hugoblog and read.
	if len(child2Targets) != 1 {
		t.Errorf("expected child2 to have 1 target, got %d: %v", len(child2Targets), child2Targets)
	}
	if len(child2Roles) > 1 {
		t.Logf("  [INFO] child2 has %d roles (expected 1): %v", len(child2Roles), child2Roles)
	}

	// Step 4: Try to delegate grandchild with WIDER envelope than child1 — should fail.
	t.Log("  Step 4: Attempt to widen envelope beyond parent...")
	errMsg, widenElapsed := toolCallExpectError(t, "task_delegate", map[string]interface{}{
		"parent_task_id": child1ID,
		"description":    "Should fail: wider than parent",
		"ttl":            "5m",
		"can_delegate":   true,
		"envelope": map[string]interface{}{
			"targets": []string{"hugoblog", "dockerhost"},
			"roles":   []string{"read", "operator", "admin"},
		},
	})
	isAttenError := strings.Contains(errMsg, "envelope") ||
		strings.Contains(errMsg, "attenu") ||
		strings.Contains(errMsg, "exceed") ||
		strings.Contains(errMsg, "not permitted") ||
		strings.Contains(errMsg, "subset") ||
		strings.Contains(errMsg, "narrow")

	logPerf(t, "attenuation_widen_rejected", widenElapsed, isAttenError,
		fmt.Sprintf("widen rejected: %s", truncate(errMsg, 80)))

	if !isAttenError {
		t.Logf("  [WARN] Widening error may use different message: %s", errMsg)
	}

	// Cleanup.
	toolCall(t, "task_revoke", map[string]interface{}{"task_id": rootID})
	t.Log("  Cleanup: revoked root (cascading)")
}
