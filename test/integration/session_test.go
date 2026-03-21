//go:build integration

package integration

import (
	"fmt"
	"strings"
	"testing"
)

// =============================================================================
// Persistent SSH Session Integration Tests
//
// Tests the session_create, session_close, and list_sessions MCP tools
// for persistent SSH session lifecycle management.
// =============================================================================

// TestSessionLifecycle tests the full session lifecycle:
// create -> verify listed -> close -> verify gone.
func TestSessionLifecycle(t *testing.T) {
	t.Log("\n=== Session Lifecycle Test ===")

	// Step 1: Create a session on hugoblog (lightweight target).
	createData, createElapsed := toolCall(t, "session_create", map[string]interface{}{
		"target": "hugoblog",
		"role":   "read",
	})

	sessionID, _ := createData["session_id"].(string)
	if sessionID == "" {
		// Try alternative field names.
		sessionID, _ = createData["id"].(string)
	}
	if sessionID == "" {
		logPerf(t, "session_create", createElapsed, false, "no session_id returned")
		t.Fatalf("session_create returned no session_id: %v", createData)
	}

	logPerf(t, "session_create", createElapsed, true,
		fmt.Sprintf("session=%s on hugoblog/read", sessionID))

	// Step 2: Verify the session appears in list_sessions.
	listData, listElapsed := toolCall(t, "list_sessions", map[string]interface{}{})
	sessions, _ := listData["sessions"].([]interface{})

	found := false
	for _, sess := range sessions {
		sessMap, ok := sess.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := sessMap["session_id"].(string)
		if id == "" {
			id, _ = sessMap["id"].(string)
		}
		if id == sessionID {
			found = true
			break
		}
	}
	if !found {
		logPerf(t, "session_list_after_create", listElapsed, false,
			fmt.Sprintf("session %s not found in %d sessions", sessionID, len(sessions)))
		t.Fatalf("created session %s not found in list_sessions", sessionID)
	}

	logPerf(t, "session_list_after_create", listElapsed, true,
		fmt.Sprintf("session %s found in %d sessions", sessionID, len(sessions)))

	// Step 3: Close the session.
	closeData, closeElapsed := toolCall(t, "session_close", map[string]interface{}{
		"session_id": sessionID,
	})
	closeStatus, _ := closeData["status"].(string)
	logPerf(t, "session_close", closeElapsed, true,
		fmt.Sprintf("closed session %s status=%q", sessionID, closeStatus))

	// Step 4: Verify the session is no longer listed.
	listData2, listElapsed2 := toolCall(t, "list_sessions", map[string]interface{}{})
	sessions2, _ := listData2["sessions"].([]interface{})

	stillPresent := false
	for _, sess := range sessions2 {
		sessMap, ok := sess.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := sessMap["session_id"].(string)
		if id == "" {
			id, _ = sessMap["id"].(string)
		}
		if id == sessionID {
			stillPresent = true
			break
		}
	}
	if stillPresent {
		logPerf(t, "session_list_after_close", listElapsed2, false,
			fmt.Sprintf("session %s still present after close", sessionID))
		t.Fatalf("closed session %s still appears in list_sessions", sessionID)
	}

	logPerf(t, "session_list_after_close", listElapsed2, true,
		fmt.Sprintf("session %s correctly removed, %d remaining", sessionID, len(sessions2)))
}

// TestSessionCreateInvalidTarget tests that creating a session on a nonexistent
// target returns an error.
func TestSessionCreateInvalidTarget(t *testing.T) {
	t.Log("\n=== Session Create Invalid Target Test ===")

	errMsg, elapsed := toolCallExpectError(t, "session_create", map[string]interface{}{
		"target": "nonexistent-host-xyz",
		"role":   "read",
	})

	isTargetError := strings.Contains(errMsg, "target") ||
		strings.Contains(errMsg, "unknown") ||
		strings.Contains(errMsg, "not found") ||
		strings.Contains(errMsg, "no such")

	logPerf(t, "session_create_invalid_target", elapsed, isTargetError,
		fmt.Sprintf("rejected: %s", truncate(errMsg, 80)))

	if !isTargetError {
		t.Logf("  [WARN] Error message may not indicate target issue: %s", errMsg)
	}
}

// TestMultipleSessions creates sessions on multiple targets, verifies all
// are listed, then closes all.
func TestMultipleSessions(t *testing.T) {
	t.Log("\n=== Multiple Sessions Test ===")

	// Targets to create sessions on (all should be reachable).
	targets := []struct {
		target string
		role   string
	}{
		{"hugoblog", "read"},
		{"dockerhost", "read"},
		{"mandrake-rack", "read"},
	}

	var sessionIDs []string

	// Step 1: Create a session on each target.
	for _, tgt := range targets {
		data, elapsed := toolCall(t, "session_create", map[string]interface{}{
			"target": tgt.target,
			"role":   tgt.role,
		})

		sessionID, _ := data["session_id"].(string)
		if sessionID == "" {
			sessionID, _ = data["id"].(string)
		}
		if sessionID == "" {
			logPerf(t, "multi_session_create_"+tgt.target, elapsed, false,
				"no session_id returned")
			t.Fatalf("session_create on %s returned no session_id: %v", tgt.target, data)
		}

		sessionIDs = append(sessionIDs, sessionID)
		logPerf(t, "multi_session_create_"+tgt.target, elapsed, true,
			fmt.Sprintf("session=%s", sessionID))
	}

	// Step 2: Verify all sessions appear in list_sessions.
	listData, listElapsed := toolCall(t, "list_sessions", map[string]interface{}{})
	sessions, _ := listData["sessions"].([]interface{})

	foundCount := 0
	for _, wantID := range sessionIDs {
		for _, sess := range sessions {
			sessMap, ok := sess.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := sessMap["session_id"].(string)
			if id == "" {
				id, _ = sessMap["id"].(string)
			}
			if id == wantID {
				foundCount++
				break
			}
		}
	}

	logPerf(t, "multi_session_list_all", listElapsed, foundCount == len(sessionIDs),
		fmt.Sprintf("found %d/%d sessions in list", foundCount, len(sessionIDs)))

	if foundCount != len(sessionIDs) {
		t.Fatalf("expected %d sessions in list, found %d", len(sessionIDs), foundCount)
	}

	// Step 3: Close all sessions.
	for i, sessionID := range sessionIDs {
		_, closeElapsed := toolCall(t, "session_close", map[string]interface{}{
			"session_id": sessionID,
		})
		logPerf(t, fmt.Sprintf("multi_session_close_%s", targets[i].target), closeElapsed, true,
			fmt.Sprintf("closed session %s", sessionID))
	}

	// Step 4: Verify none of our sessions remain.
	listData2, listElapsed2 := toolCall(t, "list_sessions", map[string]interface{}{})
	sessions2, _ := listData2["sessions"].([]interface{})

	remaining := 0
	for _, wantID := range sessionIDs {
		for _, sess := range sessions2 {
			sessMap, ok := sess.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := sessMap["session_id"].(string)
			if id == "" {
				id, _ = sessMap["id"].(string)
			}
			if id == wantID {
				remaining++
				break
			}
		}
	}

	logPerf(t, "multi_session_cleanup_verify", listElapsed2, remaining == 0,
		fmt.Sprintf("%d sessions remaining (should be 0)", remaining))

	if remaining > 0 {
		t.Fatalf("%d sessions still present after closing all", remaining)
	}
}
