package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Configuration — override via environment variables.
var (
	mcpEndpoint = envOr("CLAUTH_MCP_ENDPOINT", "http://192.168.100.75:8554/mcp")
	mcpAPIKey   = envOr("CLAUTH_MCP_KEY", "MoKz9p04QrQ/vL8XZXE4S93t96I/N+sVV1601MgJKU8=")
	dashEndpoint = envOr("CLAUTH_DASH_ENDPOINT", "http://192.168.100.75:8553")
	dashToken    = envOr("CLAUTH_DASH_TOKEN", "password")
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// --- JSON-RPC types ---

type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

// --- Test helpers ---

type perfRecord struct {
	Test     string        `json:"test"`
	Latency  time.Duration `json:"latency_ms"`
	Pass     bool          `json:"pass"`
	Detail   string        `json:"detail,omitempty"`
}

var perfLog []perfRecord

func mcpCall(t *testing.T, method string, params interface{}) (*rpcResponse, time.Duration) {
	t.Helper()
	req := rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	httpReq, _ := http.NewRequest("POST", mcpEndpoint, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+mcpAPIKey)

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

func toolCall(t *testing.T, toolName string, args map[string]interface{}) (map[string]interface{}, time.Duration) {
	t.Helper()
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}
	resp, elapsed := mcpCall(t, "tools/call", params)
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

	// Parse the text content as JSON.
	var data map[string]interface{}
	if len(result.Content) > 0 && result.Content[0].Type == "text" {
		if err := json.Unmarshal([]byte(result.Content[0].Text), &data); err != nil {
			// Not JSON — return raw text.
			return map[string]interface{}{"raw": result.Content[0].Text}, elapsed
		}
	}
	return data, elapsed
}

func toolCallExpectError(t *testing.T, toolName string, args map[string]interface{}) (string, time.Duration) {
	t.Helper()
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}
	resp, elapsed := mcpCall(t, "tools/call", params)
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

func logPerf(t *testing.T, name string, latency time.Duration, pass bool, detail string) {
	rec := perfRecord{Test: name, Latency: latency, Pass: pass, Detail: detail}
	perfLog = append(perfLog, rec)
	status := "PASS"
	if !pass {
		status = "FAIL"
	}
	t.Logf("  [%s] %s — %s (%.2fms)", status, name, detail, float64(latency.Microseconds())/1000.0)
}

// =============================================================================
// TESTS
// =============================================================================

func TestMCPInitialize(t *testing.T) {
	resp, elapsed := mcpCall(t, "initialize", map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"clientInfo": map[string]interface{}{
			"name":    "smoke-test",
			"version": "1.0",
		},
	})
	if resp.Error != nil {
		logPerf(t, "mcp_initialize", elapsed, false, resp.Error.Message)
		t.Fatalf("initialize failed: %s", resp.Error.Message)
	}

	var result map[string]interface{}
	json.Unmarshal(resp.Result, &result)

	version, _ := result["protocolVersion"].(string)
	if version != "2025-03-26" {
		logPerf(t, "mcp_initialize", elapsed, false, "wrong protocol version: "+version)
		t.Fatalf("expected protocol 2025-03-26, got %s", version)
	}

	serverInfo, _ := result["serverInfo"].(map[string]interface{})
	serverName, _ := serverInfo["name"].(string)
	logPerf(t, "mcp_initialize", elapsed, true, fmt.Sprintf("server=%s protocol=%s", serverName, version))
}

func TestToolsList(t *testing.T) {
	resp, elapsed := mcpCall(t, "tools/list", nil)
	if resp.Error != nil {
		logPerf(t, "tools_list", elapsed, false, resp.Error.Message)
		t.Fatalf("tools/list failed: %s", resp.Error.Message)
	}

	var result map[string]interface{}
	json.Unmarshal(resp.Result, &result)

	tools, _ := result["tools"].([]interface{})
	toolCount := len(tools)

	// Check that task tools exist.
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		tm, _ := tool.(map[string]interface{})
		name, _ := tm["name"].(string)
		toolNames[name] = true
	}

	expectedNew := []string{"task_create", "task_info", "task_revoke", "task_list"}
	missing := []string{}
	for _, name := range expectedNew {
		if !toolNames[name] {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		logPerf(t, "tools_list", elapsed, false, fmt.Sprintf("missing tools: %v", missing))
		t.Fatalf("missing task tools: %v", missing)
	}

	logPerf(t, "tools_list", elapsed, true, fmt.Sprintf("%d tools, all 4 task tools present", toolCount))
}

func TestLegacyToolsStillWork(t *testing.T) {
	data, elapsed := toolCall(t, "list_targets", map[string]interface{}{})
	targets, _ := data["targets"].([]interface{})
	logPerf(t, "legacy_list_targets", elapsed, true, fmt.Sprintf("%d targets", len(targets)))
}

func TestTaskLifecycle(t *testing.T) {
	// ---- 1. Create a task ----
	t.Log("\n=== Task Lifecycle Test ===")

	createData, createElapsed := toolCall(t, "task_create", map[string]interface{}{
		"description": "Smoke test: verify v0.2 task identity",
		"ttl":         "5m",
	})

	taskID, _ := createData["task_id"].(string)
	tokenStr, _ := createData["token"].(string)
	expiresAt, _ := createData["expires_at"].(string)

	if taskID == "" {
		logPerf(t, "task_create", createElapsed, false, "no task_id returned")
		t.Fatal("task_create returned no task_id")
	}
	if tokenStr == "" {
		logPerf(t, "task_create", createElapsed, false, "no token returned")
		t.Fatal("task_create returned no token")
	}

	// Validate token format (3 dot-separated base64url segments).
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		logPerf(t, "task_create", createElapsed, false, fmt.Sprintf("token has %d parts, expected 3", len(parts)))
		t.Fatalf("token format invalid: %d parts", len(parts))
	}

	// Validate ULID format (26 chars).
	if len(taskID) != 26 {
		logPerf(t, "task_create", createElapsed, false, fmt.Sprintf("task_id length %d, expected 26", len(taskID)))
		t.Fatalf("task_id not ULID: %s", taskID)
	}

	// Check envelope is populated.
	envelope, _ := createData["envelope"].(map[string]interface{})
	targets, _ := envelope["targets"].([]interface{})
	roles, _ := envelope["roles"].([]interface{})

	logPerf(t, "task_create", createElapsed, true,
		fmt.Sprintf("id=%s token=%d chars expires=%s targets=%d roles=%d",
			taskID[:8], len(tokenStr), expiresAt, len(targets), len(roles)))

	// ---- 2. Get task info ----
	infoData, infoElapsed := toolCall(t, "task_info", map[string]interface{}{
		"task_id": taskID,
	})

	task, _ := infoData["task"].(map[string]interface{})
	taskDesc, _ := task["description"].(string)
	remainingTTL, _ := infoData["remaining_ttl"].(string)
	isRevoked, _ := infoData["is_revoked"].(bool)

	if taskDesc != "Smoke test: verify v0.2 task identity" {
		logPerf(t, "task_info", infoElapsed, false, "wrong description: "+taskDesc)
		t.Fatalf("task description mismatch")
	}
	if isRevoked {
		logPerf(t, "task_info", infoElapsed, false, "task unexpectedly revoked")
		t.Fatal("new task should not be revoked")
	}

	logPerf(t, "task_info", infoElapsed, true,
		fmt.Sprintf("description match, remaining=%s, revoked=%v", remainingTTL, isRevoked))

	// ---- 3. List tasks ----
	listData, listElapsed := toolCall(t, "task_list", map[string]interface{}{})
	taskList, _ := listData["tasks"].([]interface{})
	count, _ := listData["count"].(float64)

	found := false
	for _, item := range taskList {
		tm, _ := item.(map[string]interface{})
		if id, _ := tm["id"].(string); id == taskID {
			found = true
			break
		}
	}
	if !found {
		logPerf(t, "task_list", listElapsed, false, "created task not in list")
		t.Fatal("task_list does not contain created task")
	}

	logPerf(t, "task_list", listElapsed, true,
		fmt.Sprintf("%d active tasks, created task found", int(count)))

	// ---- 4. Create a second task ----
	create2Data, create2Elapsed := toolCall(t, "task_create", map[string]interface{}{
		"description": "Second concurrent task",
		"ttl":         "2m",
	})
	taskID2, _ := create2Data["task_id"].(string)
	logPerf(t, "task_create_2", create2Elapsed, taskID2 != "",
		fmt.Sprintf("id=%s (concurrent tasks OK)", taskID2[:8]))

	// ---- 5. Revoke the first task ----
	revokeData, revokeElapsed := toolCall(t, "task_revoke", map[string]interface{}{
		"task_id": taskID,
	})
	revokedID, _ := revokeData["revoked"].(string)
	revokeStatus, _ := revokeData["status"].(string)

	if revokedID != taskID {
		logPerf(t, "task_revoke", revokeElapsed, false, "revoked wrong task")
		t.Fatal("revoke returned wrong task ID")
	}

	logPerf(t, "task_revoke", revokeElapsed, true,
		fmt.Sprintf("revoked=%s status=%q", revokedID[:8], revokeStatus))

	// ---- 6. Verify revoked task is gone ----
	errMsg, verifyElapsed := toolCallExpectError(t, "task_info", map[string]interface{}{
		"task_id": taskID,
	})

	logPerf(t, "task_verify_revoked", verifyElapsed, true,
		fmt.Sprintf("correctly rejected: %s", errMsg))

	// ---- 7. Second task still active ----
	info2Data, info2Elapsed := toolCall(t, "task_info", map[string]interface{}{
		"task_id": taskID2,
	})
	task2, _ := info2Data["task"].(map[string]interface{})
	task2Desc, _ := task2["description"].(string)

	logPerf(t, "task_independent_survival", info2Elapsed, task2Desc == "Second concurrent task",
		"second task survived first task's revocation")

	// ---- 8. Clean up second task ----
	_, cleanElapsed := toolCall(t, "task_revoke", map[string]interface{}{
		"task_id": taskID2,
	})
	logPerf(t, "task_cleanup", cleanElapsed, true, "second task revoked")
}

func TestTaskValidation(t *testing.T) {
	t.Log("\n=== Task Validation Test ===")

	// Invalid TTL.
	errMsg, elapsed := toolCallExpectError(t, "task_create", map[string]interface{}{
		"description": "bad ttl",
		"ttl":         "25h",
	})
	logPerf(t, "reject_bad_ttl", elapsed, strings.Contains(errMsg, "exceed"),
		fmt.Sprintf("rejected: %s", errMsg))

	// Empty description.
	errMsg2, elapsed2 := toolCallExpectError(t, "task_create", map[string]interface{}{
		"description": "",
	})
	logPerf(t, "reject_empty_desc", elapsed2, strings.Contains(errMsg2, "required"),
		fmt.Sprintf("rejected: %s", errMsg2))

	// Revoke nonexistent task.
	errMsg3, elapsed3 := toolCallExpectError(t, "task_revoke", map[string]interface{}{
		"task_id": "00000000000000000000000000",
	})
	logPerf(t, "reject_revoke_unknown", elapsed3, true,
		fmt.Sprintf("rejected: %s", errMsg3))
}

func TestMetricsEndpoint(t *testing.T) {
	t.Log("\n=== Metrics Endpoint Test ===")

	start := time.Now()
	req, _ := http.NewRequest("GET", dashEndpoint+"/v1/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+dashToken)
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		logPerf(t, "metrics_endpoint", elapsed, false, err.Error())
		t.Fatalf("GET /v1/metrics failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	// Check for expected Prometheus metric names.
	expected := []string{
		"clauth_tasks_created_total",
		"clauth_tokens_signed_total",
		"clauth_watermark_revocations_total",
	}
	missing := []string{}
	for _, metric := range expected {
		if !strings.Contains(content, metric) {
			missing = append(missing, metric)
		}
	}

	if len(missing) > 0 {
		logPerf(t, "metrics_content", elapsed, false, fmt.Sprintf("missing: %v", missing))
		t.Fatalf("missing Prometheus metrics: %v", missing)
	}

	lines := strings.Count(content, "\n")
	logPerf(t, "metrics_endpoint", elapsed, true,
		fmt.Sprintf("%d lines, all expected metrics present", lines))
}

func TestPerformanceBench(t *testing.T) {
	t.Log("\n=== Performance Benchmark ===")
	iterations := 10

	// Measure task_create latency over N iterations.
	var totalCreate time.Duration
	var taskIDs []string
	for i := 0; i < iterations; i++ {
		data, elapsed := toolCall(t, "task_create", map[string]interface{}{
			"description": fmt.Sprintf("perf test %d", i),
			"ttl":         "1m",
		})
		totalCreate += elapsed
		if id, ok := data["task_id"].(string); ok {
			taskIDs = append(taskIDs, id)
		}
	}
	avgCreate := totalCreate / time.Duration(iterations)
	logPerf(t, "bench_task_create", avgCreate, true,
		fmt.Sprintf("%d iterations, avg=%.2fms, total=%.2fms",
			iterations, float64(avgCreate.Microseconds())/1000.0,
			float64(totalCreate.Microseconds())/1000.0))

	// Measure task_list latency.
	var totalList time.Duration
	for i := 0; i < iterations; i++ {
		_, elapsed := toolCall(t, "task_list", map[string]interface{}{})
		totalList += elapsed
	}
	avgList := totalList / time.Duration(iterations)
	logPerf(t, "bench_task_list", avgList, true,
		fmt.Sprintf("%d iterations, avg=%.2fms", iterations, float64(avgList.Microseconds())/1000.0))

	// Measure task_info latency.
	var totalInfo time.Duration
	for i := 0; i < iterations; i++ {
		idx := i % len(taskIDs)
		_, elapsed := toolCall(t, "task_info", map[string]interface{}{
			"task_id": taskIDs[idx],
		})
		totalInfo += elapsed
	}
	avgInfo := totalInfo / time.Duration(iterations)
	logPerf(t, "bench_task_info", avgInfo, true,
		fmt.Sprintf("%d iterations, avg=%.2fms", iterations, float64(avgInfo.Microseconds())/1000.0))

	// Measure task_revoke latency (cleanup all perf tasks).
	var totalRevoke time.Duration
	for _, id := range taskIDs {
		_, elapsed := toolCall(t, "task_revoke", map[string]interface{}{
			"task_id": id,
		})
		totalRevoke += elapsed
	}
	avgRevoke := totalRevoke / time.Duration(len(taskIDs))
	logPerf(t, "bench_task_revoke", avgRevoke, true,
		fmt.Sprintf("%d iterations, avg=%.2fms", len(taskIDs), float64(avgRevoke.Microseconds())/1000.0))
}

func TestSummary(t *testing.T) {
	t.Log("\n" + strings.Repeat("=", 72))
	t.Log("  CLAUTH v0.2 PHASE 2a — INTEGRATION TEST REPORT")
	t.Log(strings.Repeat("=", 72))
	t.Log("")

	passed, failed := 0, 0
	var totalLatency time.Duration

	t.Logf("  %-30s  %8s  %6s  %s", "TEST", "LATENCY", "STATUS", "DETAIL")
	t.Log("  " + strings.Repeat("-", 70))

	for _, rec := range perfLog {
		status := "  OK  "
		if !rec.Pass {
			status = " FAIL "
			failed++
		} else {
			passed++
		}
		totalLatency += rec.Latency
		t.Logf("  %-30s  %7.2fms  [%s]  %s",
			rec.Test,
			float64(rec.Latency.Microseconds())/1000.0,
			status, rec.Detail)
	}

	t.Log("  " + strings.Repeat("-", 70))
	t.Logf("  TOTAL: %d passed, %d failed, %.2fms total latency",
		passed, failed, float64(totalLatency.Microseconds())/1000.0)
	t.Log(strings.Repeat("=", 72))

	// Write JSON report to file.
	report := map[string]interface{}{
		"timestamp":     time.Now().Format(time.RFC3339),
		"endpoint":      mcpEndpoint,
		"total_tests":   passed + failed,
		"passed":        passed,
		"failed":        failed,
		"total_latency_ms": float64(totalLatency.Microseconds()) / 1000.0,
		"tests":         perfLog,
	}
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	reportPath := "/tmp/clauth-smoke-report.json"
	os.WriteFile(reportPath, reportJSON, 0644)
	t.Logf("\n  Report written to %s", reportPath)

	if failed > 0 {
		t.Fatalf("%d tests failed", failed)
	}
}
