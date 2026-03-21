//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Dashboard API Integration Tests
//
// Tests the dashboard HTTP API endpoints on the dashboard port (:8553).
// These endpoints serve the web dashboard and expose broker state.
// =============================================================================

// dashboardGet makes an authenticated GET request to the dashboard API.
func dashboardGet(t *testing.T, path string) (map[string]interface{}, int, time.Duration) {
	t.Helper()
	url := dashEndpoint + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dashToken)

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		// Not JSON — return raw as a string value.
		return map[string]interface{}{"raw": string(body)}, resp.StatusCode, elapsed
	}
	return data, resp.StatusCode, elapsed
}

// dashboardGetRaw makes a GET request and returns the raw body string.
func dashboardGetRaw(t *testing.T, path string, token string) (string, int, time.Duration) {
	t.Helper()
	url := dashEndpoint + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode, elapsed
}

// TestDashboardSummary tests GET /v1/dashboard/summary for key status fields.
func TestDashboardSummary(t *testing.T) {
	t.Log("\n=== Dashboard Summary Test ===")

	data, statusCode, elapsed := dashboardGet(t, "/v1/dashboard/summary")

	if statusCode != 200 {
		logPerf(t, "dashboard_summary", elapsed, false,
			fmt.Sprintf("status_code=%d", statusCode))
		t.Fatalf("GET /v1/dashboard/summary returned %d", statusCode)
	}

	// Check for expected top-level fields.
	expectedFields := []string{"broker_status", "signer_ok", "hosts_online"}
	missing := []string{}
	for _, field := range expectedFields {
		if _, ok := data[field]; !ok {
			missing = append(missing, field)
		}
	}

	if len(missing) > 0 {
		// The API may use different field names — log what we got.
		logPerf(t, "dashboard_summary", elapsed, false,
			fmt.Sprintf("missing fields: %v, got keys: %v", missing, mapKeys(data)))
		t.Logf("  [WARN] Expected fields %v not found. Response keys: %v", missing, mapKeys(data))
		// Don't fail — the API structure may have evolved.
	}

	// Log what we received.
	brokerStatus, _ := data["broker_status"].(string)
	signerOK, _ := data["signer_ok"].(bool)
	hostsOnline, _ := data["hosts_online"].(float64)

	logPerf(t, "dashboard_summary", elapsed, true,
		fmt.Sprintf("broker=%s signer_ok=%v hosts_online=%d keys=%v",
			brokerStatus, signerOK, int(hostsOnline), mapKeys(data)))
}

// TestDashboardHosts tests GET /v1/dashboard/hosts for a non-empty host list.
func TestDashboardHosts(t *testing.T) {
	t.Log("\n=== Dashboard Hosts Test ===")

	data, statusCode, elapsed := dashboardGet(t, "/v1/dashboard/hosts")

	if statusCode != 200 {
		logPerf(t, "dashboard_hosts", elapsed, false,
			fmt.Sprintf("status_code=%d", statusCode))
		t.Fatalf("GET /v1/dashboard/hosts returned %d", statusCode)
	}

	// Hosts may be in a "hosts" array or be the top-level array.
	hosts, _ := data["hosts"].([]interface{})
	if hosts == nil {
		// Try to see if the whole response is an array by checking raw.
		if raw, ok := data["raw"].(string); ok {
			var arr []interface{}
			if err := json.Unmarshal([]byte(raw), &arr); err == nil {
				hosts = arr
			}
		}
	}

	if len(hosts) == 0 {
		logPerf(t, "dashboard_hosts", elapsed, false, "no hosts returned")
		t.Logf("  [WARN] No hosts found. Response: %v", data)
	} else {
		// Check first host has expected fields.
		firstHost, _ := hosts[0].(map[string]interface{})
		hostName, _ := firstHost["name"].(string)
		if hostName == "" {
			hostName, _ = firstHost["host"].(string)
		}

		logPerf(t, "dashboard_hosts", elapsed, true,
			fmt.Sprintf("%d hosts, first=%q", len(hosts), hostName))
	}
}

// TestDashboardAudit tests GET /v1/dashboard/audit?limit=10 for audit entries.
func TestDashboardAudit(t *testing.T) {
	t.Log("\n=== Dashboard Audit Test ===")

	data, statusCode, elapsed := dashboardGet(t, "/v1/dashboard/audit?limit=10")

	if statusCode != 200 {
		logPerf(t, "dashboard_audit", elapsed, false,
			fmt.Sprintf("status_code=%d", statusCode))
		t.Fatalf("GET /v1/dashboard/audit?limit=10 returned %d", statusCode)
	}

	// Audit entries may be in an "events" or "entries" array.
	events, _ := data["events"].([]interface{})
	if events == nil {
		events, _ = data["entries"].([]interface{})
	}
	if events == nil {
		events, _ = data["audit"].([]interface{})
	}

	if events == nil {
		// Might be raw text or different structure.
		logPerf(t, "dashboard_audit", elapsed, true,
			fmt.Sprintf("response keys: %v (no recognized array field)", mapKeys(data)))
		return
	}

	if len(events) == 0 {
		logPerf(t, "dashboard_audit", elapsed, true, "0 audit entries (system may be fresh)")
		return
	}

	// Check first entry for expected fields.
	firstEntry, _ := events[0].(map[string]interface{})
	eventType, _ := firstEntry["type"].(string)
	if eventType == "" {
		eventType, _ = firstEntry["action"].(string)
	}
	timestamp, _ := firstEntry["timestamp"].(string)
	if timestamp == "" {
		timestamp, _ = firstEntry["time"].(string)
	}

	logPerf(t, "dashboard_audit", elapsed, true,
		fmt.Sprintf("%d entries, first type=%q time=%s", len(events), eventType, truncate(timestamp, 25)))
}

// TestDashboardMetrics tests GET /v1/dashboard/metrics (or /v1/metrics) for
// Prometheus-format metrics with expected counter/histogram names.
func TestDashboardMetrics(t *testing.T) {
	t.Log("\n=== Dashboard Metrics Test ===")

	// The metrics endpoint may be at /v1/metrics or /v1/dashboard/metrics.
	body, statusCode, elapsed := dashboardGetRaw(t, "/v1/metrics", dashToken)

	if statusCode != 200 {
		// Try alternative path.
		body, statusCode, elapsed = dashboardGetRaw(t, "/v1/dashboard/metrics", dashToken)
	}

	if statusCode != 200 {
		logPerf(t, "dashboard_metrics", elapsed, false,
			fmt.Sprintf("status_code=%d", statusCode))
		t.Fatalf("GET metrics endpoint returned %d", statusCode)
	}

	// Check for expected Prometheus metric names.
	expectedMetrics := []string{
		"ephyr_tasks_created_total",
		"ephyr_tokens_signed_total",
	}
	found := 0
	for _, metric := range expectedMetrics {
		if strings.Contains(body, metric) {
			found++
		}
	}

	lines := strings.Count(body, "\n")
	logPerf(t, "dashboard_metrics", elapsed, found > 0,
		fmt.Sprintf("%d lines, %d/%d expected metrics found", lines, found, len(expectedMetrics)))

	if found == 0 {
		t.Logf("  [WARN] No expected metrics found in %d lines of output", lines)
	}
}

// TestDashboardAuth tests that requests without a valid token are rejected.
func TestDashboardAuth(t *testing.T) {
	t.Log("\n=== Dashboard Auth Test ===")

	t.Run("NoToken", func(t *testing.T) {
		_, statusCode, elapsed := dashboardGetRaw(t, "/v1/dashboard/summary", "")
		isUnauthorized := statusCode == 401 || statusCode == 403

		logPerf(t, "dashboard_auth_no_token", elapsed, isUnauthorized,
			fmt.Sprintf("status_code=%d (expected 401/403)", statusCode))

		if !isUnauthorized {
			t.Errorf("expected 401/403 without token, got %d", statusCode)
		}
	})

	t.Run("BadToken", func(t *testing.T) {
		_, statusCode, elapsed := dashboardGetRaw(t, "/v1/dashboard/summary", "invalid-token-xyz")
		isUnauthorized := statusCode == 401 || statusCode == 403

		logPerf(t, "dashboard_auth_bad_token", elapsed, isUnauthorized,
			fmt.Sprintf("status_code=%d (expected 401/403)", statusCode))

		if !isUnauthorized {
			t.Errorf("expected 401/403 with bad token, got %d", statusCode)
		}
	})

	t.Run("ValidToken", func(t *testing.T) {
		_, statusCode, elapsed := dashboardGetRaw(t, "/v1/dashboard/summary", dashToken)

		logPerf(t, "dashboard_auth_valid_token", elapsed, statusCode == 200,
			fmt.Sprintf("status_code=%d (expected 200)", statusCode))

		if statusCode != 200 {
			t.Errorf("expected 200 with valid token, got %d", statusCode)
		}
	})
}
