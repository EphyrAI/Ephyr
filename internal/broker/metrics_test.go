package broker

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLatencyHistogramObserveBucketPlacement(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		bucket   int // expected bucket index
	}{
		{"50µs goes to bucket 0 (<100µs)", 50 * time.Microsecond, 0},
		{"99µs goes to bucket 0 (<100µs)", 99 * time.Microsecond, 0},
		{"100µs goes to bucket 1 (<500µs)", 100 * time.Microsecond, 1},
		{"250µs goes to bucket 1 (<500µs)", 250 * time.Microsecond, 1},
		{"500µs goes to bucket 2 (<1ms)", 500 * time.Microsecond, 2},
		{"1ms goes to bucket 3 (<5ms)", 1 * time.Millisecond, 3},
		{"4ms goes to bucket 3 (<5ms)", 4 * time.Millisecond, 3},
		{"5ms goes to bucket 4 (<10ms)", 5 * time.Millisecond, 4},
		{"10ms goes to bucket 5 (<50ms)", 10 * time.Millisecond, 5},
		{"49ms goes to bucket 5 (<50ms)", 49 * time.Millisecond, 5},
		{"50ms goes to bucket 6 (>=50ms)", 50 * time.Millisecond, 6},
		{"100ms goes to bucket 6 (>=50ms)", 100 * time.Millisecond, 6},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var h LatencyHistogram
			h.Observe(tc.duration)

			if h.buckets[tc.bucket].Load() != 1 {
				for i := 0; i < 7; i++ {
					if h.buckets[i].Load() != 0 {
						t.Errorf("value went to bucket %d instead of %d", i, tc.bucket)
					}
				}
			}
			if h.count.Load() != 1 {
				t.Errorf("expected count 1, got %d", h.count.Load())
			}
			if h.sum.Load() != tc.duration.Nanoseconds() {
				t.Errorf("expected sum %d, got %d", tc.duration.Nanoseconds(), h.sum.Load())
			}
		})
	}
}

func TestLatencyHistogramPercentiles(t *testing.T) {
	var h LatencyHistogram

	// Add 100 observations all in the <100µs bucket.
	for i := 0; i < 100; i++ {
		h.Observe(50 * time.Microsecond)
	}

	p50, p95, p99 := h.Percentiles()
	if p50 > 100 {
		t.Errorf("p50 should be <= 100µs, got %.1fµs", p50)
	}
	if p95 > 100 {
		t.Errorf("p95 should be <= 100µs, got %.1fµs", p95)
	}
	if p99 > 100 {
		t.Errorf("p99 should be <= 100µs, got %.1fµs", p99)
	}
}

func TestLatencyHistogramPercentilesMultiBucket(t *testing.T) {
	var h LatencyHistogram

	// 90 observations in <100µs, 9 in <1ms, 1 in <50ms.
	for i := 0; i < 90; i++ {
		h.Observe(50 * time.Microsecond)
	}
	for i := 0; i < 9; i++ {
		h.Observe(750 * time.Microsecond)
	}
	h.Observe(30 * time.Millisecond)

	p50, p95, p99 := h.Percentiles()

	// p50 should be in the first bucket range.
	if p50 > 100 {
		t.Errorf("p50 should be <= 100µs with 90%% in first bucket, got %.1fµs", p50)
	}
	// p95 should be beyond the first bucket.
	if p95 < 100 {
		t.Errorf("p95 should be > 100µs, got %.1fµs", p95)
	}
	// p99 should be in a high bucket.
	if p99 < 500 {
		t.Errorf("p99 should be > 500µs, got %.1fµs", p99)
	}
}

func TestLatencyHistogramPercentilesEmpty(t *testing.T) {
	var h LatencyHistogram
	p50, p95, p99 := h.Percentiles()
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Errorf("expected all zeros for empty histogram, got p50=%.1f p95=%.1f p99=%.1f", p50, p95, p99)
	}
}

func TestLatencyHistogramMean(t *testing.T) {
	var h LatencyHistogram

	// 10 observations of exactly 1ms each.
	for i := 0; i < 10; i++ {
		h.Observe(1 * time.Millisecond)
	}

	mean := h.Mean()
	// Mean should be 1000µs (1ms).
	if math.Abs(mean-1000.0) > 0.01 {
		t.Errorf("expected mean ~1000µs, got %.2fµs", mean)
	}
}

func TestLatencyHistogramMeanEmpty(t *testing.T) {
	var h LatencyHistogram
	if h.Mean() != 0 {
		t.Errorf("expected 0 for empty histogram, got %.2f", h.Mean())
	}
}

func TestLatencyHistogramCount(t *testing.T) {
	var h LatencyHistogram
	if h.Count() != 0 {
		t.Fatalf("expected count 0, got %d", h.Count())
	}
	h.Observe(1 * time.Millisecond)
	h.Observe(2 * time.Millisecond)
	h.Observe(3 * time.Millisecond)
	if h.Count() != 3 {
		t.Fatalf("expected count 3, got %d", h.Count())
	}
}

func TestLatencyHistogramReset(t *testing.T) {
	var h LatencyHistogram
	for i := 0; i < 50; i++ {
		h.Observe(time.Duration(i) * time.Millisecond)
	}

	h.Reset()

	if h.Count() != 0 {
		t.Errorf("count should be 0 after reset, got %d", h.Count())
	}
	if h.sum.Load() != 0 {
		t.Errorf("sum should be 0 after reset, got %d", h.sum.Load())
	}
	for i := 0; i < 7; i++ {
		if h.buckets[i].Load() != 0 {
			t.Errorf("bucket %d should be 0 after reset, got %d", i, h.buckets[i].Load())
		}
	}
}

func TestTimerStartStop(t *testing.T) {
	m := NewMetrics()
	timer := m.StartTimer(&m.TokenSignLatency)

	// Simulate some work.
	time.Sleep(1 * time.Millisecond)

	timer.Stop()

	if m.TokenSignLatency.Count() != 1 {
		t.Fatalf("expected 1 observation, got %d", m.TokenSignLatency.Count())
	}
	// The recorded time should be at least 1ms.
	mean := m.TokenSignLatency.Mean()
	if mean < 1000 { // 1000µs = 1ms
		t.Errorf("expected mean >= 1000µs, got %.2fµs", mean)
	}
}

func TestMetricsObserveTiming(t *testing.T) {
	m := NewMetrics()

	func() {
		defer m.ObserveTiming(&m.PolicyEvalLatency)()
		time.Sleep(1 * time.Millisecond)
	}()

	if m.PolicyEvalLatency.Count() != 1 {
		t.Fatalf("expected 1 observation, got %d", m.PolicyEvalLatency.Count())
	}
	mean := m.PolicyEvalLatency.Mean()
	if mean < 1000 {
		t.Errorf("expected mean >= 1000µs, got %.2fµs", mean)
	}
}

func TestMetricsConcurrentObservations(t *testing.T) {
	var h LatencyHistogram
	var wg sync.WaitGroup
	const goroutines = 50
	const opsPerGoroutine = 1000

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				h.Observe(time.Duration(j) * time.Microsecond)
			}
		}(i)
	}

	wg.Wait()

	expected := int64(goroutines * opsPerGoroutine)
	if h.Count() != expected {
		t.Errorf("expected count %d, got %d", expected, h.Count())
	}

	// Verify bucket counts sum to total.
	var bucketSum int64
	for i := 0; i < 7; i++ {
		bucketSum += h.buckets[i].Load()
	}
	if bucketSum != expected {
		t.Errorf("bucket sum %d != expected %d", bucketSum, expected)
	}
}

func TestPrometheusOutputFormat(t *testing.T) {
	m := NewMetrics()

	// Add some data.
	m.TokenSignLatency.Observe(50 * time.Microsecond)
	m.TokenSignLatency.Observe(200 * time.Microsecond)
	m.TokenSignLatency.Observe(5 * time.Millisecond)
	m.TasksCreated.Store(42)
	m.TokensSigned.Store(250)
	m.ActiveWatermarks.Store(3)
	m.MacaroonsMinted.Store(17)
	m.MacaroonsVerified.Store(15)
	m.MacaroonsRejected.Store(2)
	m.ReducerInvocations.Store(10)
	m.TokenSizeWarnings.Store(1)
	m.MacaroonMintLatency.Observe(100 * time.Microsecond)
	m.MacaroonVerifyLatency.Observe(300 * time.Microsecond)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.ServePrometheus(rec, req)

	body := rec.Body.String()

	// Check content type.
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %s", ct)
	}

	// Check for expected Prometheus format elements.
	expectedStrings := []string{
		"# HELP ephyr_token_sign_seconds Token signing latency",
		"# TYPE ephyr_token_sign_seconds histogram",
		`ephyr_token_sign_seconds_bucket{le="0.0001"} 1`,
		`ephyr_token_sign_seconds_bucket{le="0.0005"} 2`,
		`ephyr_token_sign_seconds_bucket{le="+Inf"} 3`,
		"ephyr_token_sign_seconds_count 3",
		"ephyr_tasks_created_total 42",
		"ephyr_tokens_signed_total 250",
		"ephyr_active_watermarks 3",
		"# TYPE ephyr_tasks_created_total counter",
		"# TYPE ephyr_active_watermarks gauge",
		// Macaroon counters
		"ephyr_macaroons_minted_total 17",
		"ephyr_macaroons_verified_total 15",
		"ephyr_macaroons_rejected_total 2",
		"ephyr_reducer_invocations_total 10",
		"ephyr_token_size_warnings_total 1",
		"# TYPE ephyr_macaroons_minted_total counter",
		"# TYPE ephyr_macaroons_rejected_total counter",
		// Macaroon histograms
		"# HELP ephyr_macaroon_mint_seconds Macaroon minting latency",
		"# TYPE ephyr_macaroon_mint_seconds histogram",
		"ephyr_macaroon_mint_seconds_count 1",
		"# HELP ephyr_macaroon_verify_seconds",
		"# TYPE ephyr_macaroon_verify_seconds histogram",
		"ephyr_macaroon_verify_seconds_count 1",
	}

	for _, exp := range expectedStrings {
		if !strings.Contains(body, exp) {
			t.Errorf("Prometheus output missing: %q\n\nFull output:\n%s", exp, body)
		}
	}
}

func TestPrometheusHistogramCumulative(t *testing.T) {
	m := NewMetrics()

	// Add 3 observations in different buckets.
	m.ExecE2ELatency.Observe(50 * time.Microsecond)   // bucket 0
	m.ExecE2ELatency.Observe(2 * time.Millisecond)     // bucket 3
	m.ExecE2ELatency.Observe(100 * time.Millisecond)   // bucket 6

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.ServePrometheus(rec, req)

	body := rec.Body.String()

	// Prometheus histograms must be cumulative.
	expectedCumulative := []string{
		`ephyr_exec_e2e_seconds_bucket{le="0.0001"} 1`,  // 1
		`ephyr_exec_e2e_seconds_bucket{le="0.0005"} 1`,  // still 1
		`ephyr_exec_e2e_seconds_bucket{le="0.001"} 1`,   // still 1
		`ephyr_exec_e2e_seconds_bucket{le="0.005"} 2`,   // 1+1
		`ephyr_exec_e2e_seconds_bucket{le="0.01"} 2`,    // still 2
		`ephyr_exec_e2e_seconds_bucket{le="0.05"} 2`,    // still 2
		`ephyr_exec_e2e_seconds_bucket{le="+Inf"} 3`,    // all 3
	}

	for _, exp := range expectedCumulative {
		if !strings.Contains(body, exp) {
			t.Errorf("cumulative histogram missing: %q\n\nFull output:\n%s", exp, body)
		}
	}
}

func TestMetricsCounterIncrementDecrement(t *testing.T) {
	m := NewMetrics()

	m.TasksActive.Add(1)
	m.TasksActive.Add(1)
	m.TasksActive.Add(1)
	if m.TasksActive.Load() != 3 {
		t.Errorf("expected 3, got %d", m.TasksActive.Load())
	}

	m.TasksActive.Add(-1)
	if m.TasksActive.Load() != 2 {
		t.Errorf("expected 2 after decrement, got %d", m.TasksActive.Load())
	}
}

func TestRequestTimingJSONMarshal(t *testing.T) {
	rt := RequestTiming{
		TokenValidateMs:  1.23,
		WatermarkCheckMs: 0.05,
		PolicyEvalMs:     0.78,
		SSHCertMs:        2.50,
		SSHExecMs:        45.00,
		TotalMs:          49.56,
	}

	data, err := json.Marshal(rt)
	if err != nil {
		t.Fatalf("failed to marshal RequestTiming: %v", err)
	}

	// Unmarshal and verify.
	var decoded RequestTiming
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal RequestTiming: %v", err)
	}

	if decoded.TokenValidateMs != 1.23 {
		t.Errorf("expected TokenValidateMs 1.23, got %f", decoded.TokenValidateMs)
	}
	if decoded.TotalMs != 49.56 {
		t.Errorf("expected TotalMs 49.56, got %f", decoded.TotalMs)
	}
}

func TestRequestTimingJSONOmitsEmpty(t *testing.T) {
	rt := RequestTiming{
		TotalMs: 10.5,
	}

	data, err := json.Marshal(rt)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	str := string(data)
	if strings.Contains(str, "token_validate_ms") {
		t.Errorf("expected omitempty to exclude zero fields, got: %s", str)
	}
	if !strings.Contains(str, "total_ms") {
		t.Errorf("expected total_ms to be present, got: %s", str)
	}
}

func TestMetricsNewMetrics(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("NewMetrics returned nil")
	}
	if m.TasksCreated.Load() != 0 {
		t.Error("expected TasksCreated to be 0")
	}
	if m.TokenSignLatency.Count() != 0 {
		t.Error("expected TokenSignLatency count to be 0")
	}
}

func TestMetricsConcurrentCounters(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	const goroutines = 100
	const increments = 1000

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < increments; j++ {
				m.TasksCreated.Add(1)
				m.TokensSigned.Add(1)
				m.TokensValidated.Add(1)
			}
		}()
	}

	wg.Wait()

	expected := int64(goroutines * increments)
	if m.TasksCreated.Load() != expected {
		t.Errorf("TasksCreated: expected %d, got %d", expected, m.TasksCreated.Load())
	}
	if m.TokensSigned.Load() != expected {
		t.Errorf("TokensSigned: expected %d, got %d", expected, m.TokensSigned.Load())
	}
}

func TestPrometheusAllHistogramsPresent(t *testing.T) {
	m := NewMetrics()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.ServePrometheus(rec, req)

	body := rec.Body.String()

	expectedHistograms := []string{
		"ephyr_token_sign_seconds",
		"ephyr_token_validate_seconds",
		"ephyr_watermark_check_seconds",
		"ephyr_envelope_check_seconds",
		"ephyr_policy_eval_seconds",
		"ephyr_ssh_cert_seconds",
		"ephyr_delegation_ipc_seconds",
		"ephyr_exec_e2e_seconds",
		"ephyr_macaroon_mint_seconds",
		"ephyr_macaroon_verify_seconds",
	}

	for _, name := range expectedHistograms {
		helpLine := fmt.Sprintf("# HELP %s", name)
		typeLine := fmt.Sprintf("# TYPE %s histogram", name)
		if !strings.Contains(body, helpLine) {
			t.Errorf("missing HELP for %s", name)
		}
		if !strings.Contains(body, typeLine) {
			t.Errorf("missing TYPE for %s", name)
		}
	}
}

func TestPrometheusAllCountersPresent(t *testing.T) {
	m := NewMetrics()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.ServePrometheus(rec, req)

	body := rec.Body.String()

	expectedCounters := []string{
		"ephyr_tasks_created_total",
		"ephyr_tasks_active",
		"ephyr_tokens_signed_total",
		"ephyr_tokens_validated_total",
		"ephyr_tokens_rejected_total",
		"ephyr_watermark_revocations_total",
		"ephyr_delegation_rotations_total",
		"ephyr_legacy_requests_total",
		"ephyr_macaroons_minted_total",
		"ephyr_macaroons_verified_total",
		"ephyr_macaroons_rejected_total",
		"ephyr_reducer_invocations_total",
		"ephyr_token_size_warnings_total",
	}

	for _, name := range expectedCounters {
		if !strings.Contains(body, name) {
			t.Errorf("missing counter: %s", name)
		}
	}
}

func TestPrometheusAllGaugesPresent(t *testing.T) {
	m := NewMetrics()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.ServePrometheus(rec, req)

	body := rec.Body.String()

	expectedGauges := []string{
		"ephyr_active_watermarks",
		"ephyr_delegation_cert_age_seconds",
		"ephyr_delegation_certs_held",
	}

	for _, name := range expectedGauges {
		helpLine := fmt.Sprintf("# HELP %s", name)
		typeLine := fmt.Sprintf("# TYPE %s gauge", name)
		if !strings.Contains(body, helpLine) {
			t.Errorf("missing HELP for gauge %s", name)
		}
		if !strings.Contains(body, typeLine) {
			t.Errorf("missing TYPE for gauge %s", name)
		}
	}
}

func TestMacaroonMetricsCounterIncrement(t *testing.T) {
	m := NewMetrics()

	// Verify initial zero state.
	if m.MacaroonsMinted.Load() != 0 {
		t.Fatal("expected MacaroonsMinted to start at 0")
	}
	if m.MacaroonsVerified.Load() != 0 {
		t.Fatal("expected MacaroonsVerified to start at 0")
	}
	if m.MacaroonsRejected.Load() != 0 {
		t.Fatal("expected MacaroonsRejected to start at 0")
	}
	if m.ReducerInvocations.Load() != 0 {
		t.Fatal("expected ReducerInvocations to start at 0")
	}
	if m.TokenSizeWarnings.Load() != 0 {
		t.Fatal("expected TokenSizeWarnings to start at 0")
	}

	// Increment counters.
	m.MacaroonsMinted.Add(5)
	m.MacaroonsVerified.Add(3)
	m.MacaroonsRejected.Add(2)
	m.ReducerInvocations.Add(7)
	m.TokenSizeWarnings.Add(1)

	if m.MacaroonsMinted.Load() != 5 {
		t.Errorf("expected MacaroonsMinted=5, got %d", m.MacaroonsMinted.Load())
	}
	if m.MacaroonsVerified.Load() != 3 {
		t.Errorf("expected MacaroonsVerified=3, got %d", m.MacaroonsVerified.Load())
	}
	if m.MacaroonsRejected.Load() != 2 {
		t.Errorf("expected MacaroonsRejected=2, got %d", m.MacaroonsRejected.Load())
	}
	if m.ReducerInvocations.Load() != 7 {
		t.Errorf("expected ReducerInvocations=7, got %d", m.ReducerInvocations.Load())
	}
	if m.TokenSizeWarnings.Load() != 1 {
		t.Errorf("expected TokenSizeWarnings=1, got %d", m.TokenSizeWarnings.Load())
	}
}

func TestMacaroonHistogramsObserve(t *testing.T) {
	m := NewMetrics()

	// Observe macaroon mint latency.
	m.MacaroonMintLatency.Observe(75 * time.Microsecond)
	m.MacaroonMintLatency.Observe(250 * time.Microsecond)
	m.MacaroonMintLatency.Observe(3 * time.Millisecond)

	if m.MacaroonMintLatency.Count() != 3 {
		t.Errorf("expected MacaroonMintLatency count=3, got %d", m.MacaroonMintLatency.Count())
	}

	// Observe macaroon verify latency.
	m.MacaroonVerifyLatency.Observe(150 * time.Microsecond)
	m.MacaroonVerifyLatency.Observe(800 * time.Microsecond)

	if m.MacaroonVerifyLatency.Count() != 2 {
		t.Errorf("expected MacaroonVerifyLatency count=2, got %d", m.MacaroonVerifyLatency.Count())
	}

	// Verify they appear in Prometheus output.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.ServePrometheus(rec, req)

	body := rec.Body.String()

	expected := []string{
		`ephyr_macaroon_mint_seconds_bucket{le="0.0001"} 1`,
		`ephyr_macaroon_mint_seconds_bucket{le="0.0005"} 2`,
		`ephyr_macaroon_mint_seconds_bucket{le="+Inf"} 3`,
		"ephyr_macaroon_mint_seconds_count 3",
		`ephyr_macaroon_verify_seconds_bucket{le="0.0005"} 1`,
		`ephyr_macaroon_verify_seconds_bucket{le="+Inf"} 2`,
		"ephyr_macaroon_verify_seconds_count 2",
	}

	for _, exp := range expected {
		if !strings.Contains(body, exp) {
			t.Errorf("Prometheus output missing: %q\n\nFull output:\n%s", exp, body)
		}
	}
}
