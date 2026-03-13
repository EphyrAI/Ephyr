package broker

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Metrics tracks performance counters and latency histograms
// for the broker's hot paths. Thread-safe, lock-free where possible.
type Metrics struct {
	// Latency histograms (buckets: <100µs, <500µs, <1ms, <5ms, <10ms, <50ms, >50ms)
	TokenSignLatency      LatencyHistogram
	TokenValidateLatency  LatencyHistogram
	WatermarkCheckLatency LatencyHistogram
	EnvelopeCheckLatency  LatencyHistogram
	PolicyEvalLatency     LatencyHistogram
	SSHCertLatency        LatencyHistogram
	DelegationIPCLatency  LatencyHistogram
	ExecE2ELatency        LatencyHistogram

	// Counters
	TasksCreated         atomic.Int64
	TasksActive          atomic.Int64
	TokensSigned         atomic.Int64 // CTT-E tokens signed
	TokensDelegated      atomic.Int64 // CTT-D tokens signed (delegations)
	TokensValidated      atomic.Int64
	TokensRejected       atomic.Int64
	WatermarkRevocations atomic.Int64
	DelegationRotations  atomic.Int64
	LegacyRequests       atomic.Int64 // requests without CTT (legacy mode)
	AuthCacheHits        atomic.Int64
	AuthCacheMisses      atomic.Int64

	// Gauges
	ActiveWatermarks    atomic.Int64
	DelegationCertAge   atomic.Int64 // seconds since current delegation cert was issued
	DelegationCertsHeld atomic.Int64 // number of delegation certs in memory
}

// latencyBucketBounds defines the upper bounds for each histogram bucket in nanoseconds.
var latencyBucketBounds = [7]int64{
	100_000,      // <100µs
	500_000,      // <500µs
	1_000_000,    // <1ms
	5_000_000,    // <5ms
	10_000_000,   // <10ms
	50_000_000,   // <50ms
	0,            // >=50ms (catch-all, bound not used)
}

// latencyBucketLabels are the Prometheus "le" labels for each bucket.
var latencyBucketLabels = [7]string{
	"0.0001",  // 100µs
	"0.0005",  // 500µs
	"0.001",   // 1ms
	"0.005",   // 5ms
	"0.01",    // 10ms
	"0.05",    // 50ms
	"+Inf",    // >=50ms
}

// LatencyHistogram is a lock-free histogram with fixed buckets.
// Designed for nanosecond-precision timing of hot-path operations.
type LatencyHistogram struct {
	// Buckets: [0] <100µs, [1] <500µs, [2] <1ms, [3] <5ms, [4] <10ms, [5] <50ms, [6] >=50ms
	buckets [7]atomic.Int64
	sum     atomic.Int64 // total nanoseconds
	count   atomic.Int64 // total observations
}

// Observe records a latency observation.
func (h *LatencyHistogram) Observe(d time.Duration) {
	ns := d.Nanoseconds()
	h.sum.Add(ns)
	h.count.Add(1)

	// Find the correct bucket.
	for i := 0; i < 6; i++ {
		if ns < latencyBucketBounds[i] {
			h.buckets[i].Add(1)
			return
		}
	}
	// Falls into the catch-all bucket (>=50ms).
	h.buckets[6].Add(1)
}

// Percentiles returns approximate p50, p95, p99 from bucket data.
// Returns (p50, p95, p99) in microseconds.
func (h *LatencyHistogram) Percentiles() (p50, p95, p99 float64) {
	total := h.count.Load()
	if total == 0 {
		return 0, 0, 0
	}

	// Collect cumulative counts.
	var cumulative [7]int64
	var running int64
	for i := 0; i < 7; i++ {
		running += h.buckets[i].Load()
		cumulative[i] = running
	}

	// Bucket upper bounds in microseconds for interpolation.
	upperBoundsUs := [7]float64{100, 500, 1000, 5000, 10000, 50000, 100000}
	lowerBoundsUs := [7]float64{0, 100, 500, 1000, 5000, 10000, 50000}

	interpolate := func(target int64) float64 {
		for i := 0; i < 7; i++ {
			if cumulative[i] >= target {
				// Linear interpolation within the bucket.
				var prevCum int64
				if i > 0 {
					prevCum = cumulative[i-1]
				}
				bucketCount := cumulative[i] - prevCum
				if bucketCount == 0 {
					return lowerBoundsUs[i]
				}
				fraction := float64(target-prevCum) / float64(bucketCount)
				return lowerBoundsUs[i] + fraction*(upperBoundsUs[i]-lowerBoundsUs[i])
			}
		}
		return upperBoundsUs[6]
	}

	p50 = interpolate((total + 1) / 2)
	p95 = interpolate((total * 95 + 99) / 100)
	p99 = interpolate((total * 99 + 99) / 100)
	return p50, p95, p99
}

// Mean returns the mean latency in microseconds.
func (h *LatencyHistogram) Mean() float64 {
	c := h.count.Load()
	if c == 0 {
		return 0
	}
	return float64(h.sum.Load()) / float64(c) / 1000.0 // ns → µs
}

// Count returns total observations.
func (h *LatencyHistogram) Count() int64 {
	return h.count.Load()
}

// Reset zeroes all buckets and counters.
func (h *LatencyHistogram) Reset() {
	for i := 0; i < 7; i++ {
		h.buckets[i].Store(0)
	}
	h.sum.Store(0)
	h.count.Store(0)
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// Timer is a helper for timing operations.
type Timer struct {
	start time.Time
	hist  *LatencyHistogram
}

// StartTimer begins a timing measurement.
func (m *Metrics) StartTimer(hist *LatencyHistogram) *Timer {
	return &Timer{
		start: time.Now(),
		hist:  hist,
	}
}

// Stop records the elapsed time in the histogram.
func (t *Timer) Stop() {
	t.hist.Observe(time.Since(t.start))
}

// ObserveTiming is a convenience for timing a block:
//
//	defer m.ObserveTiming(&m.TokenValidateLatency)()
func (m *Metrics) ObserveTiming(hist *LatencyHistogram) func() {
	start := time.Now()
	return func() {
		hist.Observe(time.Since(start))
	}
}

// RequestTiming captures per-request timing breakdown for audit entries.
type RequestTiming struct {
	TokenValidateMs  float64 `json:"token_validate_ms,omitempty"`
	WatermarkCheckMs float64 `json:"watermark_check_ms,omitempty"`
	EnvelopeCheckMs  float64 `json:"envelope_check_ms,omitempty"`
	PolicyEvalMs     float64 `json:"policy_eval_ms,omitempty"`
	SSHCertMs        float64 `json:"ssh_cert_ms,omitempty"`
	SSHExecMs        float64 `json:"ssh_exec_ms,omitempty"`
	TotalMs          float64 `json:"total_ms,omitempty"`
}

// histogramDescriptors maps field names to their Prometheus metric names and help strings.
type histogramDescriptor struct {
	name string
	help string
	hist *LatencyHistogram
}

// ServePrometheus writes metrics in Prometheus exposition format.
// Mount this at GET /metrics on the dashboard or a dedicated port.
func (m *Metrics) ServePrometheus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	histograms := []histogramDescriptor{
		{"clauth_token_sign_seconds", "Token signing latency", &m.TokenSignLatency},
		{"clauth_token_validate_seconds", "Token validation latency", &m.TokenValidateLatency},
		{"clauth_watermark_check_seconds", "Watermark check latency", &m.WatermarkCheckLatency},
		{"clauth_envelope_check_seconds", "Envelope check latency", &m.EnvelopeCheckLatency},
		{"clauth_policy_eval_seconds", "Policy evaluation latency", &m.PolicyEvalLatency},
		{"clauth_ssh_cert_seconds", "SSH certificate signing latency", &m.SSHCertLatency},
		{"clauth_delegation_ipc_seconds", "Delegation IPC latency", &m.DelegationIPCLatency},
		{"clauth_exec_e2e_seconds", "End-to-end exec latency", &m.ExecE2ELatency},
	}

	for _, hd := range histograms {
		writeHistogram(w, hd.name, hd.help, hd.hist)
	}

	// Counters
	type counterDesc struct {
		name string
		help string
		val  *atomic.Int64
	}
	counters := []counterDesc{
		{"clauth_tasks_created_total", "Total tasks created", &m.TasksCreated},
		{"clauth_tasks_active", "Currently active tasks", &m.TasksActive},
		{"clauth_tokens_signed_total", "Total CTT-E tokens signed", &m.TokensSigned},
		{"clauth_tokens_delegated_total", "Total CTT-D tokens signed (delegations)", &m.TokensDelegated},
		{"clauth_tokens_validated_total", "Total tokens validated", &m.TokensValidated},
		{"clauth_tokens_rejected_total", "Total tokens rejected", &m.TokensRejected},
		{"clauth_watermark_revocations_total", "Total watermark revocations", &m.WatermarkRevocations},
		{"clauth_delegation_rotations_total", "Total delegation cert rotations", &m.DelegationRotations},
		{"clauth_legacy_requests_total", "Requests without CTT (legacy mode)", &m.LegacyRequests},
		{"clauth_auth_cache_hits_total", "Auth cache hits (bcrypt bypassed)", &m.AuthCacheHits},
		{"clauth_auth_cache_misses_total", "Auth cache misses (bcrypt required)", &m.AuthCacheMisses},
	}

	for _, c := range counters {
		cType := "counter"
		if c.name == "clauth_tasks_active" {
			cType = "gauge"
		}
		fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", c.name, cType)
		fmt.Fprintf(w, "%s %d\n\n", c.name, c.val.Load())
	}

	// Gauges
	type gaugeDesc struct {
		name string
		help string
		val  *atomic.Int64
	}
	gauges := []gaugeDesc{
		{"clauth_active_watermarks", "Number of active revocation watermarks", &m.ActiveWatermarks},
		{"clauth_delegation_cert_age_seconds", "Seconds since current delegation cert was issued", &m.DelegationCertAge},
		{"clauth_delegation_certs_held", "Number of delegation certs in memory", &m.DelegationCertsHeld},
	}

	for _, g := range gauges {
		fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
		fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)
		fmt.Fprintf(w, "%s %d\n\n", g.name, g.val.Load())
	}
}

// writeHistogram writes a single histogram in Prometheus exposition format.
func writeHistogram(w http.ResponseWriter, name, help string, h *LatencyHistogram) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)

	var cumulative int64
	for i := 0; i < 7; i++ {
		cumulative += h.buckets[i].Load()
		fmt.Fprintf(w, "%s_bucket{le=\"%s\"} %d\n", name, latencyBucketLabels[i], cumulative)
	}

	// Sum is in nanoseconds; convert to seconds for Prometheus.
	sumSeconds := float64(h.sum.Load()) / 1e9
	fmt.Fprintf(w, "%s_sum %g\n", name, sumSeconds)
	fmt.Fprintf(w, "%s_count %d\n\n", name, h.count.Load())
}
