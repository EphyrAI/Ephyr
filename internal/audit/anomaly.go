package audit

import (
	"fmt"
	"sync"
	"time"
)

// AnomalyType classifies the detected anomaly pattern.
type AnomalyType string

const (
	AnomalyRapidRequests  AnomalyType = "rapid_requests"
	AnomalyTargetScan     AnomalyType = "target_scan"
	AnomalyRoleEscalation AnomalyType = "role_escalation"
)

// Anomaly describes a single detected suspicious pattern.
type Anomaly struct {
	Type        AnomalyType `json:"type"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
}

// request records a single certificate request for anomaly tracking.
type request struct {
	timestamp time.Time
	target    string
	role      string
	denied    bool
}

// AnomalyDetector tracks recent requests per agent and detects suspicious
// patterns. Thread-safe.
type AnomalyDetector struct {
	mu sync.Mutex

	// history maps agent name -> sliding window of recent requests.
	history map[string][]request

	// denials maps agent name -> recent denied requests for escalation detection.
	denials map[string][]request
}

// NewAnomalyDetector creates a new detector with empty state.
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		history: make(map[string][]request),
		denials: make(map[string][]request),
	}
}

// Check records a new request from an agent and returns any anomalies
// detected based on recent history. Returns nil if nothing suspicious.
func (ad *AnomalyDetector) Check(agentName string, target string, role string) []Anomaly {
	now := time.Now()

	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Prune old entries (anything older than 60s).
	ad.pruneAgent(agentName, now)

	// Record this request.
	req := request{
		timestamp: now,
		target:    target,
		role:      role,
	}
	ad.history[agentName] = append(ad.history[agentName], req)

	var anomalies []Anomaly

	// Check 1: Rapid requests -- more than 5 requests in 30 seconds.
	if a := ad.checkRapidRequests(agentName, now); a != nil {
		anomalies = append(anomalies, *a)
	}

	// Check 2: Target scan -- more than 3 distinct targets in 60 seconds.
	if a := ad.checkTargetScan(agentName, now); a != nil {
		anomalies = append(anomalies, *a)
	}

	// Check 3: Role escalation -- denied role request followed by another
	// role request to the same target within 30 seconds.
	if a := ad.checkRoleEscalation(agentName, target, role, now); a != nil {
		anomalies = append(anomalies, *a)
	}

	return anomalies
}

// RecordDenial should be called when a request is denied, so the escalation
// detector can track denied-then-retry patterns.
func (ad *AnomalyDetector) RecordDenial(agentName string, target string, role string) {
	now := time.Now()

	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.denials[agentName] = append(ad.denials[agentName], request{
		timestamp: now,
		target:    target,
		role:      role,
		denied:    true,
	})
}

// pruneAgent removes entries older than 60 seconds. Caller must hold ad.mu.
func (ad *AnomalyDetector) pruneAgent(agentName string, now time.Time) {
	cutoff := now.Add(-60 * time.Second)

	if reqs, ok := ad.history[agentName]; ok {
		pruned := reqs[:0]
		for _, r := range reqs {
			if r.timestamp.After(cutoff) {
				pruned = append(pruned, r)
			}
		}
		ad.history[agentName] = pruned
	}

	if denials, ok := ad.denials[agentName]; ok {
		pruned := denials[:0]
		for _, r := range denials {
			if r.timestamp.After(cutoff) {
				pruned = append(pruned, r)
			}
		}
		ad.denials[agentName] = pruned
	}
}

// checkRapidRequests detects >5 requests within the last 30 seconds.
// Caller must hold ad.mu.
func (ad *AnomalyDetector) checkRapidRequests(agentName string, now time.Time) *Anomaly {
	cutoff := now.Add(-30 * time.Second)
	count := 0

	for _, r := range ad.history[agentName] {
		if r.timestamp.After(cutoff) {
			count++
		}
	}

	if count > 5 {
		return &Anomaly{
			Type:        AnomalyRapidRequests,
			Description: fmt.Sprintf("agent %q made %d requests in 30s (threshold: 5)", agentName, count),
			Severity:    SeverityWarn,
		}
	}
	return nil
}

// checkTargetScan detects >3 distinct targets within the last 60 seconds.
// Caller must hold ad.mu.
func (ad *AnomalyDetector) checkTargetScan(agentName string, now time.Time) *Anomaly {
	cutoff := now.Add(-60 * time.Second)
	targets := make(map[string]struct{})

	for _, r := range ad.history[agentName] {
		if r.timestamp.After(cutoff) {
			targets[r.target] = struct{}{}
		}
	}

	if len(targets) > 3 {
		return &Anomaly{
			Type:        AnomalyTargetScan,
			Description: fmt.Sprintf("agent %q contacted %d distinct targets in 60s (threshold: 3)", agentName, len(targets)),
			Severity:    SeverityAlert,
		}
	}
	return nil
}

// checkRoleEscalation detects a denied role request followed by another
// role request to the same target within 30 seconds.
// Caller must hold ad.mu.
func (ad *AnomalyDetector) checkRoleEscalation(agentName, target, role string, now time.Time) *Anomaly {
	cutoff := now.Add(-30 * time.Second)

	for _, d := range ad.denials[agentName] {
		if d.timestamp.After(cutoff) && d.target == target {
			return &Anomaly{
				Type: AnomalyRoleEscalation,
				Description: fmt.Sprintf(
					"agent %q requested role %q on %q after denial of role %q within 30s",
					agentName, role, target, d.role,
				),
				Severity: SeverityAlert,
			}
		}
	}
	return nil
}
