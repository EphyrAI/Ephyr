package broker

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ActivityType categorizes agent actions.
type ActivityType string

const (
	ActivityExec         ActivityType = "exec"
	ActivityHTTPProxy    ActivityType = "http_proxy"
	ActivitySessionOpen  ActivityType = "session_open"
	ActivitySessionClose ActivityType = "session_close"
	ActivityCertIssued   ActivityType = "cert_issued"
	ActivityCertDenied   ActivityType = "cert_denied"
	ActivityMCPCall      ActivityType = "mcp_call"
)

// ActivityEntry represents a single agent action.
type ActivityEntry struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Agent      string            `json:"agent"`
	Type       ActivityType      `json:"type"`
	Target     string            `json:"target,omitempty"`
	Role       string            `json:"role,omitempty"`
	Command    string            `json:"command,omitempty"`
	URL        string            `json:"url,omitempty"`
	Method     string            `json:"method,omitempty"`
	Service    string            `json:"service,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	DurationMs int64             `json:"duration_ms,omitempty"`
	Success    bool              `json:"success"`
	Error      string            `json:"error,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
}

// AgentActivityStats tracks per-agent statistics.
type AgentActivityStats struct {
	TotalActions int64     `json:"total_actions"`
	TotalExec    int64     `json:"total_exec"`
	TotalProxy   int64     `json:"total_proxy"`
	TotalMCP     int64     `json:"total_mcp"`
	TotalErrors  int64     `json:"total_errors"`
	LastActive   time.Time `json:"last_active"`
	LastTarget   string    `json:"last_target"`
	LastAction   string    `json:"last_action"`
}

// ActivityStore is a thread-safe ring buffer of recent agent activity.
type ActivityStore struct {
	mu       sync.RWMutex
	entries  []*ActivityEntry
	capacity int
	head     int // next write position
	count    int // current number of entries

	// Counters for dashboard summary.
	totalExec   int64
	totalProxy  int64
	totalMCP    int64
	totalErrors int64
	agentStats  map[string]*AgentActivityStats
}

// ActivityQuery filters for searching activity entries.
type ActivityQuery struct {
	Agent      string       `json:"agent,omitempty"`
	Type       ActivityType `json:"type,omitempty"`
	Target     string       `json:"target,omitempty"`
	Service    string       `json:"service,omitempty"`
	Since      time.Time    `json:"since,omitempty"`
	Until      time.Time    `json:"until,omitempty"`
	Limit      int          `json:"limit,omitempty"`
	OnlyErrors bool         `json:"only_errors,omitempty"`
}

// ActivitySummary is a high-level overview for the dashboard.
type ActivitySummary struct {
	TotalActions  int64                          `json:"total_actions"`
	TotalExec     int64                          `json:"total_exec"`
	TotalProxy    int64                          `json:"total_proxy"`
	TotalMCP      int64                          `json:"total_mcp"`
	TotalErrors   int64                          `json:"total_errors"`
	ActiveAgents  int                            `json:"active_agents"`
	AgentStats    map[string]*AgentActivityStats `json:"agent_stats"`
	RecentEntries []*ActivityEntry               `json:"recent_entries"`
	TopTargets    []TargetUsage                  `json:"top_targets"`
	TopServices   []ServiceUsage                 `json:"top_services"`
}

// TargetUsage records how many times a target was accessed.
type TargetUsage struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// ServiceUsage records how many times a service was accessed.
type ServiceUsage struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// NewActivityStore creates an activity store with the given ring buffer capacity.
func NewActivityStore(capacity int) *ActivityStore {
	if capacity <= 0 {
		capacity = 10000
	}
	return &ActivityStore{
		entries:    make([]*ActivityEntry, capacity),
		capacity:   capacity,
		agentStats: make(map[string]*AgentActivityStats),
	}
}

// Record adds a new activity entry to the ring buffer.
// This is the primary ingestion method -- called from exec, proxy, session handlers.
func (s *ActivityStore) Record(entry *ActivityEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate ID if not set.
	if entry.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		entry.ID = hex.EncodeToString(b)
	}

	// Set timestamp if not set.
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Truncate command to 200 chars.
	if len(entry.Command) > 200 {
		entry.Command = entry.Command[:200]
	}

	// Write to ring buffer.
	s.entries[s.head] = entry
	s.head = (s.head + 1) % s.capacity
	if s.count < s.capacity {
		s.count++
	}

	// Update global counters.
	switch entry.Type {
	case ActivityExec:
		s.totalExec++
	case ActivityHTTPProxy:
		s.totalProxy++
	case ActivityMCPCall:
		s.totalMCP++
	}
	if !entry.Success {
		s.totalErrors++
	}

	// Update per-agent stats.
	stats, ok := s.agentStats[entry.Agent]
	if !ok {
		stats = &AgentActivityStats{}
		s.agentStats[entry.Agent] = stats
	}
	stats.TotalActions++
	stats.LastActive = entry.Timestamp
	stats.LastTarget = entry.Target
	stats.LastAction = string(entry.Type)
	if entry.Type == ActivityExec {
		stats.TotalExec++
	}
	if entry.Type == ActivityHTTPProxy {
		stats.TotalProxy++
	}
	if entry.Type == ActivityMCPCall {
		stats.TotalMCP++
	}
	if !entry.Success {
		stats.TotalErrors++
	}
}

// Query returns activity entries matching the filter criteria.
// Results are returned in reverse chronological order (newest first).
func (s *ActivityStore) Query(q ActivityQuery) []*ActivityEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	var results []*ActivityEntry

	// Iterate backwards from most recent.
	for i := 0; i < s.count && len(results) < limit; i++ {
		idx := (s.head - 1 - i + s.capacity) % s.capacity
		e := s.entries[idx]
		if e == nil {
			continue
		}

		// Apply filters.
		if q.Agent != "" && e.Agent != q.Agent {
			continue
		}
		if q.Type != "" && e.Type != q.Type {
			continue
		}
		if q.Target != "" && e.Target != q.Target && e.Service != q.Target {
			continue
		}
		if q.Service != "" && e.Service != q.Service {
			continue
		}
		if !q.Since.IsZero() && e.Timestamp.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && e.Timestamp.After(q.Until) {
			continue
		}
		if q.OnlyErrors && e.Success {
			continue
		}

		results = append(results, e)
	}

	return results
}

// Summary returns a high-level activity summary for the dashboard.
func (s *ActivityStore) Summary() *ActivitySummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Count targets and services from the ring buffer.
	targetCounts := make(map[string]int64)
	serviceCounts := make(map[string]int64)

	for i := 0; i < s.count; i++ {
		idx := (s.head - 1 - i + s.capacity) % s.capacity
		e := s.entries[idx]
		if e == nil {
			continue
		}
		if e.Target != "" {
			targetCounts[e.Target]++
		}
		if e.Service != "" {
			serviceCounts[e.Service]++
		}
	}

	// Build sorted top targets (top 10).
	topTargets := sortedUsage(targetCounts, 10)
	topServices := sortedServiceUsage(serviceCounts, 10)

	// Recent entries (last 20).
	recent := make([]*ActivityEntry, 0, 20)
	for i := 0; i < s.count && len(recent) < 20; i++ {
		idx := (s.head - 1 - i + s.capacity) % s.capacity
		if s.entries[idx] != nil {
			recent = append(recent, s.entries[idx])
		}
	}

	// Copy agent stats to avoid races after releasing the lock.
	agentStatsCopy := make(map[string]*AgentActivityStats, len(s.agentStats))
	for k, v := range s.agentStats {
		cp := *v
		agentStatsCopy[k] = &cp
	}

	// Compute total actions across all types.
	var totalActions int64
	for _, stats := range s.agentStats {
		totalActions += stats.TotalActions
	}

	return &ActivitySummary{
		TotalActions:  totalActions,
		TotalExec:     s.totalExec,
		TotalProxy:    s.totalProxy,
		TotalMCP:      s.totalMCP,
		TotalErrors:   s.totalErrors,
		ActiveAgents:  len(s.agentStats),
		AgentStats:    agentStatsCopy,
		RecentEntries: recent,
		TopTargets:    topTargets,
		TopServices:   topServices,
	}
}

// Recent returns the N most recent entries (shorthand for Query with just Limit).
func (s *ActivityStore) Recent(n int) []*ActivityEntry {
	return s.Query(ActivityQuery{Limit: n})
}

// AgentSummary returns stats for a specific agent, or nil if unknown.
func (s *ActivityStore) AgentSummary(agentName string) *AgentActivityStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats, ok := s.agentStats[agentName]
	if !ok {
		return nil
	}
	cp := *stats
	return &cp
}

// --- Dashboard HTTP handlers ---

// handleGetActivity serves GET /v1/dashboard/activity?agent=X&type=X&limit=N&since=X&target=X&service=X&only_errors=1
func (bs *BrokerServer) handleGetActivity(w http.ResponseWriter, r *http.Request) {
	q := ActivityQuery{}

	q.Agent = r.URL.Query().Get("agent")
	q.Type = ActivityType(r.URL.Query().Get("type"))
	q.Target = r.URL.Query().Get("target")
	q.Service = r.URL.Query().Get("service")

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			q.Limit = v
		}
	}

	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			q.Since = t
		}
	}

	if untilStr := r.URL.Query().Get("until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			q.Until = t
		}
	}

	if r.URL.Query().Get("only_errors") == "1" || r.URL.Query().Get("only_errors") == "true" {
		q.OnlyErrors = true
	}

	entries := bs.activityStore.Query(q)
	if entries == nil {
		entries = []*ActivityEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// handleGetActivitySummary serves GET /v1/dashboard/activity/summary
func (bs *BrokerServer) handleGetActivitySummary(w http.ResponseWriter, r *http.Request) {
	summary := bs.activityStore.Summary()
	writeJSON(w, http.StatusOK, summary)
}

// handleGetAgentActivity serves GET /v1/dashboard/activity/agent/{name}
func (bs *BrokerServer) handleGetAgentActivity(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "agent name required")
		return
	}

	entries := bs.activityStore.Query(ActivityQuery{Agent: name, Limit: 200})
	if entries == nil {
		entries = []*ActivityEntry{}
	}

	stats := bs.activityStore.AgentSummary(name)
	if stats == nil {
		stats = &AgentActivityStats{}
	}

	resp := struct {
		Agent   string              `json:"agent"`
		Stats   *AgentActivityStats `json:"stats"`
		Entries []*ActivityEntry    `json:"entries"`
	}{
		Agent:   name,
		Stats:   stats,
		Entries: entries,
	}

	writeJSON(w, http.StatusOK, resp)
}

// --- Helper functions ---

// sortedUsage converts a count map to a sorted slice of TargetUsage, returning at most n entries.
func sortedUsage(counts map[string]int64, n int) []TargetUsage {
	usage := make([]TargetUsage, 0, len(counts))
	for name, count := range counts {
		usage = append(usage, TargetUsage{Name: name, Count: count})
	}
	sort.Slice(usage, func(i, j int) bool {
		return usage[i].Count > usage[j].Count
	})
	if len(usage) > n {
		usage = usage[:n]
	}
	return usage
}

// sortedServiceUsage converts a count map to a sorted slice of ServiceUsage, returning at most n entries.
func sortedServiceUsage(counts map[string]int64, n int) []ServiceUsage {
	usage := make([]ServiceUsage, 0, len(counts))
	for name, count := range counts {
		usage = append(usage, ServiceUsage{Name: name, Count: count})
	}
	sort.Slice(usage, func(i, j int) bool {
		return usage[i].Count > usage[j].Count
	})
	if len(usage) > n {
		usage = usage[:n]
	}
	return usage
}
