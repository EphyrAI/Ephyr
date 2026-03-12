package broker

import (
	"testing"
	"time"
)

func TestActivityRecord(t *testing.T) {
	tests := []struct {
		name  string
		entry ActivityEntry
	}{
		{
			name: "exec entry with all fields",
			entry: ActivityEntry{
				Agent:      "agent-a",
				Type:       ActivityExec,
				Target:     "dockerhost",
				Role:       "operator",
				Command:    "uptime",
				DurationMs: 150,
				Success:    true,
			},
		},
		{
			name: "http_proxy entry",
			entry: ActivityEntry{
				Agent:      "agent-b",
				Type:       ActivityHTTPProxy,
				Service:    "grafana",
				URL:        "http://grafana:3030/api/health",
				Method:     "GET",
				StatusCode: 200,
				DurationMs: 45,
				Success:    true,
			},
		},
		{
			name: "mcp_call entry",
			entry: ActivityEntry{
				Agent:   "agent-c",
				Type:    ActivityMCPCall,
				Target:  "demo-tools",
				Success: true,
				Details: map[string]string{"tool": "roll_dice"},
			},
		},
		{
			name: "failed entry with error",
			entry: ActivityEntry{
				Agent:   "agent-a",
				Type:    ActivityExec,
				Target:  "dockerhost",
				Command: "rm -rf /",
				Success: false,
				Error:   "permission denied",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewActivityStore(100)

			s.Record(&tc.entry)

			entries := s.Recent(10)
			if len(entries) != 1 {
				t.Fatalf("Recent(10): got %d entries, want 1", len(entries))
			}

			e := entries[0]
			if e.Agent != tc.entry.Agent {
				t.Errorf("Agent: got %q, want %q", e.Agent, tc.entry.Agent)
			}
			if e.Type != tc.entry.Type {
				t.Errorf("Type: got %q, want %q", e.Type, tc.entry.Type)
			}
			if e.ID == "" {
				t.Error("ID should be auto-generated")
			}
			if e.Timestamp.IsZero() {
				t.Error("Timestamp should be auto-set")
			}
			if e.Success != tc.entry.Success {
				t.Errorf("Success: got %v, want %v", e.Success, tc.entry.Success)
			}
		})
	}
}

func TestActivityRecordAutoFields(t *testing.T) {
	s := NewActivityStore(100)

	// Entry with no ID and no Timestamp.
	entry := &ActivityEntry{Agent: "agent-a", Type: ActivityExec, Target: "host1", Success: true}
	s.Record(entry)

	if entry.ID == "" {
		t.Error("ID should be auto-generated when empty")
	}
	if entry.Timestamp.IsZero() {
		t.Error("Timestamp should be auto-set when zero")
	}

	// Entry with preset ID and Timestamp should keep them.
	preset := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entry2 := &ActivityEntry{
		ID:        "custom-id",
		Timestamp: preset,
		Agent:     "agent-b",
		Type:      ActivityExec,
		Target:    "host2",
		Success:   true,
	}
	s.Record(entry2)

	entries := s.Recent(10)
	// Most recent is the last recorded (custom-id), which is at head-1.
	if entries[0].ID != "custom-id" {
		t.Errorf("preset ID: got %q, want %q", entries[0].ID, "custom-id")
	}
	if !entries[0].Timestamp.Equal(preset) {
		t.Errorf("preset Timestamp: got %v, want %v", entries[0].Timestamp, preset)
	}
}

func TestActivityCommandTruncation(t *testing.T) {
	s := NewActivityStore(100)

	longCmd := ""
	for i := 0; i < 300; i++ {
		longCmd += "x"
	}
	entry := &ActivityEntry{Agent: "agent-a", Type: ActivityExec, Command: longCmd, Success: true}
	s.Record(entry)

	if len(entry.Command) != 200 {
		t.Errorf("Command length: got %d, want 200 (truncated)", len(entry.Command))
	}
}

func TestActivityRingBufferWrap(t *testing.T) {
	capacity := 5
	s := NewActivityStore(capacity)

	// Write 8 entries into a buffer of size 5.
	for i := 0; i < 8; i++ {
		s.Record(&ActivityEntry{
			Agent:   "agent-a",
			Type:    ActivityExec,
			Target:  "host1",
			Command: string(rune('A' + i)),
			Success: true,
		})
	}

	// Should only hold last 5 entries.
	entries := s.Recent(100)
	if len(entries) != capacity {
		t.Fatalf("after wrap, Recent: got %d entries, want %d", len(entries), capacity)
	}

	// Most recent should be last recorded (command "H" = 'A'+7).
	if entries[0].Command != string(rune('A'+7)) {
		t.Errorf("most recent entry command: got %q, want %q", entries[0].Command, string(rune('A'+7)))
	}

	// Oldest should be entry index 3 (command "D" = 'A'+3).
	if entries[capacity-1].Command != string(rune('A'+3)) {
		t.Errorf("oldest entry command: got %q, want %q", entries[capacity-1].Command, string(rune('A'+3)))
	}
}

func TestActivityQueryByAgent(t *testing.T) {
	s := NewActivityStore(100)

	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-b", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityHTTPProxy, Service: "grafana", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-c", Type: ActivityMCPCall, Target: "demo", Success: true})

	results := s.Query(ActivityQuery{Agent: "agent-a"})
	if len(results) != 2 {
		t.Errorf("query agent-a: got %d, want 2", len(results))
	}
	for _, r := range results {
		if r.Agent != "agent-a" {
			t.Errorf("query agent-a returned entry for %q", r.Agent)
		}
	}
}

func TestActivityQueryByType(t *testing.T) {
	s := NewActivityStore(100)

	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityHTTPProxy, Service: "grafana", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityExec, Target: "host2", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-b", Type: ActivityMCPCall, Target: "demo", Success: true})

	results := s.Query(ActivityQuery{Type: ActivityExec})
	if len(results) != 2 {
		t.Errorf("query exec type: got %d, want 2", len(results))
	}
	for _, r := range results {
		if r.Type != ActivityExec {
			t.Errorf("query exec returned type %q", r.Type)
		}
	}
}

func TestActivityQueryByTarget(t *testing.T) {
	s := NewActivityStore(100)

	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityExec, Target: "host2", Success: true})
	// Note: Query.Target also matches e.Service per the source code.
	s.Record(&ActivityEntry{Agent: "agent-b", Type: ActivityHTTPProxy, Service: "host1", Success: true})

	results := s.Query(ActivityQuery{Target: "host1"})
	if len(results) != 2 {
		t.Errorf("query target host1: got %d, want 2 (matches Target and Service)", len(results))
	}
}

func TestActivityQueryByService(t *testing.T) {
	s := NewActivityStore(100)

	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityHTTPProxy, Service: "grafana", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityHTTPProxy, Service: "portainer", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-b", Type: ActivityHTTPProxy, Service: "grafana", Success: true})

	results := s.Query(ActivityQuery{Service: "grafana"})
	if len(results) != 2 {
		t.Errorf("query service grafana: got %d, want 2", len(results))
	}
}

func TestActivityQueryByTimeRange(t *testing.T) {
	s := NewActivityStore(100)

	now := time.Now()
	t1 := now.Add(-3 * time.Hour)
	t2 := now.Add(-2 * time.Hour)
	t3 := now.Add(-1 * time.Hour)

	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Timestamp: t1, Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Timestamp: t2, Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Timestamp: t3, Success: true})

	tests := []struct {
		name  string
		since time.Time
		until time.Time
		want  int
	}{
		{"all time", time.Time{}, time.Time{}, 3},
		{"since 2.5h ago", now.Add(-150 * time.Minute), time.Time{}, 2},
		{"until 1.5h ago", time.Time{}, now.Add(-90 * time.Minute), 2},
		{"window 2.5h to 0.5h ago", now.Add(-150 * time.Minute), now.Add(-30 * time.Minute), 2},
		{"future since -- none match", now.Add(1 * time.Hour), time.Time{}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := s.Query(ActivityQuery{Since: tc.since, Until: tc.until})
			if len(results) != tc.want {
				t.Errorf("got %d, want %d", len(results), tc.want)
			}
		})
	}
}

func TestActivityQueryErrorsOnly(t *testing.T) {
	s := NewActivityStore(100)

	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Success: false, Error: "timeout"})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Success: true})
	s.Record(&ActivityEntry{Agent: "b", Type: ActivityExec, Success: false, Error: "denied"})

	results := s.Query(ActivityQuery{OnlyErrors: true})
	if len(results) != 2 {
		t.Errorf("errors only: got %d, want 2", len(results))
	}
	for _, r := range results {
		if r.Success {
			t.Error("errors-only query returned successful entry")
		}
	}
}

func TestActivityQueryWithLimit(t *testing.T) {
	s := NewActivityStore(100)

	for i := 0; i < 20; i++ {
		s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Success: true})
	}

	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{"limit 5", 5, 5},
		{"limit 0 defaults to 100", 0, 20},
		{"limit 1001 capped to 1000", 1001, 20}, // only 20 entries in store
		{"limit 20 exact", 20, 20},
		{"negative defaults to 100", -1, 20},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := s.Query(ActivityQuery{Limit: tc.limit})
			if len(results) != tc.want {
				t.Errorf("got %d, want %d", len(results), tc.want)
			}
		})
	}
}

func TestActivityQueryCombinedFilters(t *testing.T) {
	s := NewActivityStore(100)

	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Target: "host1", Success: false, Error: "fail"})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityHTTPProxy, Service: "grafana", Success: true})
	s.Record(&ActivityEntry{Agent: "b", Type: ActivityExec, Target: "host1", Success: false, Error: "denied"})

	// Agent a + exec + errors only.
	results := s.Query(ActivityQuery{Agent: "a", Type: ActivityExec, OnlyErrors: true})
	if len(results) != 1 {
		t.Errorf("combined query: got %d, want 1", len(results))
	}
	if len(results) > 0 && results[0].Error != "fail" {
		t.Errorf("wrong entry: got error %q, want %q", results[0].Error, "fail")
	}
}

func TestActivityPerAgentStats(t *testing.T) {
	s := NewActivityStore(100)

	now := time.Now()

	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityExec, Target: "host1", Timestamp: now.Add(-2 * time.Minute), Success: true})
	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityHTTPProxy, Service: "grafana", Timestamp: now.Add(-1 * time.Minute), Success: true})
	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityMCPCall, Target: "demo", Timestamp: now, Success: false, Error: "timeout"})

	stats := s.AgentSummary("agent-a")
	if stats == nil {
		t.Fatal("AgentSummary should not be nil")
	}

	if stats.TotalActions != 3 {
		t.Errorf("TotalActions: got %d, want 3", stats.TotalActions)
	}
	if stats.TotalExec != 1 {
		t.Errorf("TotalExec: got %d, want 1", stats.TotalExec)
	}
	if stats.TotalProxy != 1 {
		t.Errorf("TotalProxy: got %d, want 1", stats.TotalProxy)
	}
	if stats.TotalMCP != 1 {
		t.Errorf("TotalMCP: got %d, want 1", stats.TotalMCP)
	}
	if stats.TotalErrors != 1 {
		t.Errorf("TotalErrors: got %d, want 1", stats.TotalErrors)
	}
	if stats.LastTarget != "demo" {
		t.Errorf("LastTarget: got %q, want %q", stats.LastTarget, "demo")
	}
	if stats.LastAction != string(ActivityMCPCall) {
		t.Errorf("LastAction: got %q, want %q", stats.LastAction, ActivityMCPCall)
	}

	// Unknown agent returns nil.
	if s.AgentSummary("nonexistent") != nil {
		t.Error("AgentSummary for unknown agent should return nil")
	}
}

func TestActivitySummary(t *testing.T) {
	s := NewActivityStore(100)

	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-a", Type: ActivityHTTPProxy, Service: "grafana", Success: true})
	s.Record(&ActivityEntry{Agent: "agent-b", Type: ActivityMCPCall, Target: "demo", Success: false, Error: "err"})
	s.Record(&ActivityEntry{Agent: "agent-b", Type: ActivityHTTPProxy, Service: "portainer", Success: true})

	summary := s.Summary()

	if summary.TotalExec != 2 {
		t.Errorf("TotalExec: got %d, want 2", summary.TotalExec)
	}
	if summary.TotalProxy != 2 {
		t.Errorf("TotalProxy: got %d, want 2", summary.TotalProxy)
	}
	if summary.TotalMCP != 1 {
		t.Errorf("TotalMCP: got %d, want 1", summary.TotalMCP)
	}
	if summary.TotalErrors != 1 {
		t.Errorf("TotalErrors: got %d, want 1", summary.TotalErrors)
	}
	if summary.TotalActions != 5 {
		t.Errorf("TotalActions: got %d, want 5", summary.TotalActions)
	}
	if summary.ActiveAgents != 2 {
		t.Errorf("ActiveAgents: got %d, want 2", summary.ActiveAgents)
	}
	if len(summary.RecentEntries) != 5 {
		t.Errorf("RecentEntries: got %d, want 5", len(summary.RecentEntries))
	}

	// TopTargets should include host1 and demo.
	if len(summary.TopTargets) < 2 {
		t.Errorf("TopTargets: got %d, want at least 2", len(summary.TopTargets))
	}

	// TopServices should include grafana and portainer.
	if len(summary.TopServices) < 2 {
		t.Errorf("TopServices: got %d, want at least 2", len(summary.TopServices))
	}

	// Agent stats map.
	if _, ok := summary.AgentStats["agent-a"]; !ok {
		t.Error("AgentStats should contain agent-a")
	}
	if _, ok := summary.AgentStats["agent-b"]; !ok {
		t.Error("AgentStats should contain agent-b")
	}
}

func TestActivitySummaryTopTargetsSorted(t *testing.T) {
	s := NewActivityStore(100)

	// host1: 3 times, host2: 1 time.
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Target: "host1", Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Target: "host2", Success: true})

	summary := s.Summary()
	if len(summary.TopTargets) < 2 {
		t.Fatalf("TopTargets: got %d, want at least 2", len(summary.TopTargets))
	}
	if summary.TopTargets[0].Name != "host1" {
		t.Errorf("TopTargets[0]: got %q, want %q", summary.TopTargets[0].Name, "host1")
	}
	if summary.TopTargets[0].Count != 3 {
		t.Errorf("TopTargets[0].Count: got %d, want 3", summary.TopTargets[0].Count)
	}
}

func TestActivityNewStoreDefaultCapacity(t *testing.T) {
	// Capacity <= 0 should default to 10000.
	s := NewActivityStore(0)
	if s.capacity != 10000 {
		t.Errorf("default capacity: got %d, want 10000", s.capacity)
	}

	s2 := NewActivityStore(-5)
	if s2.capacity != 10000 {
		t.Errorf("negative capacity: got %d, want 10000", s2.capacity)
	}
}

func TestActivityRecentShorthand(t *testing.T) {
	s := NewActivityStore(100)

	for i := 0; i < 10; i++ {
		s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Success: true})
	}

	recent := s.Recent(3)
	if len(recent) != 3 {
		t.Errorf("Recent(3): got %d, want 3", len(recent))
	}
}

func TestActivityReverseChronologicalOrder(t *testing.T) {
	s := NewActivityStore(100)

	now := time.Now()
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Timestamp: now.Add(-3 * time.Second), Command: "first", Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Timestamp: now.Add(-2 * time.Second), Command: "second", Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Timestamp: now.Add(-1 * time.Second), Command: "third", Success: true})

	entries := s.Recent(10)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].Command != "third" {
		t.Errorf("entries[0]: got %q, want %q", entries[0].Command, "third")
	}
	if entries[1].Command != "second" {
		t.Errorf("entries[1]: got %q, want %q", entries[1].Command, "second")
	}
	if entries[2].Command != "first" {
		t.Errorf("entries[2]: got %q, want %q", entries[2].Command, "first")
	}
}

func TestActivityGlobalCounters(t *testing.T) {
	s := NewActivityStore(100)

	// Record various types and check global counters.
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityHTTPProxy, Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityMCPCall, Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivitySessionOpen, Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityCertIssued, Success: true})
	s.Record(&ActivityEntry{Agent: "a", Type: ActivityExec, Success: false, Error: "err"})

	summary := s.Summary()
	if summary.TotalExec != 2 {
		t.Errorf("TotalExec: got %d, want 2", summary.TotalExec)
	}
	if summary.TotalProxy != 1 {
		t.Errorf("TotalProxy: got %d, want 1", summary.TotalProxy)
	}
	if summary.TotalMCP != 1 {
		t.Errorf("TotalMCP: got %d, want 1", summary.TotalMCP)
	}
	if summary.TotalErrors != 1 {
		t.Errorf("TotalErrors: got %d, want 1", summary.TotalErrors)
	}
	// session_open and cert_issued don't increment exec/proxy/mcp counters.
}

func TestActivityTypeConstants(t *testing.T) {
	tests := []struct {
		at   ActivityType
		want string
	}{
		{ActivityExec, "exec"},
		{ActivityHTTPProxy, "http_proxy"},
		{ActivitySessionOpen, "session_open"},
		{ActivitySessionClose, "session_close"},
		{ActivityCertIssued, "cert_issued"},
		{ActivityCertDenied, "cert_denied"},
		{ActivityMCPCall, "mcp_call"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if string(tc.at) != tc.want {
				t.Errorf("got %q, want %q", tc.at, tc.want)
			}
		})
	}
}
