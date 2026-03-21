package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashChainIntegrity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-audit.json")

	logger, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}

	// Write 5 events
	for i := 0; i < 5; i++ {
		logger.LogEvent(AuditEvent{
			EventType: EventCertIssued,
			Agent:     "test-agent",
			Target:    "test-target",
			Severity:  SeverityInfo,
		})
	}
	logger.Close()

	// Verify chain
	count, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if count != 5 {
		t.Fatalf("expected 5 entries, got %d", count)
	}
}

func TestHashChainDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-audit.json")

	logger, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}

	logger.LogEvent(AuditEvent{EventType: EventCertIssued, Agent: "agent1"})
	logger.LogEvent(AuditEvent{EventType: EventCertIssued, Agent: "agent2"})
	logger.LogEvent(AuditEvent{EventType: EventCertIssued, Agent: "agent3"})
	logger.Close()

	// Tamper with the second entry
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	var event AuditEvent
	json.Unmarshal([]byte(lines[1]), &event)
	event.Agent = "TAMPERED"
	tampered, _ := json.Marshal(event)
	lines[1] = string(tampered)

	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0640)

	// Verify should fail
	_, err = VerifyChain(path)
	if err == nil {
		t.Fatal("should detect tampering")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
}

func TestHashChainResumesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-audit.json")

	// First logger session
	logger1, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}
	logger1.LogEvent(AuditEvent{EventType: EventCertIssued, Agent: "session1"})
	logger1.LogEvent(AuditEvent{EventType: EventCertIssued, Agent: "session1"})
	logger1.Close()

	// Second logger session (simulates broker restart)
	logger2, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}
	logger2.LogEvent(AuditEvent{EventType: EventCertIssued, Agent: "session2"})
	logger2.Close()

	// Verify entire chain
	count, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("verification failed after restart: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 entries, got %d", count)
	}
}

func TestLegacyEntriesSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-audit.json")

	// Write a legacy entry without hashes
	legacy := `{"timestamp":"2026-01-01T00:00:00Z","event_type":"cert_issued","agent":"old"}` + "\n"
	os.WriteFile(path, []byte(legacy), 0640)

	// Add new entries with hashing
	logger, err := NewLogger(path, false)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogEvent(AuditEvent{EventType: EventCertIssued, Agent: "new"})
	logger.Close()

	count, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("should handle legacy entries: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 entries, got %d", count)
	}
}
