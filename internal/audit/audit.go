package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Severity levels for audit events.
type Severity = string

const (
	SeverityInfo  Severity = "INFO"
	SeverityWarn  Severity = "WARN"
	SeverityError Severity = "ERROR"
	SeverityAlert Severity = "ALERT"
)

// EventType identifies the kind of auditable action.
type EventType = string

const (
	EventCertIssued      EventType = "cert_issued"
	EventCertDenied      EventType = "cert_denied"
	EventCertPending     EventType = "cert_pending"
	EventCertRevoked     EventType = "cert_revoked"
	EventCertExpired     EventType = "cert_expired"
	EventCertApproved    EventType = "cert_approved"
	EventRateLimited     EventType = "rate_limited"
	EventPolicyReload    EventType = "policy_reload"
	EventSessionStart    EventType = "session_start"
	EventSessionReset    EventType = "session_reset"
	EventAnomalyDetected EventType = "anomaly_detected"
	EventRequestPending  EventType = "request_pending"
	EventRequestApproved EventType = "request_approved"
	EventRequestDenied   EventType = "request_denied"
	EventRateLimit       EventType = "rate_limited"
	EventStartup         EventType = "startup"
	EventShutdown        EventType = "shutdown"
)

// AuditEvent is a single structured audit log entry.
type AuditEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	Severity      Severity          `json:"severity"`
	EventType     EventType         `json:"event_type"`
	Agent         string            `json:"agent,omitempty"`
	Target        string            `json:"target,omitempty"`
	Role          string            `json:"role,omitempty"`
	Serial        string            `json:"serial,omitempty"`
	Duration      string            `json:"duration,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	PolicyVersion string            `json:"policy_version,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
	TaskID        string            `json:"task_id,omitempty"`
	TaskRootID    string            `json:"task_root_id,omitempty"`
	InitiatedBy   string            `json:"initiated_by,omitempty"`
}

// AuditLogger writes structured JSON audit events to a file and optionally
// mirrors them to stdout. Thread-safe.
type AuditLogger struct {
	mu      sync.Mutex
	writers []io.Writer
	file    *os.File
}

// NewLogger creates an AuditLogger. If path is non-empty, events are appended
// to that file. If stdout is true, events are also written to os.Stdout.
// The parent directory is created if it does not exist.
func NewLogger(path string, stdout bool) (*AuditLogger, error) {
	l := &AuditLogger{}

	if path != "" {
		// Ensure the parent directory exists.
		if err := os.MkdirAll(dirOf(path), 0750); err != nil {
			return nil, fmt.Errorf("audit: mkdir: %w", err)
		}

		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("audit: open %s: %w", path, err)
		}
		l.file = f
		l.writers = append(l.writers, f)
	}

	if stdout {
		l.writers = append(l.writers, os.Stdout)
	}

	// Fallback: if no writers configured, at least write to stdout.
	if len(l.writers) == 0 {
		l.writers = append(l.writers, os.Stdout)
	}

	return l, nil
}

// LogEvent writes a single audit event as a JSON line.
func (l *AuditLogger) LogEvent(event AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, w := range l.writers {
		_, _ = w.Write(data)
	}
}

// Close closes the underlying log file, if any.
func (l *AuditLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Writer returns the underlying file as an io.Writer for integrations
// that need a raw writer (e.g., middleware loggers). Returns nil if no
// file was configured.
func (l *AuditLogger) Writer() io.Writer {
	return l.file
}

// dirOf returns the directory portion of a file path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
